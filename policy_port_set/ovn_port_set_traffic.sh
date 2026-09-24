#!/bin/bash

# Hardcoded list of UUIDs
INPUT="c0d6f3b6-0f3f-532d-81a9-9d61b416bc7e,b0d4bcb9-5f5d-54f6-b314-eb275481da68,17eae160-dd1c-5e7f-b155-3e07e7603376,5ca58070-091a-538f-860e-8de913d50541"

IFS=',' read -ra INPUT_ARRAY <<< "$INPUT"
TARGET_GROUPS=()

for item in "${INPUT_ARRAY[@]}"; do
    item=$(echo "$item" | xargs)
    item_underscores="${item//-/_}"
    pg_name="port_group_${item_underscores}"
    TARGET_GROUPS+=("$pg_name")
done

TG_REGEX=$(IFS="|"; echo "${TARGET_GROUPS[*]}")

# Helper function to resolve OVN Address Sets to actual IPs
resolve_addr_set() {
    local val="$1"
    if [[ "$val" == \$* ]]; then
        local as_name="${val#\$}"
        local ips=$(ovn-nbctl get address_set "$as_name" addresses 2>/dev/null | tr -d '\[\]"{} \n\r')
        if [ -n "$ips" ]; then echo "$ips"; else echo "$val"; fi
    else
        echo "$val"
    fi
}

# Helper function to resolve OVN Port Groups to actual Port Names
resolve_port_group() {
    local pg_name="$1"
    local uuids=$(ovn-nbctl get port_group "$pg_name" ports 2>/dev/null | tr -d '\[\]" ')
    
    local port_names=""
    if [ -n "$uuids" ]; then
        IFS=',' read -ra uuid_array <<< "$uuids"
        for u in "${uuid_array[@]}"; do
            local pname=$(ovn-nbctl get logical_switch_port "$u" name 2>/dev/null | tr -d '\" ')
            if [ -n "$pname" ]; then port_names="${port_names}${pname}, "; fi
        done
        port_names="${port_names%, }"
    fi
    if [ -n "$port_names" ]; then echo "$port_names"; else echo "@$pg_name"; fi
}

echo "======================================================================================================================================"
echo " CONSOLIDATED TRAFFIC POLICY"
echo "======================================================================================================================================"
for tg in "${TARGET_GROUPS[@]}"; do
    echo " TARGET PORT GROUP: $tg"
    echo " PORTS AFFECTED: $(resolve_port_group "$tg")"
    echo "--------------------------------------------------------------------------------------------------------------------------------------"
done
echo ""

# Fetch ACLs and extract 'priority', 'action', 'external_ids', and 'match'
ACLS=$(ovn-nbctl list ACL | awk -v tg_regex="($TG_REGEX)" '
BEGIN { RS=""; FS="\n" }
$0 ~ tg_regex {
    prio="-"; act="-"; sg_name=""; match_str=""
    for(i=1; i<=NF; i++) {
        if ($i ~ /^priority[ \t]*:/) {
            prio = $i; sub(/^priority[ \t]*:[ \t]*/, "", prio);
        } else if ($i ~ /^action[ \t]*:/) {
            act = $i; sub(/^action[ \t]*:[ \t]*"?/, "", act); sub(/"?[ \t]*$/, "", act);
        } else if ($i ~ /^external_ids[ \t]*:/ && $i ~ /neutron:security_group_name/) {
            sg_name = $i; sub(/.*neutron:security_group_name="?/, "", sg_name); sub(/"?.*/, "", sg_name);
        } else if ($i ~ /^match[ \t]*:/) {
            match_str = $i; sub(/^match[ \t]*:[ \t]*"/, "", match_str); sub(/"[ \t]*$/, "", match_str);
        }
    }
    if (match_str != "") {
        print prio "|" act "|" sg_name "|" match_str
    }
}')

# ---------------------------------------------------------
# 1. WHAT IT CAN RECEIVE (INBOUND TO THE PORT GROUPS)
# ---------------------------------------------------------
echo ">>> 1. FROM WHERE IT CAN RECEIVE TRAFFIC (INBOUND / INGRESS) <<<"
printf "%-5s | %-14s | %-35s | %-55s | %s\n" "PRIO" "ACTION" "SECURITY GROUP / PORT GROUP" "SOURCE (Who is sending)" "ON PORTS"
printf "%-5s-|-%-14s-|-%-35s-|-%-55s-|-%s\n" "-----" "--------------" "-----------------------------------" "-------------------------------------------------------" "------------------------------"

echo "$ACLS" | grep "outport == @" | sort -nr | while IFS='|' read -r prio action sg_name match_rule; do
    pg=$(echo "$match_rule" | grep -oP 'outport == @\K[^ )]+')
    
    if [ -n "$sg_name" ]; then
        display_name="SG: $sg_name"
    else
        display_name="@$pg"
    fi

    src=""
    for s in $(echo "$match_rule" | grep -oP 'ip[46]\.src == \K[^ )]+'); do
        res=$(resolve_addr_set "$s" | tr -d '\n\r')
        src="${src}${res},"
    done
    if [ -z "$src" ]; then src="ANY (0.0.0.0/0)"; else src="${src%,}"; fi

    ports=$(echo "$match_rule" | grep -oP '(tcp|udp)\.(dst|src) [=><]+ [0-9]+' | paste -sd, -)
    if [ -z "$ports" ]; then ports="ALL"; fi

    printf "%-5s | %-14s | %-35s | %-55s | %s\n" "$prio" "$action" "$display_name" "$src" "$ports"
done

echo ""
echo ""

# ---------------------------------------------------------
# 2. WHAT IT CAN SEND (OUTBOUND FROM THE PORT GROUPS)
# ---------------------------------------------------------
echo ">>> 2. WHERE IT CAN SEND TRAFFIC (OUTBOUND / EGRESS) <<<"
printf "%-5s | %-14s | %-35s | %-55s | %s\n" "PRIO" "ACTION" "SECURITY GROUP / PORT GROUP" "DESTINATION (Where it can send)" "ON PORTS"
printf "%-5s-|-%-14s-|-%-35s-|-%-55s-|-%s\n" "-----" "--------------" "-----------------------------------" "-------------------------------------------------------" "------------------------------"

echo "$ACLS" | grep "inport == @" | sort -nr | while IFS='|' read -r prio action sg_name match_rule; do
    pg=$(echo "$match_rule" | grep -oP 'inport == @\K[^ )]+')

    if [ -n "$sg_name" ]; then
        display_name="SG: $sg_name"
    else
        display_name="@$pg"
    fi

    dst=""
    for d in $(echo "$match_rule" | grep -oP 'ip[46]\.dst == \K[^ )]+'); do
        res=$(resolve_addr_set "$d" | tr -d '\n\r')
        dst="${dst}${res},"
    done
    if [ -z "$dst" ]; then dst="ANY (0.0.0.0/0)"; else dst="${dst%,}"; fi

    ports=$(echo "$match_rule" | grep -oP '(tcp|udp)\.(dst|src) [=><]+ [0-9]+' | paste -sd, -)
    if [ -z "$ports" ]; then ports="ALL"; fi

    printf "%-5s | %-14s | %-35s | %-55s | %s\n" "$prio" "$action" "$display_name" "$dst" "$ports"
done
echo "======================================================================================================================================"
