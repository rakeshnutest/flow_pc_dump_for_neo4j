#!/bin/bash
# Given one or more NIC UUIDs, find every OVN port group (port set) that
# contains that NIC and print the inbound and outbound ACLs.
#
# Run on the Prism Central VM. CMSP uses the local kubeconfig. SMSP uses
# `mspctl cluster kubeconfig flow`. Inside the anc-ovn pod the same file
# talks to the local Northbound socket.
#
#   bash ovn_port_set_traffic.sh <src-nic-uuid>
#   bash ovn_port_set_traffic.sh <src-nic-uuid> <dst-nic-uuid> <dst-port> [--proto tcp|udp]
#
# The NIC UUID is the id in the logical switch port name port_<uuid>.
# One NIC prints its port sets and ACLs. Source, destination, and port
# also decide allow or deny for both directions.

if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: run with bash" >&2
    exit 1
fi

NB_DB="${OVN_NB_DB:-unix:/var/run/ovn/ovnnb_db.sock}"
OVN_CONTAINER="${OVN_CONTAINER:-anc-ovn}"
WORK=""
PLATFORM=""
SMSP_UUID=""
KUBECONFIG_FILE=""
OVN_NS=""
OVN_POD=""
DST_NIC=""
DST_PORT=""
PROTO="tcp"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

help_text() {
    cat <<EOF
Usage:
  $(basename "$0") <src-nic-uuid>
  $(basename "$0") <src-nic-uuid> <dst-nic-uuid> <dst-port>
  $(basename "$0") -h

Run this on the Prism Central VM. It works on CMSP and SMSP. The script
finds kubectl and the anc-ovn pod, then reads OVN port sets and ACLs.

One argument, the source NIC:
  Prints the NIC, its port sets, and a LEGEND of each port group and its IPs.
  Then the inbound and outbound ACL rows, including the port group and the
  service ports.

Three arguments, source NIC, destination NIC, and destination port:
  Prints the same LEGEND, then for both directions:
    SOURCE ROWS   outgoing ACLs of the sender
    DEST ROWS     incoming ACLs of the receiver
    VERDICT       allowed or denied
  Logic for each direction:
    source NIC outbound rules only
    destination NIC inbound rules only
    port-set match is live OVN membership, no json file
    a drop on either side denies the packet
  Each row shows the port group, MATCH, and the service ports.
  --proto defaults to tcp. udp and icmp are also accepted.

Other forms:
  --dst <dst-nic-uuid> --port <dst-port>    same as the three arguments
  --proto tcp|udp|icmp
  -h, --help                                 this help

Examples:
  bash $(basename "$0") fa9b2b43-76c3-4456-958a-b7e31fbd64c8
  bash $(basename "$0") fa9b2b43-76c3-4456-958a-b7e31fbd64c8 \\
      017ce39e-a535-401f-9149-63ab2b831a5b 22
  bash $(basename "$0") fa9b2b43-76c3-4456-958a-b7e31fbd64c8 \\
      017ce39e-a535-401f-9149-63ab2b831a5b 22 --proto udp
EOF
}

usage() {
    help_text >&2
    exit 2
}

cleanup() {
    if [ -n "$WORK" ] && [ -d "$WORK" ]; then
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

log() {
    echo "$*" >&2
}

ovn() {
    COLUMNS=1000000 ovn-nbctl --db="$NB_DB" "$@"
}

trim() {
    local s="$1"
    s="${s//$'\r'/}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    s="${s//\"/}"
    printf '%s' "$s"
}

pg_to_uuid() {
    local name="${1#port_group_}"
    printf '%s\n' "${name//_/-}"
}

declare -A AS_CACHE=()
declare -A LSP_IPS=()

# Turn an OVN address-set or port-address blob into a comma-separated IP list.
format_ip_list() {
    # Pull every IPv4 or IPv4 CIDR out of an address set, port address, or
    # neutron:cidrs string. MAC addresses are ignored.
    printf '%s' "$1" | awk '
    {
        s = $0
        out = ""
        while (match(s, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?/)) {
            tok = substr(s, RSTART, RLENGTH)
            out = out (out ? ", " : "") tok
            s = substr(s, RSTART + RLENGTH)
        }
        print out
    }'
}

resolve_addr_set() {
    local val="$1" as_name ips
    case "$val" in
        \$*)
            as_name="${val#\$}"
            if [ -n "${AS_CACHE[$as_name]+x}" ]; then
                printf '%s' "${AS_CACHE[$as_name]}"
                return
            fi
            ips=$(ovn get address_set "$as_name" addresses 2>/dev/null || true)
            ips=$(format_ip_list "$ips")
            if [ -z "$ips" ]; then
                ips="$val"
            fi
            AS_CACHE[$as_name]="$ips"
            printf '%s' "$ips"
            ;;
        @port_group_*)
            printf '%s' "$(resolve_port_group "${val#@}")"
            ;;
        *)
            ips=$(format_ip_list "$val")
            if [ -n "$ips" ]; then
                printf '%s' "$ips"
            else
                printf '%s' "$val"
            fi
            ;;
    esac
}

join_lines() {
    local out="" line
    while IFS= read -r line; do
        line=$(trim "$line")
        [ -n "$line" ] || continue
        if [ -z "$out" ]; then
            out="$line"
        else
            out="$out, $line"
        fi
    done
    printf '%s' "$out"
}

remember_lsp_ips() {
    local ids=("$@") pending=() u line uuid ips i=0 chunk=()
    for u in "${ids[@]}"; do
        u=$(trim "$u")
        [ -n "$u" ] || continue
        if [ -z "${LSP_IPS[$u]+x}" ]; then
            pending+=("$u")
        fi
    done
    while [ "$i" -lt "${#pending[@]}" ]; do
        chunk=()
        while [ "$i" -lt "${#pending[@]}" ] && [ "${#chunk[@]}" -lt 40 ]; do
            chunk+=("${pending[$i]}")
            i=$((i + 1))
        done
        [ "${#chunk[@]}" -eq 0 ] && continue
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            uuid=$(trim "${line%%,*}")
            [ -n "$uuid" ] || continue
            ips=$(format_ip_list "${line#*,}")
            LSP_IPS[$uuid]="$ips"
        done < <(ovn --format=csv --data=bare --no-heading --columns=_uuid,addresses,port_security,external_ids list Logical_Switch_Port "${chunk[@]}" 2>/dev/null || true)
        for u in "${chunk[@]}"; do
            [ -n "${LSP_IPS[$u]+x}" ] || LSP_IPS[$u]=""
        done
    done
}

resolve_port_group() {
    local pg_name="$1" raw uuids=() u ip out=""
    raw=$(ovn get port_group "$pg_name" ports 2>/dev/null | tr -d '[]"' || true)
    raw="${raw//,/ }"
    # shellcheck disable=SC2206
    uuids=($raw)
    if [ "${#uuids[@]}" -eq 0 ]; then
        printf '%s' ""
        return
    fi
    remember_lsp_ips "${uuids[@]}"
    for u in "${uuids[@]}"; do
        u=$(trim "$u")
        [ -n "$u" ] || continue
        ip="${LSP_IPS[$u]}"
        [ -n "$ip" ] || continue
        if [ -z "$out" ]; then
            out="$ip"
        else
            out="$out, $ip"
        fi
    done
    printf '%s' "$out"
}

find_lsps() {
    local nic="$1" out="" line query
    for query in \
        "name=port_${nic}" \
        "name=${nic}" \
        "external_ids:neutron:port_name=port_${nic}"
    do
        out=$(ovn --data=bare --no-heading --columns=_uuid find Logical_Switch_Port "$query" 2>/dev/null || true)
        out=$(printf '%s\n' "$out" | sed '/^$/d')
        if [ -n "$out" ]; then
            printf '%s\n' "$out"
            return 0
        fi
    done
    log "LSP name lookup missed $nic; scanning Logical_Switch_Port"
    ovn --data=bare --no-heading --format=csv --columns=_uuid,name,external_ids list Logical_Switch_Port 2>/dev/null \
        | grep -F "$nic" \
        | while IFS= read -r line; do
            line="${line%%,*}"
            line=$(trim "$line")
            [ -n "$line" ] && printf '%s\n' "$line"
        done
}

find_port_groups() {
    local lsp="$1" out="" rc=0 line
    out=$(ovn --data=bare --no-heading --columns=name find Port_Group "ports{>=}${lsp}" 2>"$WORK/pg.err") || rc=$?
    if [ "$rc" -ne 0 ]; then
        log "port-group find ports{>=} failed; trying bracket form"
        rc=0
        out=$(ovn --data=bare --no-heading --columns=name find Port_Group "ports{>=}[${lsp}]" 2>"$WORK/pg.err") || rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        log "port-group find failed; scanning Port_Group ($(tr '\n' ' ' < "$WORK/pg.err" | cut -c1-180))"
        ovn --data=bare --no-heading --format=csv --columns=name,ports list Port_Group 2>/dev/null \
            | grep -F "$lsp" \
            | while IFS= read -r line; do
                line="${line%%,*}"
                line=$(trim "$line")
                [ -n "$line" ] && printf '%s\n' "$line"
            done
        return
    fi
    printf '%s\n' "$out" | while IFS= read -r line; do
        line=$(trim "$line")
        [ -n "$line" ] && printf '%s\n' "$line"
    done
}

csv_to_rows() {
    awk '
    function csvsplit(line, arr,    i, c, field, inq, n) {
        n = 0
        field = ""
        inq = 0
        for (i = 1; i <= length(line); i++) {
            c = substr(line, i, 1)
            if (inq) {
                if (c == "\"") {
                    if (substr(line, i + 1, 1) == "\"") {
                        field = field "\""
                        i++
                    } else {
                        inq = 0
                    }
                } else {
                    field = field c
                }
            } else if (c == "\"") {
                inq = 1
            } else if (c == ",") {
                arr[++n] = field
                field = ""
            } else {
                field = field c
            }
        }
        arr[++n] = field
        return n
    }
    {
        n = csvsplit($0, f)
        prio = f[1]
        act = f[2]
        ext = f[3]
        match_str = f[4]
        if (n > 4) {
            match_str = f[4]
            for (i = 5; i <= n; i++) match_str = match_str "," f[i]
        }
        gsub(/^[ \t]+|[ \t]+$/, "", prio)
        gsub(/^[ \t]+|[ \t]+$/, "", act)
        gsub(/^"|"$/, "", act)
        if (prio == "") prio = "-"
        if (act == "") act = "-"
        sg = ""
        if (match(ext, /neutron:security_group_name="?[^",} ]+/)) {
            sg = substr(ext, RSTART, RLENGTH)
            sub(/.*neutron:security_group_name="?/, "", sg)
        }
        gsub(/\r/, "", match_str)
        printf "%s\x1f%s\x1f%s\x1f%s\n", prio, act, sg, match_str
    }
    '
}

fetch_group_acls() {
    local pg raw id i=0
    local ids=() batch=()
    declare -A seen=()
    for pg in "$@"; do
        raw=$(ovn get port_group "$pg" acls 2>/dev/null || true)
        raw=$(printf '%s' "$raw" | tr -d '[]"')
        raw="${raw//,/ }"
        local n_here=0
        for id in $raw; do
            id=$(trim "$id")
            [ -n "$id" ] || continue
            if [ -z "${seen[$id]+x}" ]; then
                seen[$id]=1
                ids+=("$id")
                n_here=$((n_here + 1))
            fi
        done
        log "  $pg acls=$n_here"
    done
    log "ACL uuids=${#ids[@]}"
    if [ "${#ids[@]}" -eq 0 ]; then
        return 0
    fi
    while [ "$i" -lt "${#ids[@]}" ]; do
        batch=()
        while [ "$i" -lt "${#ids[@]}" ] && [ "${#batch[@]}" -lt 20 ]; do
            batch+=("${ids[$i]}")
            i=$((i + 1))
        done
        ovn --format=csv --data=bare --no-heading --columns=priority,action,external_ids,match list ACL "${batch[@]}"
    done | csv_to_rows
}

peer_of() {
    local match_rule="$1" side="$2" item peer=""
    while IFS= read -r item; do
        [ -n "$item" ] || continue
        item=$(resolve_addr_set "$item")
        [ -n "$item" ] || continue
        if [ -z "$peer" ]; then
            peer="$item"
        else
            peer="$peer, $item"
        fi
    done < <(printf '%s\n' "$match_rule" | grep -oE "ip[46][.]${side} == [^ )]+" | sed -E "s/^ip[46][.]${side} == //" || true)
    if [ -z "$peer" ]; then
        printf '%s' "ANY (0.0.0.0/0)"
    else
        printf '%s' "$peer"
    fi
}

ports_of() {
    local match_rule="$1" ports
    ports=$(printf '%s\n' "$match_rule" | grep -oE '(tcp|udp)[.](dst|src) [=><]+ [0-9]+' | join_lines || true)
    if [ -z "$ports" ]; then
        printf '%s' "ALL"
    else
        printf '%s' "$ports"
    fi
}

print_acl_table() {
    local title="$1" kind="$2" peer_hdr="$3"
    local id prio dir action pg match_rule peer ports side shown=0
    echo "$title"
    printf "%-4s | %-5s | %-14s | %-36s | %s | %s\n" "ID" "PRIO" "ACTION" "PORT GROUP" "$peer_hdr" "ON PORTS"
    printf "%-4s-|-%-5s-|-%-14s-|-%-36s-|-%s-|-%s\n" "----" "-----" "--------------" "------------------------------------" "------------------------------" "--------"
    if [ "$kind" = "inbound" ]; then
        side="src"
    else
        side="dst"
    fi
    while IFS=$'\x1f' read -r id prio dir action pg match_rule; do
        [ "$dir" = "$kind" ] || continue
        [ -n "$match_rule" ] || continue
        shown=1
        peer=$(peer_of "$match_rule" "$side")
        ports=$(ports_of "$match_rule")
        printf "%-4s | %-5s | %-14s | %-36s | %s | %s\n" "$id" "$prio" "$action" "$pg" "$peer" "$ports"
    done < "$WORK/rules.tsv"
    if [ "$shown" -eq 0 ]; then
        echo "(no ACLs)"
    fi
}

ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<< "${1%%/*}"
    case "$a$b$c$d" in
        *[!0-9]*) printf '%s' "" ;;
        *) printf '%s' $(( (a << 24) + (b << 16) + (c << 8) + d )) ;;
    esac
}

cidr_has() {
    local cidr="$1" ip="$2" base bits ipi basei mask
    cidr=$(trim "$cidr")
    ip=$(trim "${ip%%/*}")
    [ -n "$cidr" ] && [ -n "$ip" ] || return 1
    base="${cidr%/*}"
    if [ "$cidr" = "$base" ]; then
        [ "$ip" = "$base" ]
        return
    fi
    bits="${cidr#*/}"
    case "$bits" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$bits" -le 32 ] || return 1
    ipi=$(ip_to_int "$ip")
    basei=$(ip_to_int "$base")
    [ -n "$ipi" ] && [ -n "$basei" ] || return 1
    if [ "$bits" -eq 0 ]; then
        return 0
    fi
    mask=$(( (0xffffffff << (32 - bits)) & 0xffffffff ))
    [ $((ipi & mask)) -eq $((basei & mask)) ]
}

ip_in_peer() {
    local peer="$1" ips="$2" tok ip
    case "$peer" in
        ANY*) return 0 ;;
    esac
    [ -n "$ips" ] || return 1
    local IFS=','
    local -a toks iplist
    read -ra toks <<< "$peer"
    read -ra iplist <<< "$ips"
    IFS=$' \t\n'
    for tok in "${toks[@]}"; do
        tok=$(trim "$tok")
        [ -n "$tok" ] || continue
        for ip in "${iplist[@]}"; do
            if cidr_has "$tok" "$ip"; then
                return 0
            fi
        done
    done
    return 1
}

port_matches() {
    printf '%s' "$1" | awk -v proto="$2" -v port="$3" '
    {
        m = $0
        if (m !~ /(tcp|udp|icmp)/) { print "yes"; exit }
        if (proto == "icmp") {
            if (m !~ /icmp/) { print "no"; exit }
            if (m !~ /icmp[46]?\.type/) { print "yes"; exit }
        } else if (m !~ proto) {
            print "no"; exit
        } else if (m !~ (proto "\\.dst")) {
            print "yes"; exit
        }
        n = split(m, parts, /\|\|/)
        for (i = 1; i <= n; i++) {
            part = parts[i]
            if (proto == "icmp") {
                if (part !~ /icmp/) continue
                tmp = part
                seen = 0
                while (match(tmp, /icmp[46]?\.type == [0-9]+/)) {
                    seen = 1
                    num = substr(tmp, RSTART, RLENGTH)
                    sub(/.*== /, "", num)
                    if (num + 0 == port + 0) { print "yes"; exit }
                    tmp = substr(tmp, RSTART + RLENGTH)
                }
                if (!seen) { print "yes"; exit }
                continue
            }
            if (part !~ proto) continue
            if (part !~ (proto "\\.dst")) { print "yes"; exit }
            tmp = part
            while (match(tmp, proto "\\.dst == [0-9]+")) {
                num = substr(tmp, RSTART, RLENGTH)
                sub(/.*== /, "", num)
                if (num + 0 == port + 0) { print "yes"; exit }
                tmp = substr(tmp, RSTART + RLENGTH)
            }
            tmp = part
            while (match(tmp, proto "\\.dst == \\{[0-9, ]+\\}")) {
                brace = substr(tmp, RSTART, RLENGTH)
                if (brace ~ ("[^0-9]" port "[^0-9]") || brace ~ ("\\{" port "[,}]")) { print "yes"; exit }
                tmp = substr(tmp, RSTART + RLENGTH)
            }
            lo = ""
            hi = ""
            if (match(part, proto "\\.dst >= [0-9]+")) {
                lo = substr(part, RSTART, RLENGTH)
                sub(/.*>= /, "", lo)
            }
            if (match(part, proto "\\.dst <= [0-9]+")) {
                hi = substr(part, RSTART, RLENGTH)
                sub(/.*<= /, "", hi)
            }
            if (lo != "" && hi != "" && port + 0 >= lo + 0 && port + 0 <= hi + 0) { print "yes"; exit }
            if (lo != "" && hi == "" && port + 0 >= lo + 0) { print "yes"; exit }
            if (hi != "" && lo == "" && port + 0 <= hi + 0) { print "yes"; exit }
        }
        print "no"
    }'
}

nic_ip() {
    local nic="$1" lsp mac ips ip
    lsp=$(find_lsps "$nic" | head -n 1)
    lsp=$(trim "$lsp")
    [ -n "$lsp" ] || return 0
    remember_lsp_ips "$lsp"
    ips="${LSP_IPS[$lsp]}"
    if [ -n "$ips" ]; then
        printf '%s' "$ips"
        return 0
    fi
    mac=$(ovn get Logical_Switch_Port "$lsp" addresses 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1 || true)
    if [ -n "$mac" ] && [ -S /var/run/ovn/ovnsb_db.sock ] && command -v ovn-sbctl >/dev/null 2>&1; then
        ip=$(COLUMNS=1000000 ovn-sbctl --db=unix:/var/run/ovn/ovnsb_db.sock --data=bare --no-heading --columns=ip find MAC_Binding mac="$mac" 2>/dev/null || true)
        ip=$(format_ip_list "$ip")
        printf '%s' "$ip"
    fi
}

pgs_of_nic() {
    local nic="$1"
    awk -v n="$nic" '$1 == n { printf "%s ", $2 }' "$WORK/nicmap"
}

token_pg_uuid() {
    local token="$1" body
    case "$token" in
        \$address_set_*) body="${token#\$address_set_}" ;;
        @port_group_*) body="${token#@port_group_}" ;;
        port_group_*) body="${token#port_group_}" ;;
        *) printf '%s' ""; return ;;
    esac
    printf '%s' "${body//_/-}"
}

nic_in_pg_uuid() {
    local nic="$1" uuid="$2" pgs
    [ -n "$uuid" ] || return 1
    pgs=" $(pgs_of_nic "$nic")"
    case "$pgs" in
        *" $uuid "*) return 0 ;;
        *) return 1 ;;
    esac
}

# MATCH is live OVN port-set membership, then the peer IP list. No json file.
peer_hits() {
    local match_rule="$1" side="$2" other_nic="$3" other_ips="$4"
    local token uuid peer
    while IFS= read -r token; do
        [ -n "$token" ] || continue
        uuid=$(token_pg_uuid "$token")
        if nic_in_pg_uuid "$other_nic" "$uuid"; then
            return 0
        fi
    done < <(printf '%s\n' "$match_rule" | grep -oE '\$address_set_[^ )]+|@port_group_[^ )]+' || true)
    peer=$(peer_of "$match_rule" "$side")
    ip_in_peer "$peer" "$other_ips"
}

winning_rule() {
    local nic="$1" dir="$2" other_ips="$3" other_nic="$4"
    local side id prio d action pg match peer pgs
    pgs=" $(pgs_of_nic "$nic")"
    if [ "$dir" = "inbound" ]; then
        side="src"
    else
        side="dst"
    fi
    while IFS=$'\x1f' read -r id prio d action pg match; do
        [ "$d" = "$dir" ] || continue
        case "$pgs" in
            *" $pg "*) ;;
            *) continue ;;
        esac
        peer=$(peer_of "$match" "$side")
        peer_hits "$match" "$side" "$other_nic" "$other_ips" || continue
        [ "$(port_matches "$match" "$PROTO" "$DST_PORT")" = "yes" ] || continue
        printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$id" "$prio" "$action" "$pg" "$peer"
        return 0
    done < "$WORK/rules.tsv"
    return 1
}

action_word() {
    case "$1" in
        drop) printf '%s' "denied" ;;
        allow|allow-related|allow-stateless) printf '%s' "allowed" ;;
        "") printf '%s' "allowed" ;;
        *) printf '%s' "allowed" ;;
    esac
}

print_side_rows() {
    local title="$1" nic="$2" dir="$3" other_ips="$4" peer_hdr="$5" flow="$6" other_nic="$7"
    local side id prio d action pg match_rule peer ports hit shown=0 pgs
    pgs=" $(pgs_of_nic "$nic")"
    if [ "$dir" = "inbound" ]; then
        side="src"
    else
        side="dst"
    fi
    echo "======================================================================================================================================"
    echo " $title"
    echo "======================================================================================================================================"
    echo "  $flow"
    echo "  NIC $nic    ${dir}    peer IP ${other_ips:-unknown}    ${PROTO}/${DST_PORT}"
    printf "%-4s | %-5s | %-14s | %-36s | %-5s | %s | %s\n" "ID" "PRIO" "ACTION" "PORT GROUP" "MATCH" "$peer_hdr" "ON PORTS"
    printf "%-4s-|-%-5s-|-%-14s-|-%-36s-|-%-5s-|-%s-|-%s\n" "----" "-----" "--------------" "------------------------------------" "-----" "------------------------------" "--------"
    while IFS=$'\x1f' read -r id prio d action pg match_rule; do
        [ "$d" = "$dir" ] || continue
        case "$pgs" in
            *" $pg "*) ;;
            *) continue ;;
        esac
        [ -n "$match_rule" ] || continue
        shown=1
        peer=$(peer_of "$match_rule" "$side")
        ports=$(ports_of "$match_rule")
        hit="no"
        if peer_hits "$match_rule" "$side" "$other_nic" "$other_ips" && [ "$(port_matches "$match_rule" "$PROTO" "$DST_PORT")" = "yes" ]; then
            hit="yes"
        fi
        printf "%-4s | %-5s | %-14s | %-36s | %-5s | %s | %s\n" "$id" "$prio" "$action" "$pg" "$hit" "$peer" "$ports"
        if [ "$title" = "DEST ROWS" ]; then
            printf 'Dest rows\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$id" "$prio" "$action" "$pg" "$hit" "$ports" >> "$WORK/summary.tsv"
        else
            printf 'Source rows\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$id" "$prio" "$action" "$pg" "$hit" "$ports" >> "$WORK/summary.tsv"
        fi
    done < "$WORK/rules.tsv"
    if [ "$shown" -eq 0 ]; then
        echo "(no ACLs)"
    fi
    echo ""
}

print_built_table() {
    local section id prio action pg hit ports
    echo "  SECTION     | ID   | PRIO  | ACTION         | PORT GROUP                           | MATCH | SERVICE PORTS"
    echo "  ------------|------|-------|----------------|--------------------------------------|-------|--------------"
    if [ ! -s "$WORK/summary.tsv" ]; then
        echo "  (no rows)"
        return
    fi
    while IFS=$'\x1f' read -r section id prio action pg hit ports; do
        [ -n "$id" ] || continue
        printf "  %-11s | %-4s | %-5s | %-14s | %-36s | %-5s | %s\n" "$section" "$id" "$prio" "$action" "$pg" "$hit" "${ports:-ALL}"
    done < "$WORK/summary.tsv"
}

print_verdict_block() {
    local from_nic="$1" from_ip="$2" to_nic="$3" to_ip="$4" flow="$5"
    local out_row in_row out_id out_prio out_act out_pg in_id in_prio in_act in_pg out_v in_v verdict out_ports in_ports
    echo "======================================================================================================================================"
    echo " VERDICT"
    echo "======================================================================================================================================"
    echo "  $flow    ${PROTO}/${DST_PORT}"
    echo "  from $from_nic  IP ${from_ip:-unknown}"
    echo "  to   $to_nic  IP ${to_ip:-unknown}"
    echo "  logic: source NIC outbound rules only; destination NIC inbound rules only"
    echo "  port-set match is live OVN membership, no json file"
    echo "  a drop on either side denies the packet"
    echo ""
    print_built_table
    echo ""
    if out_row=$(winning_rule "$from_nic" outbound "$to_ip" "$to_nic"); then
        IFS=$'\x1f' read -r out_id out_prio out_act out_pg _peer <<< "$out_row"
        out_ports=$(awk -F $'\x1f' -v id="$out_id" '$2 == id { print $7; exit }' "$WORK/summary.tsv")
        echo "  source row: ID $out_id  PRIO $out_prio  $out_act  PORT GROUP $out_pg  SERVICE PORTS ${out_ports:-ALL}"
    else
        out_act=""
        echo "  source row: no matching ACL (default allow)"
    fi
    if in_row=$(winning_rule "$to_nic" inbound "$from_ip" "$from_nic"); then
        IFS=$'\x1f' read -r in_id in_prio in_act in_pg _peer <<< "$in_row"
        in_ports=$(awk -F $'\x1f' -v id="$in_id" '$2 == id { print $7; exit }' "$WORK/summary.tsv")
        echo "  dest row:   ID $in_id  PRIO $in_prio  $in_act  PORT GROUP $in_pg  SERVICE PORTS ${in_ports:-ALL}"
    else
        in_act=""
        echo "  dest row:   no matching ACL (default allow)"
    fi
    out_v=$(action_word "$out_act")
    in_v=$(action_word "$in_act")
    if [ "$out_v" = "denied" ] || [ "$in_v" = "denied" ]; then
        verdict="denied"
    else
        verdict="allowed"
    fi
    echo "  verdict: $verdict"
    if [ -z "$from_ip" ] || [ -z "$to_ip" ]; then
        echo "  note: a NIC has no IPv4 in OVN, so only rules with no peer address were applied"
    fi
    echo ""
}

print_conclusion() {
    local src src_ip dst_ip flow
    [ -n "$DST_NIC" ] && [ -n "$DST_PORT" ] || return 0
    dst_ip=$(nic_ip "$DST_NIC")
    for src in "$@"; do
        [ "$src" = "$DST_NIC" ] && continue
        src_ip=$(nic_ip "$src")
        flow="$src -> $DST_NIC"
        echo "  LOGIC  $flow"
        echo "  source NIC outbound rules only"
        echo "  destination NIC inbound rules only"
        echo "  port-set match is live OVN membership, no json file"
        echo "  a drop on either side denies the packet"
        echo ""
        : > "$WORK/summary.tsv"
        print_side_rows "SOURCE ROWS" "$src" outbound "$dst_ip" "DESTINATION" "$flow" "$DST_NIC"
        print_side_rows "DEST ROWS" "$DST_NIC" inbound "$src_ip" "SOURCE" "$flow" "$src"
        print_verdict_block "$src" "$src_ip" "$DST_NIC" "$dst_ip" "$flow"
        flow="$DST_NIC -> $src"
        echo "  LOGIC  $flow"
        echo "  source NIC outbound rules only"
        echo "  destination NIC inbound rules only"
        echo "  port-set match is live OVN membership, no json file"
        echo "  a drop on either side denies the packet"
        echo ""
        : > "$WORK/summary.tsv"
        print_side_rows "SOURCE ROWS" "$DST_NIC" outbound "$src_ip" "DESTINATION" "$flow" "$src"
        print_side_rows "DEST ROWS" "$src" inbound "$dst_ip" "SOURCE" "$flow" "$DST_NIC"
        print_verdict_block "$DST_NIC" "$dst_ip" "$src" "$src_ip" "$flow"
    done
}

print_legend() {
    local nic uuid id prio dir action pg match_rule peer side key
    echo "======================================================================================================================================"
    echo " LEGEND"
    echo "======================================================================================================================================"
    echo "  port group - IP list. The same port group is listed once for each distinct IP list."
    echo "  ID is the same number in PORT GROUPS BY PRIORITY and in the IP chart."
    echo "  Higher PRIO is checked first. drop denies. allow-related allows."
    echo ""
    : > "$WORK/seenleg"
    if [ -s "$WORK/rules.tsv" ]; then
        while IFS=$'\x1f' read -r id prio dir action pg match_rule; do
            [ -n "$pg" ] || continue
            if [ "$dir" = "inbound" ]; then
                side="src"
            else
                side="dst"
            fi
            peer=$(peer_of "$match_rule" "$side")
            key=$(printf '%s\t%s' "$pg" "$peer")
            if grep -Fxq "$key" "$WORK/seenleg"; then
                continue
            fi
            printf '%s\n' "$key" >> "$WORK/seenleg"
            echo "$pg - $peer"
        done < "$WORK/rules.tsv"
    else
        echo "(no port group IP mapping)"
    fi
    echo ""
    if [ -s "$WORK/nicmap" ]; then
        sort -u "$WORK/nicmap" | while read -r nic uuid; do
            [ -n "$nic" ] || continue
            echo "NIC $nic -> PORT GROUP $uuid"
        done
    fi
    echo ""
}

build_rules() {
    local rows="$1" filtered id=0 prio dir action pg match_rule
    : > "$WORK/rules.tsv"
    filtered=$(
        printf '%s\n' "$rows" | while IFS=$'\x1f' read -r prio action _sg match_rule; do
            [ -n "$match_rule" ] || continue
            if printf '%s\n' "$match_rule" | grep -q "outport == @"; then
                pg=$(printf '%s\n' "$match_rule" | grep -oE 'outport == @[^ )]+' | head -n 1 | sed 's/^outport == @//')
                printf '%s\x1finbound\x1f%s\x1f%s\x1f%s\n' "$prio" "$action" "$(pg_to_uuid "$pg")" "$match_rule"
            fi
            if printf '%s\n' "$match_rule" | grep -q "inport == @"; then
                pg=$(printf '%s\n' "$match_rule" | grep -oE 'inport == @[^ )]+' | head -n 1 | sed 's/^inport == @//')
                printf '%s\x1foutbound\x1f%s\x1f%s\x1f%s\n' "$prio" "$action" "$(pg_to_uuid "$pg")" "$match_rule"
            fi
        done | sort -t $'\x1f' -k1,1nr
    )
    [ -n "$filtered" ] || return 0
    while IFS=$'\x1f' read -r prio dir action pg match_rule; do
        [ -n "$pg" ] || continue
        id=$((id + 1))
        printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$id" "$prio" "$dir" "$action" "$pg" "$match_rule" >> "$WORK/rules.tsv"
    done <<< "$filtered"
}

print_priority_chart() {
    local id prio dir action pg match_rule
    echo "======================================================================================================================================"
    echo " PORT GROUPS BY PRIORITY"
    echo "======================================================================================================================================"
    printf "%-4s | %-5s | %-8s | %-14s | %s\n" "ID" "PRIO" "DIR" "ACTION" "PORT GROUP"
    printf "%-4s-|-%-5s-|-%-8s-|-%-14s-|-%s\n" "----" "-----" "--------" "--------------" "------------------------------------"
    if [ ! -s "$WORK/rules.tsv" ]; then
        echo "(no ACLs)"
        echo ""
        return
    fi
    while IFS=$'\x1f' read -r id prio dir action pg match_rule; do
        [ -n "$pg" ] || continue
        printf "%-4s | %-5s | %-8s | %-14s | %s\n" "$id" "$prio" "$dir" "$action" "$pg"
    done < "$WORK/rules.tsv"
    echo ""
}

run_inside() {
    local nic lsp pg lname groups=() seen=" " found present=0
    local -a nics=()
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dst)
                DST_NIC=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
                shift 2
                ;;
            --port)
                DST_PORT="$2"
                shift 2
                ;;
            --proto)
                PROTO=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
                shift 2
                ;;
            *)
                nics+=("$1")
                shift
                ;;
        esac
    done
    local -a src_nics=("${nics[@]}")
    WORK="${WORK:-$(mktemp -d /tmp/ovn-port-set.XXXXXX)}"
    : > "$WORK/nicmap"
    command -v ovn-nbctl >/dev/null 2>&1 || die "ovn-nbctl not found"
    [ -S "${NB_DB#unix:}" ] || die "Northbound socket not found at ${NB_DB#unix:}"
    if [ -n "$DST_NIC" ]; then
        for nic in "${nics[@]}"; do
            [ "$nic" = "$DST_NIC" ] && present=1
        done
        [ "$present" -eq 0 ] && nics+=("$DST_NIC")
    fi

    echo "======================================================================================================================================"
    echo " NIC PORT SETS"
    echo "======================================================================================================================================"
    for nic in "${nics[@]}"; do
        nic=$(printf '%s' "$nic" | tr '[:upper:]' '[:lower:]')
        echo "NIC: $nic"
        log "NIC: $nic"
        found=0
        while IFS= read -r lsp; do
            lsp=$(trim "$lsp")
            [ -n "$lsp" ] || continue
            found=1
            lname=$(ovn --data=bare --no-heading --columns=name list Logical_Switch_Port "$lsp" 2>/dev/null | head -n 1 || true)
            lname=$(trim "$lname")
            echo "  LSP: $lsp    name=${lname:-unknown}"
            log "  LSP: $lsp name=${lname:-unknown}"
            while IFS= read -r pg; do
                pg=$(trim "$pg")
                [ -n "$pg" ] || continue
                echo "  PORT SET: $(pg_to_uuid "$pg")    $pg"
                log "  PORT SET: $(pg_to_uuid "$pg") $pg"
                printf '%s %s\n' "$nic" "$(pg_to_uuid "$pg")" >> "$WORK/nicmap"
                case "$seen" in
                    *" $pg "*) ;;
                    *)
                        seen="${seen}${pg} "
                        groups+=("$pg")
                        ;;
                esac
            done < <(find_port_groups "$lsp")
        done < <(find_lsps "$nic")
        if [ "$found" -eq 0 ]; then
            log "LSP not found for $nic (expected port_${nic})"
            echo "  LSP: not found"
        fi
    done
    echo ""
    if [ "${#groups[@]}" -eq 0 ]; then
        die "no port set contains the given NIC $(tr '\n' ' ' < "$WORK/pg.err" 2>/dev/null | cut -c1-220)"
    fi

    log "Loading ACLs for ${#groups[@]} port set(s)"
    local ACLS
    ACLS=$(fetch_group_acls "${groups[@]}") || die "failed to read ACLs"

    build_rules "$ACLS"
    print_legend
    if [ -n "$DST_NIC" ] && [ -n "$DST_PORT" ]; then
        print_conclusion "${src_nics[@]}"
        return
    fi
    print_priority_chart

    echo "======================================================================================================================================"
    echo " PORT GROUP IP CHART"
    echo "======================================================================================================================================"
    for pg in "${groups[@]}"; do
        echo " TARGET PORT GROUP: $pg"
        echo " PORT SET: $(pg_to_uuid "$pg")"
        member_ips=$(resolve_port_group "$pg")
        if [ -n "$member_ips" ]; then
            echo " MEMBER IPs: $member_ips"
        else
            echo " MEMBER IPs: (none recorded on the logical port)"
        fi
        echo "--------------------------------------------------------------------------------------------------------------------------------------"
    done
    echo ""
    print_acl_table ">>> 1. FROM WHERE IT CAN RECEIVE TRAFFIC (INBOUND / INGRESS) <<<" inbound "SOURCE (Who is sending)"
    echo ""
    echo ""
    print_acl_table ">>> 2. WHERE IT CAN SEND TRAFFIC (OUTBOUND / EGRESS) <<<" outbound "DESTINATION (Where it can send)"
    echo "======================================================================================================================================"
}

detect_platform() {
    PLATFORM="cmsp"
    SMSP_UUID=""
    local out
    if ! command -v mspctl >/dev/null 2>&1; then
        log "PLATFORM: cmsp (mspctl not installed)"
        return
    fi
    out=$(mspctl cluster get flow --verbose 2>&1 || true)
    SMSP_UUID=$(printf '%s\n' "$out" | grep -oiE 'ClusterUUID[^0-9a-fA-F-]{0,24}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' \
        | grep -oE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | head -n 1 || true)
    if [ -n "$SMSP_UUID" ]; then
        PLATFORM="smsp"
        log "PLATFORM: smsp cluster=$SMSP_UUID"
    else
        log "PLATFORM: cmsp"
    fi
}

pick_kubectl() {
    local kbin
    kbin=$(command -v kubectl || true)
    if [ -z "$kbin" ]; then
        local cand
        for cand in /usr/bin/kubectl /usr/local/bin/kubectl /home/nutanix/bin/kubectl; do
            if [ -x "$cand" ]; then
                kbin="$cand"
                break
            fi
        done
    fi
    [ -n "$kbin" ] || die "kubectl not found"
    if sudo -n "$kbin" get ns >/dev/null 2>&1; then
        KCTL=(sudo -n "$kbin")
    elif "$kbin" get ns >/dev/null 2>&1; then
        KCTL=("$kbin")
    else
        die "kubectl get ns failed"
    fi
    if [ -n "${KUBECONFIG_FILE:-}" ]; then
        KCTL+=(--kubeconfig "$KUBECONFIG_FILE")
    fi
}

write_smsp_kubeconfig() {
    local text yaml marker idx
    text=$(mspctl cluster kubeconfig flow 2>&1 || true)
    yaml=""
    for marker in "apiVersion:" "kind: Config" "clusters:"; do
        idx=$(printf '%s\n' "$text" | grep -n -m1 -F "$marker" | cut -d: -f1 || true)
        if [ -n "$idx" ]; then
            yaml=$(printf '%s\n' "$text" | tail -n +"$idx")
            break
        fi
    done
    [ -n "$yaml" ] || die "mspctl cluster kubeconfig flow did not return a kubeconfig"
    KUBECONFIG_FILE="$WORK/flow.kubeconfig"
    printf '%s\n' "$yaml" > "$KUBECONFIG_FILE"
    chmod 600 "$KUBECONFIG_FILE" || true
}

find_ovn_pod() {
    local ns name phase label
    OVN_NS=""
    OVN_POD=""
    while IFS=$'\t' read -r ns name phase label; do
        [ "$phase" = "Running" ] || continue
        if [ "$name" = "anc-ovn-0" ]; then
            OVN_NS="$ns"
            OVN_POD="$name"
            break
        fi
        if [ "$label" = "anc-ovn" ] || [[ "$name" == anc-ovn-* ]]; then
            if [ -z "$OVN_POD" ]; then
                OVN_NS="$ns"
                OVN_POD="$name"
            fi
        fi
    done < <("${KCTL[@]}" get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.metadata.labels.app}{"\n"}{end}')
    [ -n "$OVN_POD" ] || die "no Running anc-ovn pod"
    log "OVN POD: ${OVN_NS}/${OVN_POD} container=${OVN_CONTAINER}"
}

run_remote() {
    local -a exec_cmd
    exec_cmd=("${KCTL[@]}" exec -i -n "$OVN_NS" "$OVN_POD")
    if "${KCTL[@]}" exec -n "$OVN_NS" "$OVN_POD" -c "$OVN_CONTAINER" -- ovn-nbctl --version >/dev/null 2>&1; then
        exec_cmd+=(-c "$OVN_CONTAINER")
    elif "${KCTL[@]}" exec -n "$OVN_NS" "$OVN_POD" -- ovn-nbctl --version >/dev/null 2>&1; then
        log "container ${OVN_CONTAINER} has no ovn-nbctl; using the pod default container"
    else
        die "ovn-nbctl failed in ${OVN_NS}/${OVN_POD}"
    fi
    local -a verdict_args=()
    if [ -n "$DST_NIC" ]; then
        verdict_args+=(--dst "$DST_NIC" --port "$DST_PORT" --proto "$PROTO")
    fi
    "${exec_cmd[@]}" -- env INSIDE_OVN=1 COLUMNS=1000000 bash -s -- "$@" "${verdict_args[@]}" < "$0"
}

is_uuid() {
    [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
}

main() {
    [ "$#" -ge 1 ] || usage
    local arg nic raw=()
    local nics=()
    local parts=()
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --dst)
                [ -n "${2:-}" ] || usage
                DST_NIC=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
                shift 2
                ;;
            --port)
                [ -n "${2:-}" ] || usage
                DST_PORT="$2"
                shift 2
                ;;
            --proto)
                [ -n "${2:-}" ] || usage
                PROTO=$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')
                shift 2
                ;;
            -h|--help)
                help_text
                exit 0
                ;;
            *)
                raw+=("$1")
                shift
                ;;
        esac
    done
    if [ -z "$DST_NIC" ] && [ -z "$DST_PORT" ] && [ "${#raw[@]}" -eq 3 ]; then
        case "${raw[2]}" in
            ''|*[!0-9]*) ;;
            *)
                DST_NIC=$(printf '%s' "${raw[1]}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
                DST_PORT="${raw[2]}"
                raw=("${raw[0]}")
                ;;
        esac
    fi
    if [ -n "$DST_NIC" ] || [ -n "$DST_PORT" ]; then
        [ -n "$DST_NIC" ] && [ -n "$DST_PORT" ] || die "destination NIC and port are both required"
        is_uuid "$DST_NIC" || die "not a NIC uuid: $DST_NIC"
        case "$DST_PORT" in
            ''|*[!0-9]*) die "port must be a number: $DST_PORT" ;;
        esac
        [ "$DST_PORT" -le 65535 ] || die "port must be 0-65535: $DST_PORT"
        case "$PROTO" in
            tcp|udp|icmp) ;;
            *) die "proto must be tcp, udp, or icmp" ;;
        esac
    fi
    for arg in "${raw[@]}"; do
        IFS=',' read -ra parts <<< "$arg"
        for nic in "${parts[@]}"; do
            nic=$(printf '%s' "$nic" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
            [ -n "$nic" ] || continue
            if ! is_uuid "$nic"; then
                die "not a NIC uuid: $nic"
            fi
            nics+=("$nic")
        done
    done
    [ "${#nics[@]}" -ge 1 ] || usage

    if [ -S "${NB_DB#unix:}" ] && command -v ovn-nbctl >/dev/null 2>&1; then
        log "PLATFORM: local-ovn"
        run_inside "${nics[@]}"
        return
    fi

    WORK=$(mktemp -d /tmp/ovn-port-set.XXXXXX)
    detect_platform
    if [ "$PLATFORM" = "smsp" ]; then
        write_smsp_kubeconfig
    fi
    pick_kubectl
    find_ovn_pod
    run_remote "${nics[@]}"
}

if [ "${INSIDE_OVN:-}" = "1" ]; then
    run_inside "$@"
elif [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
