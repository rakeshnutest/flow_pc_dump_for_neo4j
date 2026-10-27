#!/bin/bash
# Given one or more NIC UUIDs, find every OVN port group (port set) that
# contains that NIC and print the inbound and outbound ACLs.
#
# Run on the Prism Central VM. CMSP uses the local kubeconfig. SMSP uses
# `mspctl cluster kubeconfig flow`. Inside the anc-ovn pod the same file
# talks to the local Northbound socket.
#
#   bash ovn_port_set_traffic.sh <nic-uuid> [nic-uuid ...]
#
# The NIC UUID is the id in the logical switch port name port_<uuid>.

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

die() {
    echo "ERROR: $*" >&2
    exit 1
}

usage() {
    cat >&2 <<EOF
Usage: $(basename "$0") <nic-uuid> [nic-uuid ...]

Find every port set that contains the NIC, then print inbound and outbound ACLs.
Works on CMSP and SMSP when run on the Prism Central VM.
EOF
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

shorten_ips() {
    local ips="$1" n short
    case "$ips" in
        *,*)
            n=$(printf '%s' "$ips" | awk -F, '{print NF}')
            short=$(printf '%s' "$ips" | cut -d, -f1-6)
            if [ "$n" -gt 6 ]; then
                printf '%s,... (%s addresses)' "$short" "$n"
            else
                printf '%s' "$ips"
            fi
            ;;
        *) printf '%s' "$ips" ;;
    esac
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
            ips=$(ovn get address_set "$as_name" addresses 2>/dev/null | tr -d '\[\]"{} \n\r' || true)
            if [ -z "$ips" ]; then
                ips="$val"
            fi
            ips=$(shorten_ips "$ips")
            AS_CACHE[$as_name]="$ips"
            printf '%s' "$ips"
            ;;
        *) printf '%s' "$val" ;;
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

resolve_port_group() {
    local pg_name="$1" raw uuids=() u chunk=() names="" part i
    raw=$(ovn get port_group "$pg_name" ports 2>/dev/null | tr -d '\[\]"' || true)
    raw="${raw//,/ }"
    # shellcheck disable=SC2206
    uuids=($raw)
    if [ "${#uuids[@]}" -eq 0 ]; then
        printf '@%s' "$pg_name"
        return
    fi
    i=0
    while [ "$i" -lt "${#uuids[@]}" ]; do
        chunk=()
        while [ "$i" -lt "${#uuids[@]}" ] && [ "${#chunk[@]}" -lt 40 ]; do
            u=$(trim "${uuids[$i]}")
            if [ -n "$u" ]; then
                chunk+=("$u")
            fi
            i=$((i + 1))
        done
        if [ "${#chunk[@]}" -eq 0 ]; then
            continue
        fi
        part=$(ovn --data=bare --no-heading --columns=name list Logical_Switch_Port "${chunk[@]}" 2>/dev/null || true)
        names="${names}${part}"$'\n'
    done
    names=$(printf '%s\n' "$names" | join_lines)
    if [ -n "$names" ]; then
        printf '%s' "$names"
    else
        printf '@%s' "$pg_name"
    fi
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
        peer="${peer}$(resolve_addr_set "$item"),"
    done < <(printf '%s\n' "$match_rule" | grep -oE "ip[46][.]${side} == [^ )]+" | sed -E "s/^ip[46][.]${side} == //" || true)
    if [ -z "$peer" ]; then
        printf '%s' "ANY (0.0.0.0/0)"
    else
        printf '%s' "${peer%,}"
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
    local title="$1" kind="$2" peer_hdr="$3" rows="$4"
    local filtered prio action sg_name match_rule pg display_name peer ports
    echo "$title"
    printf "%-5s | %-14s | %-35s | %-55s | %s\n" "PRIO" "ACTION" "SECURITY GROUP / PORT GROUP" "$peer_hdr" "ON PORTS"
    printf "%-5s-|-%-14s-|-%-35s-|-%-55s-|-%s\n" "-----" "--------------" "-----------------------------------" "-------------------------------------------------------" "------------------------------"
    if [ "$kind" = "in" ]; then
        filtered=$(printf '%s\n' "$rows" | grep "outport == @" || true)
    else
        filtered=$(printf '%s\n' "$rows" | grep "inport == @" || true)
    fi
    if [ -n "$filtered" ]; then
        filtered=$(printf '%s\n' "$filtered" | sort -nr)
    fi
    if [ -z "$filtered" ]; then
        echo "(no ACLs)"
        if [ -n "$rows" ]; then
            log "no $kind rows matched; sample=$(printf '%s\n' "$rows" | head -n 1 | cut -c1-240)"
        fi
        return
    fi
    while IFS=$'\x1f' read -r prio action sg_name match_rule; do
        [ -n "$match_rule" ] || continue
        if [ "$kind" = "in" ]; then
            pg=$(printf '%s\n' "$match_rule" | grep -oE 'outport == @[^ )]+' | head -n 1 | sed 's/^outport == @//' || true)
        else
            pg=$(printf '%s\n' "$match_rule" | grep -oE 'inport == @[^ )]+' | head -n 1 | sed 's/^inport == @//' || true)
        fi
        if [ -n "$sg_name" ]; then
            display_name="SG: $sg_name"
        else
            display_name="@${pg:-unknown}"
        fi
        if [ "$kind" = "in" ]; then
            peer=$(peer_of "$match_rule" "src")
        else
            peer=$(peer_of "$match_rule" "dst")
        fi
        ports=$(ports_of "$match_rule")
        printf "%-5s | %-14s | %-35s | %-55s | %s\n" "$prio" "$action" "$display_name" "$peer" "$ports"
    done <<< "$filtered"
}

run_inside() {
    local nic lsp pg lname groups=() seen=" " found
    WORK="${WORK:-$(mktemp -d /tmp/ovn-port-set.XXXXXX)}"
    command -v ovn-nbctl >/dev/null 2>&1 || die "ovn-nbctl not found"
    [ -S "${NB_DB#unix:}" ] || die "Northbound socket not found at ${NB_DB#unix:}"

    echo "======================================================================================================================================"
    echo " NIC PORT SETS"
    echo "======================================================================================================================================"
    for nic in "$@"; do
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

    echo "======================================================================================================================================"
    echo " CONSOLIDATED TRAFFIC POLICY"
    echo "======================================================================================================================================"
    for pg in "${groups[@]}"; do
        echo " TARGET PORT GROUP: $pg"
        echo " PORT SET: $(pg_to_uuid "$pg")"
        echo " PORTS AFFECTED: $(resolve_port_group "$pg")"
        echo "--------------------------------------------------------------------------------------------------------------------------------------"
    done
    echo ""
    print_acl_table ">>> 1. FROM WHERE IT CAN RECEIVE TRAFFIC (INBOUND / INGRESS) <<<" in "SOURCE (Who is sending)" "$ACLS"
    echo ""
    echo ""
    print_acl_table ">>> 2. WHERE IT CAN SEND TRAFFIC (OUTBOUND / EGRESS) <<<" out "DESTINATION (Where it can send)" "$ACLS"
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
    "${exec_cmd[@]}" -- env INSIDE_OVN=1 COLUMNS=1000000 bash -s -- "$@" < "$0"
}

main() {
    [ "$#" -ge 1 ] || usage
    local arg nic
    local nics=()
    local parts=()
    for arg in "$@"; do
        IFS=',' read -ra parts <<< "$arg"
        for nic in "${parts[@]}"; do
            nic=$(printf '%s' "$nic" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
            [ -n "$nic" ] || continue
            if ! [[ "$nic" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
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
