#!/bin/sh
# Sourced by the serialized discovery/initial-authentication controller only.
# PF refresh uses tun0 and must not change this set. Callers cancel $active.
bootstrap_fetch() {
    bootstrap_host=$1
    shift
    case "$bootstrap_host" in
        serverlist.piaservers.net|www.privateinternetaccess.com) ;;
        *) return 1 ;;
    esac
    # Revoke the previous snapshot before DNS, including on failed retries.
    nft flush set inet pia_transmission bootstrap_https || return 1
    # Absolute names prevent a failed lookup from using a local search suffix.
    bootstrap_answers=$(timeout 10 getent ahostsv4 "$bootstrap_host.") || return 1
    bootstrap_addresses=$(printf '%s\n' "$bootstrap_answers" | awk '
        {
            if (split($1, octets, ".") != 4) exit 1
            for (i=1; i<=4; i++)
                if (octets[i] !~ /^[0-9]+$/ || octets[i] > 255) exit 1
            if (!seen[$1]++) {
                if (++count > 64) exit 1
                addresses = addresses separator $1
                separator = ","
            }
        }
        END {if (!count) exit 1; print addresses}
    ') || return 1
    # One transaction publishes the complete validated snapshot. Entries expire
    # after 45s even after SIGKILL; curl itself is bounded to 30s. Curl uses the
    # same snapshot, avoiding a second DNS lookup and retaining TLS hostname/SNI.
    printf 'flush set inet pia_transmission bootstrap_https\nadd element inet pia_transmission bootstrap_https { %s }\n' \
        "$bootstrap_addresses" | nft -f - || return 1
    env -i PATH=/usr/bin:/bin curl -q --fail --silent --show-error --ipv4 \
        --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 --max-filesize 1048576 \
        --resolve "$bootstrap_host:443:$bootstrap_addresses" "$@" 2>/dev/null &
    active=$!; bootstrap_status=0; wait "$active" || bootstrap_status=$?; active=
    nft flush set inet pia_transmission bootstrap_https || return 1
    return "$bootstrap_status"
}
