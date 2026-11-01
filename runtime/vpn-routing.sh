#!/bin/sh
# Dedicated application routes: a missing tunnel must never fall through to main.
set -eu
state=/run/pia-transmission
case ${1:?routing operation} in
    init)
        gateway=$(ip -4 route show default dev eth0 | awk '$1=="default" && $2=="via" {print $3; exit}')
        [ -n "$gateway" ] || { echo 'Missing eth0 gateway' >&2; exit 1; }
        ip -4 route replace unreachable default metric 32767 table 100
        ip -4 rule add priority 1000 uidrange "$PUID-$PUID" table 100
        ip -6 route replace unreachable default table 100
        ip -6 rule add priority 1000 uidrange "$PUID-$PUID" table 100
        old_ifs=$IFS; IFS=,
        for cidr in $(printf '%s' "$LOCAL_NETWORK" | tr -d ' '); do
            case "$cidr" in
                *:*) ;; # RPC is IPv4-only.
                *) ip -4 route replace "$cidr" via "$gateway" dev eth0 onlink table 100 ;;
            esac
        done
        IFS=$old_ifs
        ;;
    close)
        rm -f "$state/ready" "$state/pf-gateway" "$state/pf-active" "$state/pf-status"
        # Atomic removal of tunnel permissions. Leave LAN RPC rules untouched.
        printf 'flush chain inet pia_transmission vpn_traffic\nflush chain inet pia_transmission vpn_dns\nflush chain inet pia_transmission vpn_ingress\nflush chain inet pia_transmission vpn_forward\n' | nft -f -
        ip -4 route del default dev tun0 table 100 2>/dev/null || :
        ;;
    *) exit 1 ;;
esac
