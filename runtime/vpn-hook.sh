#!/bin/sh
set -eu
umask 077
[ "$(id -u)" -eq 0 ] && [ "${dev:-}" = tun0 ] || exit 1
state=/run/pia-transmission
runtime=/usr/local/lib/pia-transmission
case ${script_type:-} in
    route-up)
        # OpenVPN invokes this only after TLS/authentication and interface setup.
        ip -4 -o address show dev tun0 | awk '/inet / {found=1} END {exit !found}'
        dns=10.0.0.242
        index=1
        while option=$(printenv "foreign_option_$index"); do
            case "$option" in
                'dhcp-option DNS '*) dns=${option#dhcp-option DNS }; break ;;
            esac
            index=$((index + 1))
            [ "$index" -le 128 ] || break
        done
        printf '%s\n' "$dns" | awk -F. 'NF != 4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1}'
        ip -4 route replace default dev tun0 metric 10 table 100
        ip -4 route replace "$dns/32" dev tun0 table 100
        # The root PF worker also resolves authentication API names via PIA DNS.
        ip -4 route replace "$dns/32" dev tun0
        printf 'nameserver %s\n' "$dns" > /etc/resolv.conf
        # Install routes/DNS first, permissions second, readiness last.
        {
            echo 'flush chain inet pia_transmission vpn_traffic'
            echo 'flush chain inet pia_transmission vpn_dns'
            echo 'flush chain inet pia_transmission vpn_ingress'
            echo 'flush chain inet pia_transmission vpn_forward'
            echo 'add rule inet pia_transmission vpn_ingress jump vpn_forward'
            echo 'add rule inet pia_transmission vpn_traffic oifname "tun0" meta nfproto ipv4 accept'
            printf 'add rule inet pia_transmission vpn_dns oifname "tun0" ip daddr %s accept\n' "$dns"
        } | nft -f -
        # Missing/invalid PF gateway disables PF, not the protected VPN.
        rm -f "$state/pf-gateway" "$state/pf-active"
        if printf '%s\n' "${route_vpn_gateway:-}" | awk -F. 'NF != 4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1}'; then
            printf '%s\n' "$route_vpn_gateway" > "$state/pf-gateway"
        fi
        generation=$(mktemp "$state/generation.XXXXXX")
        printf '%s\n' "${generation##*/}" > "$state/ready"
        rm -f "$generation"
        ;;
    route-pre-down|down)
        "$runtime/vpn-routing.sh" close
        ;;
    *) exit 1 ;;
esac
