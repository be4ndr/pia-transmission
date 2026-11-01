#!/bin/sh
# Emit an atomic nftables batch. nft validates address/mask syntax before it
# commits anything; the character allowlist prevents configuration injection.
set -eu
networks=${1:?LOCAL_NETWORK must contain comma-separated CIDRs}
case "$networks" in
    *[!0-9a-fA-F:./,\ ]*) echo 'Invalid LOCAL_NETWORK characters' >&2; exit 1 ;;
esac
networks=$(printf '%s' "$networks" | tr -d ' ')
case "$networks" in
    ''|,*|*,|*,,*) echo 'LOCAL_NETWORK contains an empty CIDR' >&2; exit 1 ;;
esac

cat <<'EOF'
add table inet pia_transmission
flush table inet pia_transmission
add set inet pia_transmission vpn_endpoint { type ipv4_addr; }
add set inet pia_transmission bootstrap_https { type ipv4_addr; flags timeout; timeout 45s; }
add chain inet pia_transmission vpn_traffic
add chain inet pia_transmission vpn_dns
add chain inet pia_transmission vpn_ingress
add chain inet pia_transmission vpn_forward
add chain inet pia_transmission input { type filter hook input priority 0; policy drop; }
add chain inet pia_transmission output { type filter hook output priority -150; policy drop; }
add chain inet pia_transmission forward { type filter hook forward priority 0; policy drop; }
add rule inet pia_transmission input ct state invalid drop
add rule inet pia_transmission output ct state invalid drop
# Only controller-originated bootstrap/transport connections receive this mark.
add rule inet pia_transmission input ct mark 0x50494101 ct direction reply ct state established accept
add rule inet pia_transmission output meta skuid 0 oifname "eth0" ip daddr @vpn_endpoint udp dport 8080 ct mark set 0x50494101 accept
EOF
# Resolver addresses come from the original Docker resolv.conf. Validate before
# interpolation. Transmission can never use these controller-only allowances.
for dns in ${2:-}; do
    printf '%s\n' "$dns" | awk -F. 'NF != 4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1}' || exit 1
    printf 'add rule inet pia_transmission output meta skuid 0 ip daddr %s udp dport 53 ct mark set 0x50494101 accept\n' "$dns"
    printf 'add rule inet pia_transmission output meta skuid 0 ip daddr %s tcp dport 53 ct mark set 0x50494101 accept\n' "$dns"
done
cat <<'EOF'
add rule inet pia_transmission output udp dport 53 jump vpn_dns
add rule inet pia_transmission output tcp dport 53 jump vpn_dns
# Filter DNS before Docker's OUTPUT DNAT, including its internal high-port
# listener, which must not be reachable via the general loopback allowance.
add rule inet pia_transmission output udp dport 53 drop
add rule inet pia_transmission output tcp dport 53 drop
add rule inet pia_transmission output ip daddr 127.0.0.11 drop
add rule inet pia_transmission input iifname "lo" accept
add rule inet pia_transmission output oifname "lo" accept
EOF
old_ifs=$IFS
IFS=,
set -f
for cidr in $networks; do
    case "$cidr" in
        */*) ;;
        *) echo 'LOCAL_NETWORK entries must be CIDRs' >&2; exit 1 ;;
    esac
    case "$cidr" in
        *:*) family=ip6 ;;
        *) family=ip ;;
    esac
    printf 'add rule inet pia_transmission input %s saddr %s tcp dport 9091 ct state { new, established } accept\n' "$family" "$cidr"
    printf 'add rule inet pia_transmission output %s daddr %s tcp sport 9091 ct direction reply ct state established accept\n' "$family" "$cidr"
    printf 'add rule inet pia_transmission output %s daddr %s drop\n' "$family" "$cidr"
done
IFS=$old_ifs
echo 'add rule inet pia_transmission output meta skuid 0 oifname "eth0" ip daddr @bootstrap_https tcp dport 443 ct mark set 0x50494101 accept'
echo 'add rule inet pia_transmission output jump vpn_traffic'
echo 'add rule inet pia_transmission input iifname "tun0" meta nfproto ipv4 ct direction reply ct state established accept'
echo 'add rule inet pia_transmission input iifname "tun0" meta nfproto ipv4 jump vpn_ingress'
