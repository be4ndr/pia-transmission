#!/bin/sh
set -eu
umask 077
state=/run/pia-transmission
. /usr/local/lib/pia-transmission/bootstrap-https.sh
active=
fail() { echo "pia-transmission: $*" >&2; exit 1; }
trap 'nft flush set inet pia_transmission bootstrap_https || :; rm -f "$state/username" "$state/password" "$state/token-response" "$state/servers-response"' EXIT
cancel() {
    trap '' TERM INT
    if [ -n "$active" ]; then kill -TERM "$active" 2>/dev/null || :; wait "$active" 2>/dev/null || :; fi
    for pid in $(jobs -p); do kill -TERM "$pid" 2>/dev/null || :; done
    wait 2>/dev/null || :
    exit 1
}
trap cancel TERM INT

/usr/local/lib/pia-transmission/pia-auth.sh check

# Disable curlrc, proxies, redirects, tracing and TLS downgrades. Never print an
# API body or credentials. Bootstrap DNS is allowed only for UID 0.
bootstrap_fetch serverlist.piaservers.net --output "$state/servers-response" https://serverlist.piaservers.net/vpninfo/servers/v6 || fail 'PIA discovery failed'
head -n 1 "$state/servers-response" > "$state/servers.json"
# Validate the selected endpoint's entire value before writing config/nft syntax.
# Round-robin across the region's available servers on controller retries.
jq -er --arg region "${PIA_REGION:?set PIA_REGION}" --argjson attempt "${1:-0}" '
    [.regions[] | select(.id == $region) | .servers.ovpnudp[]]
    | if length == 0 then error("unknown region") else .[$attempt % length] end
    | select(.ip | test("^([0-9]{1,3}\\.){3}[0-9]{1,3}$"))
    | select(.ip | split(".") | all(.[]; tonumber <= 255))
    | select(.cn | test("^[A-Za-z0-9_.-]+$"))
    | [.ip,.cn] | @tsv
' "$state/servers.json" > "$state/endpoint" 2>/dev/null || fail 'invalid PIA region or endpoint'
read -r address hostname < "$state/endpoint"

jq -r --arg region "$PIA_REGION" '.regions[] | select(.id == $region) | (.port_forward == true)' "$state/servers.json" > "$state/pf-supported"
/usr/local/lib/pia-transmission/pia-auth.sh vpn &
active=$!; authenticated=0; wait "$active" || authenticated=$?; active=
[ "$authenticated" -eq 0 ] || exit "$authenticated"
printf 'flush set inet pia_transmission vpn_endpoint\nadd element inet pia_transmission vpn_endpoint { %s }\n' "$address" | nft -f -
cat > "$state/openvpn.conf" <<EOF
client
dev tun0
dev-type tun
disable-dco
proto udp4
remote $address 8080
nobind
resolv-retry 0
connect-retry-max 1
connect-timeout 15
ca /usr/local/share/pia/ca.crt
remote-cert-tls server
verify-x509-name $hostname name
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-256-CBC
data-ciphers-fallback AES-256-CBC
auth SHA256
auth-user-pass $state/auth
auth-nocache
auth-retry none
reneg-sec 0
route-noexec
# Retain redirect metadata so OpenVPN exports route_vpn_gateway.
# route-noexec prevents ALL pushed routes from changing kernel routing.
pull-filter ignore "route-ipv6"
pull-filter ignore "ifconfig-ipv6"
script-security 2
route-up /usr/local/lib/pia-transmission/vpn-hook.sh
route-pre-down /usr/local/lib/pia-transmission/vpn-hook.sh
down /usr/local/lib/pia-transmission/vpn-hook.sh
down-pre
up-restart
ping 10
ping-restart 30
verb 0
log /dev/null
EOF
