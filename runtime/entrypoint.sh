#!/bin/sh
set -eu
umask 077
ulimit -c 0
runtime=/usr/local/lib/pia-transmission
state=/run/pia-transmission
die() { echo "pia-transmission: $*" >&2; exit 1; }
[ "$#" -eq 0 ] || die 'custom commands are not supported'
[ "$(id -u)" -eq 0 ] || die 'the controller must run as root'
drop-privileges --check-ids "${PUID:?set PUID}" "${PGID:?set PGID}"
# iproute2 accepts base-prefixed numbers; the launcher uses decimal IDs.
PUID=$(printf '%s' "$PUID" | sed 's/^0*//')
PGID=$(printf '%s' "$PGID" | sed 's/^0*//')
. "$runtime/select-web-ui.sh"
[ "${TRANSMISSION_RPC_PORT:-9091}" = 9091 ] || die 'RPC port must be 9091'
[ "${PIA_PROTOCOL:-openvpn}" = openvpn ] || die 'only OpenVPN is supported'
: "${PIA_REGION:?set PIA_REGION}"
: "${WEB_BIND_IP:?set WEB_BIND_IP}"
PIA_PORT_FORWARDING=${PIA_PORT_FORWARDING:-true}
case "$PIA_PORT_FORWARDING" in true|false) ;; *) die 'PIA_PORT_FORWARDING must be true or false' ;; esac
VPN_START_TIMEOUT=${VPN_START_TIMEOUT:-90}
VPN_RETRY_DELAY=${VPN_RETRY_DELAY:-5}
for number in "$VPN_START_TIMEOUT" "$VPN_RETRY_DELAY"; do
    case "$number" in ''|*[!0-9]*) die 'VPN timeouts must be decimal seconds' ;; esac
    [ "$number" -gt 0 ] && [ "$number" -le 3600 ] || die 'VPN timeout out of range'
done

# Protect existing mounts before VPN preparation, even if the VPN never connects.
# Restrict traversal before handing the directory to the application UID.
[ ! -L /config ] || die 'symlink directory: /config'
mkdir -p /config
chmod 0700 /config
chown -h "$PUID:$PGID" /config
[ ! -L /config/settings.json ] || die 'symlink settings: /config/settings.json'
if [ -e /config/settings.json ]; then
    [ -f /config/settings.json ] || die 'settings must be a regular file'
    # Permit migration of a root/previous-UID-owned settings file without
    # touching torrents, resume state, or any other user data.
    chown -h "$PUID:$PGID" /config/settings.json
fi

for directory in /run/secrets "$state"; do
    [ ! -L "$directory" ] || die "symlink directory: $directory"
    mkdir -p "$directory"
    chown 0:0 "$directory"
    chmod 0700 "$directory"
done
rm -f "$state/ready" "$state/auth"
cat /etc/resolv.conf > "$state/bootstrap-resolv.conf"
# Docker's embedded resolver can forward upstream queries from this namespace.
# Its ExtServers metadata identifies those destinations; permitting only
# 127.0.0.11 would block the controller's forwarded queries on Linux Engine.
# Ignore host-namespace/IPv6 entries. network-lock.sh validates IPv4 octets.
bootstrap_dns=$(awk '
    $1=="nameserver" && $2 !~ /:/ {print $2}
    $1=="#" && $2=="ExtServers:" {
        gsub(/[][]/, "")
        for (i=3; i<=NF; i++)
            if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $i
    }
' "$state/bootstrap-resolv.conf")
"$runtime/network-lock.sh" "${LOCAL_NETWORK:?set LOCAL_NETWORK}" "$bootstrap_dns" > "$state/lock.nft"
nft -f "$state/lock.nft" || die 'network protection failed; Transmission will not start'
"$runtime/vpn-routing.sh" init || die 'routing protection failed; Transmission will not start'
echo 'pia-transmission: network protection installed; waiting for VPN' >&2

child=; vpn=; prepare=; sleeper=; pf=; pf_generation=
running() {
    [ -n "$1" ] && kill -0 "$1" 2>/dev/null &&
        [ "$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)" != Z ]
}
stop() {
    trap '' TERM INT
    "$runtime/vpn-routing.sh" close || :
    # Include jobs whose PID assignment was interrupted by a signal.
    jobs=$(jobs -p)
    for pid in "$prepare" "$vpn" "$child" "$sleeper" "$pf" $jobs; do
        if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || :; fi
    done
    for pid in "$prepare" "$vpn" "$child" "$sleeper" "$pf" $jobs; do
        if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || :; fi
    done
    rm -f "$state/auth" "$state/username" "$state/password" "$state/token-response" "$state/pf-token"
    rm -rf "$state/pf" "$state/pf-lease.json"
    exit "${exit_status:-0}"
}
trap stop TERM INT
pause() { sleep "$1" & sleeper=$!; wait "$sleeper" || :; sleeper=; }
check_child() {
    if [ -n "$child" ] && ! running "$child"; then
        status=0; wait "$child" 2>/dev/null || status=$?
        [ "$status" -ne 0 ] || status=1
        echo 'pia-transmission: Transmission exited' >&2
        child=; exit_status=$status; stop
    fi
}
stop_pf() {
    if [ -n "$pf" ]; then kill -TERM "$pf" 2>/dev/null || :; wait "$pf" 2>/dev/null || :; pf=; fi
    pf_generation=
}
close_vpn() {
    stop_pf
    if ! "$runtime/vpn-routing.sh" close; then
        echo 'pia-transmission: failed to close VPN permissions; stopping' >&2
        exit_status=1; stop
    fi
}
start_transmission() {
    for directory in /data /data/complete /data/incomplete; do
        [ ! -L "$directory" ] || die "symlink directory: $directory"
        mkdir -p "$directory"
        if [ "$directory" != /data ]; then chown -h "$PUID:$PGID" "$directory"; fi
    done
    env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/config TZ="${TZ:-UTC}" \
        WEB_BIND_IP="$WEB_BIND_IP" \
        TRANSMISSION_WEB_HOME="$TRANSMISSION_WEB_HOME" \
        TRANSMISSION_DOWNLOAD_DIR="${TRANSMISSION_DOWNLOAD_DIR-}" \
        TRANSMISSION_INCOMPLETE_DIR="${TRANSMISSION_INCOMPLETE_DIR-}" \
        TRANSMISSION_INCOMPLETE_DIR_ENABLED="${TRANSMISSION_INCOMPLETE_DIR_ENABLED-}" \
        drop-privileges "$PUID" "$PGID" "$runtime/start-transmission.sh" &
    child=$!
}

attempt=0
while :; do
    close_vpn
    cat "$state/bootstrap-resolv.conf" > /etc/resolv.conf
    "$runtime/vpn-prepare.sh" "$attempt" & prepare=$!
    while running "$prepare"; do check_child; pause 1; done
    prepared=0; wait "$prepare" || prepared=$?; prepare=
    if [ "$prepared" -eq 0 ]; then
        env -i PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
            openvpn --config "$state/openvpn.conf" > /dev/null 2>&1 & vpn=$!
        waited=0; connected=false
        while running "$vpn"; do
            check_child
            if [ -f "$state/ready" ]; then
                # Never trust a stale marker after interface/route disappearance.
                if ! ip -4 route show table 100 | awk '/^default dev tun0 / {found=1} END {exit !found}'; then
                    close_vpn; break
                fi
                if [ "$connected" = false ]; then
                    echo 'pia-transmission: VPN routing and firewall ready' >&2
                    connected=true
                fi
                waited=0
                [ -n "$child" ] || start_transmission
                generation=$(cat "$state/ready" 2>/dev/null) || { pause 1; continue; }
                if [ "$generation" != "$pf_generation" ]; then stop_pf; fi
                if [ "$PIA_PORT_FORWARDING" = true ] && ! running "$pf"; then
                    [ -z "$pf" ] || wait "$pf" 2>/dev/null || :
                    "$runtime/port-forward.sh" "$generation" & pf=$!
                    pf_generation=$generation
                fi
            else
                stop_pf
                if [ "$connected" = true ]; then
                    echo 'pia-transmission: VPN disconnected; RPC stays available' >&2
                    connected=false
                fi
                waited=$((waited + 1))
                [ "$waited" -lt "$VPN_START_TIMEOUT" ] || break
            fi
            pause 1
        done
        close_vpn
        kill -TERM "$vpn" 2>/dev/null || :
        wait "$vpn" 2>/dev/null || :; vpn=
        echo 'pia-transmission: VPN unavailable; retrying with torrent egress blocked' >&2
    fi
    rm -f "$state/auth"
    check_child
    attempt=$((attempt + 1))
    if [ "$prepared" -eq 75 ]; then pause 300; else pause "$VPN_RETRY_DELAY"; fi
done
