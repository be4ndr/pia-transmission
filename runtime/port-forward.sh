#!/bin/sh
# One root worker per VPN generation. Secrets are files, never argv/env/logs.
set -eu
umask 077
state=/run/pia-transmission
runtime=/usr/local/lib/pia-transmission
generation=${1:?VPN generation required}
active=
work=$state/pf
mkdir -p "$work"
chmod 0700 "$work"
current() { [ -f "$state/ready" ] && [ "$(cat "$state/ready")" = "$generation" ]; }
clear_port() {
    rm -f "$state/pf-active"
    printf 'flush chain inet pia_transmission vpn_forward\n' | nft -f -
}
cancel() {
    trap '' TERM INT
    if [ -n "$active" ]; then kill -TERM "$active" 2>/dev/null || :; wait "$active" 2>/dev/null || :; fi
    exit 0
}
trap cancel TERM INT
trap 'rm -rf "$work"' EXIT
pause() { sleep "$1" & active=$!; wait "$active" || :; active=; }
fetch() {
    env -i PATH=/usr/bin:/bin curl -q --silent --fail --ipv4 --proto '=https' \
        --tlsv1.2 --interface tun0 --connect-timeout 5 --max-time 15 \
        --max-filesize 65536 --cacert /usr/local/share/pia/ca.crt \
        --connect-to "$hostname:19999:$gateway:19999" --write-out '%{http_code}' "$@" > "$work/http-code" 2>/dev/null &
    active=$!; status=0; wait "$active" || status=$?; active=
    return "$status"
}
lease_valid() {
    jq -e '.status == "OK" and (.payload | type == "string" and length > 0 and length <= 16384 and test("^[A-Za-z0-9+/=]+$"))
        and (.signature | type == "string" and length > 0 and length <= 16384 and test("^[A-Za-z0-9+/=]+$"))' \
        "$state/pf-lease.json" > /dev/null 2>&1 || return 1
    jq -rj '.payload' "$state/pf-lease.json" | base64 -d > "$work/decoded" 2>/dev/null || return 1
    port=$(jq -er '.port | select(type == "number" and . == floor and . >= 1024 and . <= 65535 and . != 9091)' "$work/decoded" 2>/dev/null) || return 1
    expires=$(jq -er '.expires_at | select(type == "string") | select(test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?(Z|\\+00:00)$")) | .[0:19] | sub("T"; " ")' "$work/decoded" 2>/dev/null) || return 1
    expires=$(date -u -d "$expires" +%s 2>/dev/null) || return 1
    [ "$expires" -gt "$(( $(date +%s) + 180 ))" ] || return 1
    jq -rj '.payload' "$state/pf-lease.json" > "$work/payload"
    jq -rj '.signature' "$state/pf-lease.json" > "$work/signature"
}
acquire() {
    # Refresh only if the existing token cannot obtain a lease; active VPN auth
    # remains untouched. HTTPS authentication is also bound to tun0.
    for round in 1 2; do
        current || return 1
        if fetch --get --data-urlencode "token@$state/pf-token" --output "$work/response" "https://$hostname:19999/getSignature"; then
            cp "$work/response" "$state/pf-lease.json"
            if lease_valid; then return 0; fi
            # Malformed successful leases are not an authentication failure.
            if jq -e '.status == "OK"' "$work/response" >/dev/null 2>&1; then
                rm -f "$state/pf-lease.json"; return 1
            fi
        else
            # A missing gateway, TLS failure or timeout cannot be fixed by
            # issuing more auth tokens (and can otherwise cause rate limits).
            if [ "$(cat "$work/http-code")" = 429 ]; then failure=pf-rate-limit; return 1; fi
            [ "$status" = 22 ] || return 1
            case $(cat "$work/http-code") in 400|401|403) ;; *) return 1 ;; esac
        fi
        rm -f "$state/pf-lease.json"
        [ "$round" = 1 ] || return 1
        "$runtime/pia-auth.sh" pf &
        active=$!; status=0; wait "$active" || status=$?; active=
        if [ "$status" = 75 ]; then failure=auth-rate-limit; return 1; fi
        [ "$status" = 0 ] || return 1
    done
}
rpc_fetch() {
    env -i PATH=/usr/bin:/bin curl -q --silent --max-time 15 --connect-timeout 2 \
        --proto '=http' --max-filesize 65536 --header "@$work/rpc-headers" \
        --dump-header "$work/rpc-response-headers" --output "$work/rpc-response" \
        --data-binary "@$work/rpc-request" --write-out '%{http_code}' \
        http://127.0.0.1:9091/transmission/rpc > "$work/rpc-code" 2>/dev/null &
    active=$!; status=0; wait "$active" || status=$?; active=
    return "$status"
}
sync_rpc() {
    printf 'Content-Type: application/json\n' > "$work/rpc-headers"
    # Optional separate RPC credentials; hashed settings.json passwords cannot
    # authenticate. Never copy VPN secrets into the application's environment.
    if [ -e /run/secrets/transmission_rpc_username ] || [ -e /run/secrets/transmission_rpc_password ]; then
        for name in username password; do
            file=/run/secrets/transmission_rpc_$name
            [ -f "$file" ] && [ ! -L "$file" ] || return 1
            unset value
            value=$(cat "$file")
            [ -n "$value" ] && [ "${#value}" -le 4096 ] || return 1
            case "$value" in *"
"*|*"$(printf '\r')"*) return 1 ;; esac
            [ "$name" != username ] || case "$value" in *:*) return 1 ;; esac
            printf '%s' "$value" > "$work/rpc-$name"
            unset value
        done
        { cat "$work/rpc-username"; printf ':'; cat "$work/rpc-password"; } | base64 | tr -d '\n' > "$work/basic"
        { printf 'Authorization: Basic '; cat "$work/basic"; printf '\n'; } >> "$work/rpc-headers"
    fi
    printf '{"method":"session-set","arguments":{"peer-port":%s,"peer-port-random-on-start":false,"port-forwarding-enabled":false}}\n' "$port" > "$work/rpc-request"
    rpc_fetch || return 1
    if [ "$(cat "$work/rpc-code")" = 409 ]; then
        sed -n 's/^[Xx]-[Tt]ransmission-[Ss]ession-[Ii]d: *//p' "$work/rpc-response-headers" | tr -d '\r' > "$work/session"
        # Do not allow a response header to inject more request headers.
        unset session
        session=$(cat "$work/session")
        case "$session" in ''|*[!A-Za-z0-9]*) return 1 ;; esac
        { printf 'X-Transmission-Session-Id: '; cat "$work/session"; printf '\n'; } >> "$work/rpc-headers"
        unset session
        rpc_fetch || return 1
    fi
    case $(cat "$work/rpc-code") in 401|403) failure=rpc-auth; return 1 ;; esac
    [ "$(cat "$work/rpc-code")" = 200 ] && jq -e '.result == "success"' "$work/rpc-response" >/dev/null 2>&1 || return 1
    printf '{"method":"session-get"}\n' > "$work/rpc-request"
    rpc_fetch || return 1
    [ "$(cat "$work/rpc-code")" = 200 ] && jq -e --argjson port "$port" '.result == "success" and .arguments["peer-port"] == $port and .arguments["peer-port-random-on-start"] == false and .arguments["port-forwarding-enabled"] == false' "$work/rpc-response" >/dev/null 2>&1
}
update() {
    failure=metadata
    [ -f "$state/pf-gateway" ] || return 1
    gateway=$(cat "$state/pf-gateway")
    printf '%s\n' "$gateway" | awk -F. 'NF != 4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || $i>255) exit 1}' || return 1
    read -r address hostname < "$state/endpoint"
    case "$hostname" in ''|*[!A-Za-z0-9_.-]*) return 1 ;; esac
    failure=lease
    if ! lease_valid; then acquire || return 1; fi
    current || return 1
    failure=bind
    fetch --get --data-urlencode "payload@$work/payload" --data-urlencode "signature@$work/signature" \
        --output "$work/bind-response" "https://$hostname:19999/bindPort" || {
        # HTTP rejection of a cached lease requires reacquisition. Transport
        # failures retain it, avoiding needless port changes on short outages.
        if [ "$(cat "$work/http-code")" = 429 ]; then failure=pf-rate-limit; return 1; fi
        if [ "$status" = 22 ]; then
            case $(cat "$work/http-code") in 400|401|403|410) rm -f "$state/pf-lease.json" ;; esac
        fi
        return 1
    }
    if ! jq -e '.status == "OK"' "$work/bind-response" >/dev/null 2>&1; then
        rm -f "$state/pf-lease.json"; return 1
    fi
    current || return 1
    failure=rpc
    sync_rpc || return 1
    current || return 1
    # The hook controls the separate ingress gate; even a late worker response
    # cannot open eth0, bypass an unreachable route, or restore VPN egress.
    failure=firewall
    {
        echo 'flush chain inet pia_transmission vpn_forward'
        printf 'add rule inet pia_transmission vpn_forward tcp dport %s ct state { new, established } accept\n' "$port"
        printf 'add rule inet pia_transmission vpn_forward udp dport %s ct state { new, established } accept\n' "$port"
    } | nft -f - || return 1
    current || return 1
    printf '%s\n' "$port" > "$state/pf-active"
}
if [ "$(cat "$state/pf-supported" 2>/dev/null)" != true ]; then
    printf 'unsupported\n' > "$state/pf-status"
    echo 'pia-transmission: selected region does not support port forwarding' >&2
    while current; do pause 900; done
    exit 0
fi
while current; do
    if update; then
        printf 'active\n' > "$state/pf-status"
        echo "pia-transmission: forwarded port $port synchronized with Transmission" >&2
        delay=900
        remaining=$((expires - $(date +%s) - 180))
        [ "$remaining" -ge "$delay" ] || delay=$remaining
        [ "$delay" -gt 0 ] || delay=1
    else
        clear_port || exit 1
        printf 'retrying\n' > "$state/pf-status"
        echo "pia-transmission: port forwarding unavailable ($failure); retrying without restarting Transmission" >&2
        delay=60
        [ "$failure" != rpc ] || delay=5
        case "$failure" in auth-rate-limit|pf-rate-limit) delay=300 ;; esac
    fi
    pause "$delay"
done
