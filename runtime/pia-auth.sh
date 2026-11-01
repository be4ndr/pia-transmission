#!/bin/sh
# Shared authentication; PF refresh must not replace active OpenVPN credentials.
set -eu
umask 077
state=/run/pia-transmission
. /usr/local/lib/pia-transmission/bootstrap-https.sh
active=
fail() { echo "pia-transmission: $*" >&2; exit 1; }
trap 'if [ "${1:-vpn}" = vpn ]; then nft flush set inet pia_transmission bootstrap_https || :; fi; rm -f "$state/username" "$state/password" "$state/token-response" "$state/pf-token.tmp" "$state/auth-http-code"' EXIT
cancel() {
    trap '' TERM INT
    if [ -n "$active" ]; then kill -TERM "$active" 2>/dev/null || :; wait "$active" 2>/dev/null || :; fi
    exit 1
}
trap cancel TERM INT
# Do not read secrets into exported variables or external-command arguments.
for name in username password; do
    file=/run/secrets/pia_$name
    [ -f "$file" ] && [ ! -L "$file" ] || fail 'missing or invalid PIA secret mount'
    unset value
    value=$(cat "$file")
    [ -n "$value" ] && [ "${#value}" -le 4096 ] || fail 'empty or oversized PIA secret'
    case "$value" in
        *"
"*|*"$(printf '\r')"*) fail 'PIA secrets must contain a single line' ;;
    esac
    printf '%s' "$value" > "$state/$name"
    unset value
done

[ "${1:-vpn}" != check ] || exit 0

# Disable curlrc, proxies, redirects, tracing and TLS downgrades. Never print an
# API body or credentials. Bootstrap DNS is allowed only for UID 0.
fetch() {
    if [ -z "$vpn_interface" ]; then
        bootstrap_fetch www.privateinternetaccess.com --write-out '%{http_code}' "$@" > "$state/auth-http-code"
        return $?
    fi
    env -i PATH=/usr/bin:/bin curl -q --fail --silent --show-error --ipv4 \
        --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 --max-filesize 1048576 ${vpn_interface:+--interface tun0} --write-out '%{http_code}' "$@" > "$state/auth-http-code" 2>/dev/null &
    active=$!; fetched=0; wait "$active" || fetched=$?; active=
    return "$fetched"
}
vpn_interface=
case ${1:-vpn} in vpn) ;; pf) vpn_interface=tun0 ;; *) exit 1 ;; esac
fetch --form "username=<$state/username" --form "password=<$state/password" \
    --output "$state/token-response" https://www.privateinternetaccess.com/api/client/v2/token || {
    if [ "$(cat "$state/auth-http-code")" = 429 ]; then
        echo 'pia-transmission: PIA authentication rate limited; delaying retries' >&2
        exit 75
    fi
    fail 'PIA authentication failed'
}
if [ "${1:-vpn}" = vpn ]; then
jq -er '.token | select(type == "string") | select(length > 62 and length <= 4096)
    | select(test("^[A-Za-z0-9_.=+-]+$")) | .[0:62] + "\n" + .[62:]' \
    "$state/token-response" > "$state/auth" 2>/dev/null || fail 'invalid PIA authentication response'
chmod 0600 "$state/auth"
fi
jq -erj '.token | select(type == "string") | select(length > 62 and length <= 4096)
    | select(test("^[A-Za-z0-9_.=+-]+$"))' "$state/token-response" > "$state/pf-token.tmp" 2>/dev/null || fail 'invalid PIA authentication response'
mv "$state/pf-token.tmp" "$state/pf-token"
