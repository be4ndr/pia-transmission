#!/bin/sh
set -eu
umask 077
cd /config
temporary=$(mktemp /config/.settings.XXXXXX)
trap 'rm -f "$temporary"' EXIT
trap 'exit 0' TERM INT
if [ -e settings.json ]; then
    settings=settings.json
else
    printf '{}\n' > "$temporary"
    settings=$temporary
fi
# Read before writing so a new config can use the same temporary path.
settings_json=$(cat "$settings")
printf '%s\n' "$settings_json" | jq '
    if type != "object" then error("settings must be a JSON object") else . end
    # Transmission replaces the inherited shell umask with this persisted value.
    # JSON uses decimal: 63 is octal 077, keeping subsequent daemon saves private.
    | .["umask"] = 63
    | .["rpc-enabled"] = true
    | .["rpc-port"] = 9091
    | .["rpc-bind-address"] = "0.0.0.0"
    | .["rpc-whitelist-enabled"] = false
    | if (env.TRANSMISSION_DOWNLOAD_DIR // "") != "" then
        .["download-dir"] = env.TRANSMISSION_DOWNLOAD_DIR
      elif has("download-dir") then . else .["download-dir"] = "/data/complete" end
    | if (env.TRANSMISSION_INCOMPLETE_DIR // "") != "" then
        .["incomplete-dir"] = env.TRANSMISSION_INCOMPLETE_DIR
      elif has("incomplete-dir") then . else .["incomplete-dir"] = "/data/incomplete" end
    | if (env.TRANSMISSION_INCOMPLETE_DIR_ENABLED // "") != "" then
        .["incomplete-dir-enabled"] = (env.TRANSMISSION_INCOMPLETE_DIR_ENABLED
            | if . == "true" then true elif . == "false" then false
              else error("TRANSMISSION_INCOMPLETE_DIR_ENABLED must be true or false") end)
      elif has("incomplete-dir-enabled") then . else .["incomplete-dir-enabled"] = true end
' > "$temporary"
mv -f "$temporary" settings.json
trap - EXIT TERM INT
unset TRANSMISSION_DOWNLOAD_DIR TRANSMISSION_INCOMPLETE_DIR TRANSMISSION_INCOMPLETE_DIR_ENABLED
exec /usr/bin/transmission-daemon --foreground --config-dir /config
