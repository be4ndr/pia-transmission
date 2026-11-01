#!/bin/sh
# Source this before startup; only packaged, root-owned assets may be selected.
case "${TRANSMISSION_WEB_UI-transmission-web}" in
    transmission-web) TRANSMISSION_WEB_HOME=/usr/share/transmission/web-ui/transmission-web ;;
    transmission-web-legacy) TRANSMISSION_WEB_HOME=/usr/share/transmission/web-ui/transmission-web-legacy ;;
    transmission-default) TRANSMISSION_WEB_HOME=/usr/share/transmission/public_html ;;
    *) echo 'pia-transmission: TRANSMISSION_WEB_UI must be transmission-web, transmission-web-legacy or transmission-default' >&2; exit 1 ;;
esac
[ -r "$TRANSMISSION_WEB_HOME/index.html" ] || {
    echo 'pia-transmission: selected WebUI assets are missing' >&2
    exit 1
}
