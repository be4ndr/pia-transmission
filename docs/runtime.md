# Runtime behavior

## Startup and recovery

The root `/bin/sh` controller installs nftables protection and dedicated UID
routing before contacting PIA or starting Transmission. It fetches the public
server inventory over verified HTTPS, selects a `PIA_REGION` server, and obtains
an authentication token using the existing username/password file mounts. Failed
API requests, TLS verification, routing, or firewall setup leave Transmission
unstarted. API/connection failures retry after `VPN_RETRY_DELAY` (default 5 seconds),
rotating through the selected region's servers. Each connection attempt has a
`VPN_START_TIMEOUT` readiness deadline (default 90 seconds); individual HTTPS
requests have a 30-second limit. Authentication HTTP 429 responses use a
five-minute backoff instead of the normal retry delay.

OpenVPN checks the vendored PIA CA, server certificate role, exact server CN from
PIA's HTTPS inventory, and TLS 1.2 or newer. It uses UDP/8080 with AES-256-GCM or
AES-256-CBC/SHA256, following PIA's current manual token connection flow. The
pinned CA source/license and fingerprint are recorded in [runtime/pia](../runtime/pia/README.md).
Server-pushed routes are not executed automatically. A trusted route-up hook
installs application routes, DNS, and tunnel permissions before setting readiness.

Transmission starts only after the first successful VPN setup. Once started,
it remains running during VPN downtime, preserving IPv4 LAN RPC on TCP 9091.
A fresh container that has never connected does not expose Transmission RPC yet.
Disconnect hooks revoke tunnel permissions without changing LAN rules. The
controller also handles OpenVPN crashes without relying on a down hook, restores
bootstrap DNS, and reacquires a token before restarting OpenVPN. An unexpected
Transmission exit stops the container with a failure status for Compose recovery.
SIGTERM/SIGINT terminate and reap the managed processes. Compose uses `init: true`
and a 30-second stop grace period.

## Direct LAN WebUI and API

Compose publishes host TCP **8088** directly to Transmission's IPv4 RPC listener
on container TCP 9091. No proxy or extra service is required. Set `WEB_BIND_IP`
to the Docker host's LAN IPv4 address where Compose should listen, and set
`LOCAL_NETWORK` to the permitted client CIDRs, then recreate the container.
`WEB_BIND_IP` controls the host interface binding; it does not filter client
source addresses. `LOCAL_NETWORK` remains the source-address filter inside the
container.

Transmission also checks the HTTP `Host` header against `RPC_HOST_WHITELIST`.
Set it to a comma-separated list of IP addresses and DNS hostnames that clients
will use. For example:
`RPC_HOST_WHITELIST=192.0.2.10,transmission.example,transmission.lan.example`.
The example addresses and names are reserved for documentation; replace them
with your own values. If `RPC_HOST_WHITELIST` is unset, it defaults to
`WEB_BIND_IP`. Keep the host binding and Host whitelist aligned with the URL
used by clients. A Host whitelist match does not bypass `LOCAL_NETWORK` or
persisted RPC authentication.

Open `http://<WEB_BIND_IP>:8088/transmission/web/`; API clients use
`http://<WEB_BIND_IP>:8088/transmission/rpc` and Transmission's session-ID handshake.
Persisted RPC authentication and optional RPC credential files still apply.
`WEB_HOST_PORT` sets the published host port (default 8088). Verify source
visibility on the intended Docker host/LAN; do not broaden the allowlist to
compensate for unexpected NAT. IPv6 RPC remains unsupported. Port 8088 serves
HTTP, so use it only on your trusted LAN.

LAN access survives VPN downtime after the first successful VPN startup.
Application egress still requires the VPN, and new LAN connections from the
application stay blocked. Validate published-port source visibility and access policy on your Docker host.

## WebUI selection

Set `TRANSMISSION_WEB_UI` in `.env` before recreating the container:

| Value | Packaged interface |
| --- | --- |
| `transmission-web` (default) | jianxcao v0.1.6 with the local compatibility patch |
| `transmission-web-legacy` | Archived/unmaintained ronggang Web Control, pinned commit |
| `transmission-default` | Official assets from Transmission 4.1.3 |

All three use the existing `/transmission/web/` endpoint and RPC on port 9091.
The controller resolves the selection to a fixed, root-owned directory and
forwards only that `TRANSMISSION_WEB_HOME` through the privilege launcher.
An arbitrary supplied `TRANSMISSION_WEB_HOME` is ignored. Empty or unknown
selector values fail startup before modifying `/config` or `/data`.
Changing the selector requires container recreation, for example
`docker compose up -d --force-recreate`; restarting an existing container retains
its existing environment. Settings and torrent data stay in the same mounts.

The modern UI starts with an empty Default Tracker List. To opt in, save tracker
URLs under Settings → Other → Default Tracker List. Existing saved browser
preferences and daemon settings are retained. Automatic browser additions require
complete metadata proving a torrent is public; unresolved magnets and private
torrents receive no automatic extras. Clearing and saving the list disables them.
Explicit tracker edits and trackers supplied by torrents/magnets remain available.
Review old browser preferences when upgrading from unpatched upstream: its saved
defaults cannot be distinguished from an intentional user list.

Modern settings/login bookmarks use `/transmission/web/#/settings` and
`/transmission/web/#/login`. Clear old PWA/browser caches when switching interfaces
if stale assets appear. The archived UI's Original UI link is unavailable; select
`transmission-default` through the environment instead. The modern UI does not display a torrent
source URL after submission.

## Automatic PIA port forwarding

`PIA_PORT_FORWARDING=true` (default) starts a separate root worker after VPN
readiness. Choose a region whose PIA inventory advertises `port_forward: true`.
Provider support can vary between regions and gateways. Unsupported regions
keep VPN and Transmission working and report PF as unavailable. Set the flag to `false` to
skip the worker. The runtime never changes your selected region automatically.

The worker uses the OpenVPN gateway and advertised server CN to verify PIA's
CA/hostname on HTTPS port 19999. All PF requests are bound to `tun0`. A shared
file-backed authentication helper retains the token in root-only ephemeral
state. Transport/TLS errors retry without creating new tokens. Token rejection
can refresh PF authentication through the tunnel without replacing the active
OpenVPN authentication file. Authentication or PF API HTTP 429 responses back
off for five minutes.

A validated signed lease is bound every 900 seconds. Valid leases are reused and
rebound on reconnect/server change; renewal happens early near expiry, and
expired, malformed or rejected leases are replaced. Provider/RPC/firewall
failures revoke incoming PF permissions and retry independently of VPN and
Transmission. RPC initialization retries after five seconds; other PF failures
normally retry after 60 seconds. TCP 9091 and privileged ports are rejected as
peer-port allocations so PF cannot expose the RPC listener.

After a successful provider bind, authenticated/session-aware loopback RPC sets
and verifies `peer-port`, disables random peer ports and Transmission's own
UPnP/NAT-PMP mapping, then opens only that TCP/UDP port through the VPN ingress
gate. Disconnect closes this gate independently of in-flight PF requests.
Neither eth0 ingress nor application eth0 egress is opened. Transmission keeps
running; its last peer-port setting persists even when PF is unavailable.

If persisted Transmission settings require RPC authentication, mount separate
root-only secrets named `transmission_rpc_username` and
`transmission_rpc_password` under `/run/secrets`, containing the matching
plaintext RPC credentials. The hashed password in `settings.json` cannot be used
by an RPC client. For example, an optional Compose override can add:

```yaml
services:
  pia-transmission:
    secrets:
      - transmission_rpc_username
      - transmission_rpc_password
secrets:
  transmission_rpc_username:
    file: "${PIA_SECRETS_DIR}/rpc-username"
  transmission_rpc_password:
    file: "${PIA_SECRETS_DIR}/rpc-password"
```

Keep these files `0600` in the root-only secret directory. Missing/wrong RPC
credentials leave PF closed and log a generic retry; they never restart the
application. PF tokens, payloads, signatures, and RPC headers stay in root-only
files and never enter external-command arguments/environment or container logs.
Root diagnostics are `/run/pia-transmission/pf-status` and `pf-active`; check VPN
readiness as well.

## Network and process boundaries

- Transmission's nonzero `PUID`/`PGID` have no supplementary groups, empty effective,
  permitted, inheritable, bounding, and ambient capability sets, and `NoNewPrivs`.
  The static launcher also disables core dumps and closes inherited descriptors
  above stderr. The controller retains the capabilities needed for VPN control.
- Application UID traffic uses routing table 100. LAN RPC replies retain an eth0
  route; other application traffic requires `tun0`, with an unreachable default
  as the fallback. IPv6 application routing is unreachable; IPv6 VPN/RPC support
  is not implemented. Do not share this namespace or run unrelated processes as
  the configured application UID.
- nftables permits application IPv4 egress only through an authenticated tunnel,
  and established RPC replies to comma-separated `LOCAL_NETWORK` CIDRs. New LAN
  egress remains blocked even through the tunnel. DNS is limited to the pushed
  IPv4 VPN resolver (fallback `10.0.0.242`) over `tun0`.
- Bootstrap exceptions are controller-only: IPv4 DNS to the original container
  resolvers (including IPv4 upstreams in Docker's `ExtServers` resolver metadata),
  encrypted OpenVPN UDP/8080 to the selected endpoint, and TCP/443 through eth0
  only to the current IPv4 snapshot for `serverlist.piaservers.net` (discovery)
  or `www.privateinternetaccess.com` (initial token authentication). The controller
  revokes the previous HTTPS set before each bounded DNS lookup, atomically
  installs the validated addresses, and pins curl to that same snapshot with
  `--resolve`. Normal TLS hostname/SNI and certificate verification remain in
  force; curlrc/proxies/redirects remain disabled. The HTTPS set is cleared after
  each request and on orderly cancellation; entries also expire after 45 seconds.
  Failed DNS/firewall updates never start HTTPS. Every bootstrap retry resolves
  afresh, allowing IP rotation without permitting arbitrary destinations.
  Configured LAN destinations remain denied for new HTTPS connections. These
  exceptions are unavailable to Transmission; PF HTTPS stays bound to tun0.
  Replies are tracked with a controller connection mark. The IP allowlist can
  also reach other hostnames served by shared PIA/CDN addresses, and the
  bootstrap resolver remains trusted to supply addresses. Root retains
  NET_ADMIN and is outside the unprivileged application's security boundary.
- DNS is filtered before Docker OUTPUT DNAT. Unprivileged access to Docker's
  `127.0.0.11` resolver, including its internal high-port listener, is blocked.
  Protection stays installed during shutdown and retries; nothing flushes the
  host ruleset or temporarily opens eth0 application egress.

## Credentials and persistent data

Keep host secrets outside the repository in a `0700` directory with `0600` files.
Compose mounts them read-only as `/run/secrets/pia_username` and
`/run/secrets/pia_password`. The controller restricts the parent to root-only
traversal. Each file must contain one nonempty credential line, optionally ending
in a newline. No credential values enter external-command argv or environment.

curl reads temporary root-only files to send token-request form fields. The token
is split into OpenVPN's two-line authentication file, following PIA's manual
connection protocol. All such state lives below root-owned `/run/pia-transmission`
(mode `0700`); files are `0600`, credential request files/responses are
removed promptly, and the authentication file is removed between attempts/on
shutdown. Nothing is persisted in `/config`. Controller output contains generic
status/error messages; raw OpenVPN logs are suppressed to avoid authentication
material or provider-controlled text reaching container logs.

`/config/settings.json` still persists application settings. Explicit
`TRANSMISSION_DOWNLOAD_DIR`, `TRANSMISSION_INCOMPLETE_DIR`, and
`TRANSMISSION_INCOMPLETE_DIR_ENABLED` values override existing settings; unrelated
values survive. Defaults remain `/data/complete`, `/data/incomplete`, and `true`.
RPC stays on IPv4 port 9091 with nftables enforcing source CIDRs; persisted RPC
authentication survives. Other `TRANSMISSION_*` overrides are not supported.

Before VPN preparation, the controller restricts `/config` to `0700` and assigns
it and an existing regular `settings.json` to `PUID:PGID`. Symlink configuration
directories/settings are rejected. The application atomically replaces settings
with a private file and forces Transmission's own `umask` to `077` (decimal `63`
at startup; saved by 4.1.3 as `"077"`). Daemon saves at startup/shutdown therefore
retain `0600`, including after RPC changes, restart and recreation. Only the
directory mode is enforced once per controller startup; no recurring file-mode
repair is needed.

The controller also manages ownership of `/data/complete` and `/data/incomplete`.
It never recursively changes ownership or permissions in either mount. Other
existing files, including torrent/resume state, must be accessible to PUID/PGID;
changing application IDs may require an operator to migrate those files.
New downloads and directories are private (`0600`/`0700`); media consumers using
another UID need an explicit sharing arrangement. Existing data permissions
remain unchanged. Set `DATA_DIR` to the intended host data directory; Compose mounts it at `/data`.
