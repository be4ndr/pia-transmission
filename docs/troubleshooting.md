# Limitations and troubleshooting

## Connection and startup

Replace `PIA_REGION` in `.env` with an exact region ID from the provider's public
server inventory at `https://serverlist.piaservers.net/vpninfo/servers/v6`.
The example value is a placeholder, not a region selection. For port forwarding,
choose a region advertising `port_forward: true`. Provider availability can change;
a region advertising support does not guarantee every gateway will respond.

If the daemon does not start, check container logs, credential file permissions,
`/dev/net/tun`, `NET_ADMIN` and outbound access to provider services. Transmission
starts only after the first successful VPN connection. Authentication rate limits
cause a five-minute backoff; avoid repeated container restarts to bypass it.

## LAN access

If the WebUI is unreachable, verify `WEB_BIND_IP` belongs to the Docker host,
the published port is free, and the source address visible to the container is
included in `LOCAL_NETWORK`. Docker NAT behavior can differ between hosts. Do not
broaden the allowlist to hide unexpected source translation. IPv6 RPC is unsupported.
RPC uses HTTP; use a trusted LAN and enable authentication in persisted settings.

## Port forwarding

Forwarding failures leave VPN and Transmission running while incoming forwarded
traffic stays blocked. Check the root-only runtime `pf-status` file inside the
container and confirm VPN readiness. Persisted RPC authentication requires matching
plaintext RPC credential mounts for the PF worker. These differ from the password
hash stored by Transmission; see [runtime configuration](runtime.md).

## Storage and interfaces

Use application-readable torrent state and download files when changing
`PUID`/`PGID`. The controller does not recursively migrate existing data ownership.
New files/directories are private by default; sharing with another UID requires
an explicit permission arrangement.

Changing the selected WebUI requires container recreation. Clear browser/PWA
caches if old assets appear. The optional legacy WebUI is archived and unmaintained;
prefer the modern or official interface.

## Security boundaries and support limits

The controller requires root and network administration capabilities. Host root,
other privileged containers sharing the namespace, and processes running as the
application UID are outside the application's isolation boundary. Do not share
its namespace or application UID with unrelated workloads.

There is no VPN-aware Docker healthcheck. A running container alone does not prove
VPN or forwarding readiness. IPv6 VPN/RPC support is not implemented. Provider
regions, network paths and outage duration affect recovery. Validate access policy
and recovery on your intended host before relying on the service.

Builds download upstream sources and packages. Source archives are checksum-verified,
but base packages are not a completely frozen snapshot. Keep third-party license
notices when distributing built assets; see the image notices and public PIA CA
[source information](../runtime/pia/README.md).
