# pia-transmission

A single Docker container running Transmission 4.1.3 behind a PIA OpenVPN tunnel,
with automatic PIA port forwarding and three packaged WebUIs. A root controller
manages VPN/firewall state; Transmission runs without root or capabilities.
Application traffic fails closed during VPN outages while allowed LAN RPC replies
remain available after the first successful connection.

## Configure and build

Requirements: a Linux Docker engine with Compose, `/dev/net/tun`, and a PIA account.
Copy `.env.example` to `.env` and `compose.yaml.example` to
`compose.yaml`. Replace documentation addresses with your Docker host IPv4
address and permitted LAN CIDRs. `WEB_BIND_IP` selects the host interface where
Compose publishes the WebUI/RPC port. `RPC_HOST_WHITELIST` controls which HTTP
Host header values Transmission accepts, defaulting to `WEB_BIND_IP` when unset.
For access by IP and multiple DNS names, set
`RPC_HOST_WHITELIST=192.0.2.10,transmission.example,transmission.lan.example`
and use one of those values in the client URL. Set `CONFIG_DIR`, `DATA_DIR`, `PUID`,
`PGID` and a current PIA region ID. Keep PIA username/password files outside the
repository in the configured `PIA_SECRETS_DIR` (directory 0700, files 0600).

```sh
cp .env.example .env
# Edit .env and create the external credential files before starting.
docker compose config -q
docker compose build
# Start only when you intend to run the VPN/application:
docker compose up -d
```

The UI is `http://<WEB_BIND_IP>:8088/transmission/web/`; RPC uses
`/transmission/rpc`. Host binding selects the host interface that receives
connections; it does not filter client source addresses. `LOCAL_NETWORK` remains
the source-address filter. The RPC Host whitelist separately checks the HTTP
Host header and must include the IP or DNS name used in the URL.
Fresh RPC settings do not require authentication. Enable RPC authentication for
your deployment; see [runtime configuration](docs/runtime.md) for persisted
settings, optional PF RPC credentials, WebUI selection, process/secret boundaries,
recovery and data permissions. HTTP access is intended for a trusted LAN.

## Running tests

Host tests need Python 3, a C compiler, jq and `/bin/sh`:

```sh
python3 -m unittest discover -s tests -v
# Disposable local Docker integration tests also need host openssl and TUN:
mkdir -p .local/test-results
python3 tests/run_local.py --evidence-dir .local/test-results/example
```

Choose a new results directory for each run; the runner refuses to overwrite it.
The container runner builds the image, uses real local OpenVPN/TLS, Transmission,
routing and nftables, and supplies synthetic provider APIs and credentials. It
removes its disposable resources. Browser build/regression instructions are in
[webui/transmission-web](webui/transmission-web/README.md).

Install and run the pinned secret scanner as documented in
[security checks](docs/security.md). CI runs secret scans and host regressions.
See [limitations and troubleshooting](docs/troubleshooting.md) before deployment.

Keep private notes and generated test results under `.local/`. It is excluded from Git,
secret-scan publication inputs and Docker build contexts. Never publish workspace
archives that include ignored files or `.git` internals.

## License

Original pia-transmission code and documentation are licensed under the MIT
License; see [LICENSE](LICENSE). Third-party components retain their own terms.
The image includes Transmission's GPL license, both packaged WebUI licenses,
frontend dependency notices, and an inventory of Alpine package license identifiers
under `/usr/share/licenses/`. The public PIA CA retains its
upstream MIT notice in [runtime/pia/LICENSE](runtime/pia/LICENSE). Keep these
notices with redistributed copies or images. The MIT grant for this project does
not relicense third-party code or assets.
