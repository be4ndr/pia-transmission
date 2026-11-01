# transmission-web compatibility patch

This directory contains an isolated patch and build/test tooling for
`jianxcao/transmission-web` v0.1.6 with Transmission 4.1.3. The main Dockerfile
applies this patch in a build-only Node stage and packages its static output. The
name is `transmission-web` (default); the legacy and official fallback
clients are not modified.

Upstream commit: `b8e3ff39c9ebeef07bf196ce4bb3ff9236f632f1`.
The source archive SHA-256 is enforced by `build.py`:
`4fab7668c98a2606c301a48b8d67fea8b14a39f62b813f4850be521affcb8bf1`.

The patch changes five upstream frontend files:

- `store/setting.ts`: initialize fresh browser defaults with an empty tracker
  list. Existing stored choices and explicit opt-in remain available.

- `AddDialog.vue`: automatic tracker additions require complete metadata and
  `isPrivate === false`. Unresolved magnets and failed privacy lookups receive
  no extra trackers. Explicit manual tracker edits remain available.
- `SettingsContent.vue`: after a successful save, the existing Default Tracker
  List control also updates the browser-local defaults. Clearing it disables
  automatic injection and persists across refresh. A rejected save leaves the
  tracker preference unchanged.
- `rpc.ts`: require both HTTP 200 and RPC `result: "success"`. Existing add/move
  error handlers now run for daemon rejections; successful duplicate additions
  remain valid responses. The daemon and RPC protocol are unchanged.
- `router/index.ts`: use hash routing with Vite's normalized base URL. Direct
  links are `/transmission/web/#/settings` and `/transmission/web/#/login`.
  These request the existing root document on refresh, without server rewrites
  or a service worker.

## Build and test

Requirements: Python 3.12+, Git, Node.js meeting the upstream requirements,
and a Linux Docker engine with the existing `pia-transmission:dev`
image. Build/test dependency versions are pinned
in this directory's package lock; upstream dependencies use its frozen pnpm lock.
The browser additionally requires Playwright's documented system libraries.

Build the image first with `docker build -t pia-transmission:dev .` from the
repository root. From this directory:

```sh
npm ci --ignore-scripts
./node_modules/.bin/playwright install chromium
python3 build.py /tmp/transmission-web-patched
python3 tests/run.py \
  --assets /tmp/transmission-web-patched/source/jianxcao-transmission-web-b8e3ff3/dist \
  --evidence /tmp/transmission-web-patched-evidence
```

Use new working/evidence directory names on each run; the tools refuse to
overwrite existing directories. `build.py` downloads and verifies the source,
checks/applies `compatibility.patch`, installs frozen dependencies, and runs the
upstream type check and production build. It writes `provenance.json` with source,
patch, lockfile, tool versions, and asset hashes. Keep the upstream `LICENSE`
from the extracted checkout when distributing any built assets.

For a before/after comparison, build another new directory with `--baseline`;
the same regressions intentionally fail against unmodified upstream. A cached
source archive can be supplied with `--source-archive`; checksum enforcement
still applies. Dependency updates and floating source checkouts are not used.
Generated asset bytes can differ between fresh builds due to upstream compiler
ordering; the patch and build inputs are pinned, and each artifact's hashes are
recorded. This is not a claim of a bit-for-bit deterministic upstream build.

`tests/run.py` creates an application daemon, local seeder, and local CGI tracker
fixture. Application/seeder containers use the existing image and privilege
launcher, disposable config/data, a clean environment, and an outbound firewall.
UI ports bind only to loopback. The tracker uses `busybox:1.36.1`; no extra UI
runtime service is introduced. Every test resource is removed in `finally`;
logs, RPC captures and screenshots remain in the requested evidence directory.
The runner checks the actual daemon version and local tracker availability.

For packaged integration checks, omit `--assets`, select the built image and
use `--suite integration --ui transmission-web` (or another packaged UI).
The runner then uses the installed selector, privilege launcher and startup
settings merge. The separate repository container suite exercises the complete
production entrypoint with a local OpenVPN/TLS fixture:

```sh

# Run this block from the repository root.
docker build -t pia-transmission:dev .
python3 webui/transmission-web/tests/run.py --image pia-transmission:dev \
  --suite integration --ui transmission-web --evidence /tmp/webui-integration
# Container regressions:
PIA_TEST_DOCKER_CONTEXT=default PIA_RUN_CONTAINER_TESTS=1 \
  PIA_TEST_IMAGE=pia-transmission:dev \
  python3 -m unittest discover -s tests -v
```

Use `--docker /absolute/path/to/docker` or `WEBUI_TEST_DOCKER` if necessary.
Docker Desktop's Windows `docker.exe` also works: asset transfers use tar on
stdin instead of interpreting WSL filesystem paths as Windows paths.

## Limits

Existing extensionless history URLs `/transmission/web/settings` and `/login`
still require a server rewrite. Update bookmarks to the hash URLs; no Transmission
server patch or proxy is included. Existing browser/PWA caches must load the new
assets using the existing update prompt or cache reset.

Automatic browser defaults are intentionally skipped for unresolved magnets;
they are not queued for application after metadata arrives. Known public file
torrents still receive configured browser defaults. Already injected trackers,
tracker URLs supplied by a torrent/magnet, and explicit manual edits are not
removed or rewritten by this patch. Transmission does not exchange private
torrent metadata with peers; the real private-magnet test verifies protection
while unresolved, and private file tests verify protection after metadata is known.

The patch does not add source-URL display.

The local compatibility patch is covered by the repository's MIT License.
The upstream frontend retains its own license; the container image includes its
upstream `LICENSE` and generated dependency notices beside the installed assets.
The notice collector records each installed package version and declared license,
and copies available license/notice texts without relabeling those packages.
