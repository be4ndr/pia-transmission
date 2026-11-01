#!/usr/bin/env python3
"""Run browser regressions against disposable containers of the existing 4.1.3 image."""
import argparse
import base64
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
AUTH = base64.b64encode(b"fixture:fixture-password").decode()


def bencode(value):
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, list):
        return b"l" + b"".join(map(bencode, value)) + b"e"
    return b"d" + b"".join(bencode(k) + bencode(value[k]) for k in sorted(value)) + b"e"


def rpc(url, method, arguments=None):
    headers = {"Authorization": "Basic " + AUTH, "Content-Type": "application/json"}
    payload = json.dumps({"method": method, "arguments": arguments or {}}).encode()
    for _ in range(2):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, payload, headers), timeout=5) as response:
                result = json.load(response)
            if result["result"] != "success":
                raise RuntimeError(result)
            return result["arguments"]
        except urllib.error.HTTPError as error:
            if error.code != 409:
                raise
            headers["X-Transmission-Session-Id"] = error.headers["X-Transmission-Session-Id"]
    raise RuntimeError("RPC session negotiation failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, help="override packaged assets for isolated patch comparisons")
    parser.add_argument("--ui", default="transmission-web", choices=["transmission-web", "transmission-web-legacy", "transmission-default"])
    parser.add_argument("--suite", default="compatibility", choices=["compatibility", "integration"])
    parser.add_argument("--image", default="pia-transmission:dev")
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--docker", default=os.environ.get("WEBUI_TEST_DOCKER", "docker"),
                        help="Docker executable; also accepts an absolute path to docker.exe")
    args = parser.parse_args()
    assets = args.assets.resolve() if args.assets else None
    if assets and not (assets / "index.html").is_file():
        parser.error("--assets must be a built UI directory")
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    prefix = "pia-webui-fix-" + uuid.uuid4().hex[:10]
    containers = []
    network_created = False

    def docker(*argv, data=None):
        result = subprocess.run([args.docker, *argv], input=data, capture_output=True,
                                check=True, timeout=90)
        output = result.stdout + (result.stderr if argv[0] == "logs" else b"")
        return output.decode().strip()

    def copy(source, destination):
        # Tar on stdin works with both Linux Docker and Docker Desktop's Windows CLI.
        with io.BytesIO() as stream:
            with tarfile.open(fileobj=stream, mode="w") as archive:
                archive.add(source, arcname=source.name)
            docker("cp", "-", destination, data=stream.getvalue())

    try:
        docker("image", "inspect", args.image)
        docker("network", "create", prefix)
        network_created = True
        info = json.loads(docker("network", "inspect", prefix))[0]
        cidr = str(ipaddress.ip_network(info["IPAM"]["Config"][0]["Subnet"]))
        with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
            work = Path(temporary)
            fixtures = work / "fixture"
            fixtures.mkdir()
            data_dir = fixtures / "data"
            data_dir.mkdir()
            settings = {
                "rpc-enabled": True, "rpc-bind-address": "0.0.0.0", "rpc-port": 9091,
                "rpc-whitelist-enabled": False, "rpc-host-whitelist-enabled": False,
                "rpc-authentication-required": True, "rpc-username": "fixture",
                "rpc-password": "fixture-password", "download-dir": "/data/downloads",
                "incomplete-dir-enabled": False, "dht-enabled": False, "pex-enabled": False,
                "lpd-enabled": False, "port-forwarding-enabled": False,
                "peer-port-random-on-start": False, "peer-port": 51413,
                "utp-enabled": False, "default-trackers": "", "start-added-torrents": False,
                "seedRatioLimited": False,
            }
            firewall = (
                "set -eu; nft delete table inet webui_test 2>/dev/null || :; nft add table inet webui_test; "
                "nft 'add chain inet webui_test output { type filter hook output priority 0; policy drop; }'; "
                "nft add rule inet webui_test output ip daddr 127.0.0.11 drop; "
                "nft add rule inet webui_test output oifname lo accept; "
                f"nft add rule inet webui_test output ip daddr {cidr} accept; "
                "nft add rule inet webui_test output ct state established,related accept; "
                "mkdir -p /data/downloads; "
                "if [ ! -f /data/.fixture-initialized ]; then cp -r /fixture/data/. /data/downloads/; touch /data/.fixture-initialized; fi; "
                "chown -R 1234:2345 /config /data; "
            )
            seed = prefix + "-seed"
            ui = prefix + "-ui"
            http = prefix + "-tracker"
            for name in [seed, ui]:
                command = firewall
                web_home = "/test-ui" if name == ui and assets else "/usr/share/transmission/public_html"
                if name == ui and not assets:
                    command += f"TRANSMISSION_WEB_UI={args.ui}; . /usr/local/lib/pia-transmission/select-web-ui.sh; "
                    web_home = "$TRANSMISSION_WEB_HOME"
                # Docker Desktop may inject proxy variables. Match the production
                # environment boundary so local tracker traffic cannot use a proxy.
                command += ("exec env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/config "
                            f"TRANSMISSION_WEB_HOME={web_home} "
                            "/usr/local/bin/drop-privileges 1234 2345 /usr/local/lib/pia-transmission/start-transmission.sh")
                # Docker reallocates automatically published ports on restart.
                # Choose an explicit loopback port so browser URLs stay stable.
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    host_port = listener.getsockname()[1]
                docker("create", "--name", name, "--network", prefix, "--ip",
                       str(ipaddress.ip_address(info["IPAM"]["Config"][0]["Gateway"]) + (1 if name == seed else 2)),
                       "--cap-add", "NET_ADMIN",
                       "-p", f"127.0.0.1:{host_port}:9091", "-e", "TRANSMISSION_WEB_HOME=/test-ui" if name == ui
                       else "TRANSMISSION_WEB_HOME=/usr/share/transmission/public_html",
                       "--entrypoint", "/bin/sh", args.image, "-c", command)
                containers.append(name)
            seed_ip = str(ipaddress.ip_address(info["IPAM"]["Config"][0]["Gateway"]) + 1)
            http_ip = str(ipaddress.ip_address(info["IPAM"]["Config"][0]["Gateway"]) + 3)
            docker("create", "--name", http, "--network", prefix, "--ip", http_ip,
                   "--entrypoint", "/bin/busybox", "busybox:1.36.1",
                   "httpd", "-f", "-p", "8080", "-h", "/fixture/www")
            containers.append(http)
            announce = f"http://{http_ip}:8080/cgi-bin/announce"
            extra = f"http://{http_ip}:8080/cgi-bin/extra"
            payload = b"disposable transmission compatibility fixture\n" * 1024
            records = {}
            for private in [False, True]:
                label = "private" if private else "public"
                name = label + "-fixture.bin"
                (data_dir / name).write_bytes(payload)
                metainfo = {
                    "announce": announce,
                    "info": {
                        "name": name, "length": len(payload), "piece length": 16384,
                        "pieces": b"".join(hashlib.sha1(payload[n:n + 16384]).digest()
                                           for n in range(0, len(payload), 16384)),
                    },
                }
                if private:
                    metainfo["info"]["private"] = 1
                torrent = fixtures / (label + ".torrent")
                torrent.write_bytes(bencode(metainfo))
                infohash = hashlib.sha1(bencode(metainfo["info"])).hexdigest()
                records[label] = {"name": name, "path": str(torrent), "hash": infohash,
                                  "magnet": "magnet:?xt=urn:btih:" + infohash + "&dn=" + name +
                                  "&tr=" + urllib.parse.quote(announce, safe="")}
            (fixtures / "invalid.torrent").write_text("not torrent metadata\n")
            (fixtures / "tracker-response").write_bytes(bencode({
                "interval": 5, "min interval": 1, "complete": 1, "incomplete": 0,
                "peers": socket.inet_aton(seed_ip) + struct.pack("!H", 51413),
            }))
            cgi = fixtures / "www/cgi-bin"
            cgi.mkdir(parents=True)
            for name in ["announce", "extra", "scrape"]:
                script = cgi / name
                script.write_text("""#!/bin/sh
printf 'Content-Type: application/x-bittorrent\\r\\n\\r\\n'
cat /fixture/tracker-response
""")
                script.chmod(0o755)
            config_dir = work / "config"
            config_dir.mkdir()
            (config_dir / "settings.json").write_text(json.dumps(settings))
            asset_copy = work / "test-ui"
            if assets:
                shutil.copytree(assets, asset_copy)
            copy(fixtures, http + ":/")
            docker("start", http)
            for name in [seed, ui]:
                copy(config_dir / "settings.json", name + ":/config/")
                copy(fixtures, name + ":/")
                if name == ui and assets:
                    copy(asset_copy, name + ":/")
                docker("start", name)
            urls = {}
            for name in [seed, ui]:
                container_info = json.loads(docker("inspect", name))[0]
                port = container_info["NetworkSettings"]["Ports"]["9091/tcp"][0]["HostPort"]
                url = f"http://127.0.0.1:{port}/transmission/rpc"
                for _ in range(50):
                    try:
                        session = rpc(url, "session-get")
                        break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError("test daemon unavailable: " + docker("logs", name))
                if session["version"] != "4.1.3 (838877323f)":
                    raise RuntimeError("unexpected Transmission version: " + session["version"])
                urls[name] = url
            actual_seed_ip = json.loads(docker("inspect", seed))[0]["NetworkSettings"]["Networks"][prefix]["IPAddress"]
            if actual_seed_ip != seed_ip:
                raise RuntimeError("tracker fixture address did not match allocated seeder address")
            if docker("exec", ui, "curl", "--noproxy", "*", "--max-time", "5", "--fail",
                      "--silent", "--output", "/tmp/tracker-probe", "--write-out", "%{http_code}", announce) != "200":
                raise RuntimeError("local tracker fixture unavailable")
            for record in records.values():
                rpc(urls[seed], "torrent-add", {
                    "metainfo": base64.b64encode(Path(record["path"]).read_bytes()).decode(), "paused": False,
                })
            fixture_config = {
                "base": urls[ui].removesuffix("rpc") + "web/", "rpc": urls[ui],
                "records": records, "invalid": str(fixtures / "invalid.torrent"),
                "announce": announce, "extra": extra, "docker": args.docker,
                "container": ui, "digest": hashlib.sha256(payload).hexdigest(),
                "ui": args.ui,
            }
            config_path = work / "test-config.json"
            config_path.write_text(json.dumps(fixture_config))
            env = dict(os.environ, WEBUI_TEST_CONFIG=str(config_path), WEBUI_TEST_EVIDENCE=str(evidence))
            result = subprocess.run(["node", "--test", str(ROOT / f"tests/{args.suite}.cjs")], env=env)
            (evidence / "daemon.log").write_text(docker("logs", ui))
            (evidence / "seed.log").write_text(docker("logs", seed))
            return result.returncode
    finally:
        for container in reversed(containers):
            subprocess.run([args.docker, "rm", "-f", container], check=True, capture_output=True, timeout=90)
        if network_created:
            subprocess.run([args.docker, "network", "rm", prefix], check=True, capture_output=True, timeout=90)
        (evidence / "cleanup.json").write_text(json.dumps({"containers": containers,
                                                        "network": prefix, "removed": True}, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
