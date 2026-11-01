"""Opt-in real Transmission/OpenVPN/TLS/netfilter checks on a Linux Docker engine.

Run: PIA_TEST_DOCKER_CONTEXT=default PIA_RUN_CONTAINER_TESTS=1 python3 -m unittest discover -s tests -v
Uses only disposable images, a private bridge, and named test containers.
"""
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("PIA_RUN_CONTAINER_TESTS") == "1",
                     "requires opt-in and a Linux Docker engine with NET_ADMIN")
class ContainerTests(unittest.TestCase):
    @staticmethod
    def docker(*args, check=True, timeout=60):
        context = os.environ.get("PIA_TEST_DOCKER_CONTEXT")
        if not context:
            raise RuntimeError("Set PIA_TEST_DOCKER_CONTEXT explicitly before container tests")
        return subprocess.run(["docker", "--context", context, *args], check=check, capture_output=True,
                              text=True, timeout=timeout)

    @classmethod
    def setUpClass(cls):
        # An opted-in run must fail if prerequisites are missing, rather than
        # report skipped kernel checks as success.
        cls.docker("info")
        cls.prefix = "pia-test-" + uuid.uuid4().hex[:10]
        cls.image = cls.prefix + ":test"
        cls.network = cls.prefix + "-net"
        cls.containers = []
        cls.volumes = []
        cls.temp = tempfile.TemporaryDirectory(prefix=cls.prefix)
        cls.addClassCleanup(cls.temp.cleanup)
        # LIFO: remove containers/restore ownership before deleting host files.
        cls.addClassCleanup(cls.cleanup)
        cls.secret = Path(cls.temp.name) / "secret"
        cls.secret.write_text("fixture-secret-do-not-log\n")
        # The parent's 0700 mode must isolate even a permissive secret mount.
        cls.secret.chmod(0o644)
        existing_image = os.environ.get("PIA_TEST_IMAGE")
        if existing_image:
            cls.docker("tag", existing_image, cls.image)
        else:
            cls.docker("build", "-t", cls.image, str(ROOT), timeout=600)
        cls.docker("network", "create", cls.network)
        info = json.loads(cls.docker("network", "inspect", cls.network).stdout)[0]
        cls.cidr = info["IPAM"]["Config"][0]["Subnet"]
        cls.real_curl = Path(cls.temp.name) / "real-curl"
        curl_source = cls.prefix + "-curl-source"
        cls.docker("create", "--name", curl_source, cls.image)
        try:
            cls.docker("cp", curl_source + ":/usr/bin/curl", str(cls.real_curl))
        finally:
            cls.docker("rm", curl_source)
        cls.real_curl.chmod(0o755)
        cls.setup_vpn_server()
        cls.peer = cls.prefix + "-peer"
        cls.containers.append(cls.peer)
        cls.docker("run", "-d", "--name", cls.peer, "--network", cls.network,
                   "--entrypoint", "/bin/sh", cls.image, "-c", r'''
cat > /tmp/http-response <<'SH'
#!/bin/sh
while IFS= read -r line; do
    [ "$line" = "$(printf '\r')" ] && break
done
printf 'HTTP/1.0 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\npeer-ok\n'
SH
chmod 0755 /tmp/http-response
exec nc -lk -p 8080 -e /tmp/http-response
''')
        cls.peer_ip = cls.address(cls.peer)
        # A failed fixture must never make a negative network check pass.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = cls.docker("exec", cls.peer, "wget", "-T", "1", "-qO-",
                                "http://127.0.0.1:8080", check=False)
            if result.returncode == 0 and "peer-ok" in result.stdout:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("HTTP fixture failed: " + cls.docker("logs", cls.peer).stderr)

    @classmethod
    def setup_vpn_server(cls):
        """Real OpenVPN TLS server. Only the PIA HTTPS APIs are mocked."""
        cls.vpn_files = Path(cls.temp.name) / "vpn"
        cls.vpn_files.mkdir()
        def openssl(*args):
            subprocess.run(["openssl", *args], check=True, capture_output=True)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=PIA-Test-CA", "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", str(cls.vpn_files / "ca.key"), "-out", str(cls.vpn_files / "ca.crt"))
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=fixture-pia",
                "-keyout", str(cls.vpn_files / "server.key"), "-out", str(cls.vpn_files / "server.csr"))
        extensions = cls.vpn_files / "extensions"
        extensions.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        openssl("x509", "-req", "-in", str(cls.vpn_files / "server.csr"), "-CA", str(cls.vpn_files / "ca.crt"),
                "-CAkey", str(cls.vpn_files / "ca.key"), "-CAcreateserial", "-days", "2",
                "-extfile", str(extensions), "-out", str(cls.vpn_files / "server.crt"))
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=Untrusted-Test-CA", "-keyout", str(cls.vpn_files / "wrong-ca.key"),
                "-out", str(cls.vpn_files / "wrong-ca.crt"))
        cls.token = "T" * 62 + "fixture-password"
        auth = cls.vpn_files / "verify-auth"
        auth.write_text('#!/bin/sh\ntest "$(head -n 1 "$1")" = "' + "T" * 62 +
                        '" && test "$(tail -n 1 "$1")" = "fixture-password"\n')
        auth.chmod(0o755)
        config = cls.vpn_files / "server.conf"
        config.write_text('''dev tun0
dev-type tun
disable-dco
proto udp4
port 8080
topology subnet
server 10.8.0.0 255.255.255.0
ca /fixture/ca.crt
cert /fixture/server.crt
key /fixture/server.key
dh none
data-ciphers AES-256-GCM:AES-256-CBC
auth SHA256
verify-client-cert none
username-as-common-name
duplicate-cn
script-security 2
auth-user-pass-verify /fixture/verify-auth via-file
keepalive 1 3
push "dhcp-option DNS 10.8.0.1"
push "redirect-gateway def1"
verb 0
''')
        cls.vpn_server = cls.prefix + "-vpn-server"
        cls.containers.append(cls.vpn_server)
        cls.docker("run", "-d", "--init", "--name", cls.vpn_server, "--network", cls.network,
                   "--cap-add", "NET_ADMIN", "--device", "/dev/net/tun",
                   "--mount", f"type=bind,src={cls.vpn_files},dst=/fixture,readonly",
                   "--entrypoint", "/bin/sh", cls.image, "-c", r'''
cat > /tmp/http-response <<'SH'
#!/bin/sh
while IFS= read -r line; do
    [ "$line" = "$(printf '\r')" ] && break
done
printf 'HTTP/1.0 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\npeer-ok\n'
SH
chmod 0755 /tmp/http-response
nc -lk -p 8080 -e /tmp/http-response &
exec openvpn --config /fixture/server.conf
''')
        cls.server_ip = cls.address(cls.vpn_server)
        cls.curl_mock = Path(cls.temp.name) / "curl-mock"
        cls.curl_mock.write_text('''#!/bin/sh
set -eu
out=
previous=
for argument in "$@"; do
    if [ "$previous" = --output ]; then out=$argument; fi
    previous=$argument
done
case "$previous" in
    */servers/v6)
        if [ -f /run/test-control/real-bootstrap ]; then exec /usr/local/bin/real-curl "$@"; fi
        cp /run/test-control/regions.json "$out" ;;
    */token)
        printf '%s\\n' "$@" > /run/test-control/curl-argv
        chmod 0644 /run/test-control/curl-argv
        [ ! -f /run/test-control/fail-auth ] || exit 22
        if [ -f /run/test-control/real-bootstrap ]; then exec /usr/local/bin/real-curl "$@"; fi
        cp /run/pia-transmission/username /run/test-control/seen-username
        cp /run/pia-transmission/password /run/test-control/seen-password
        chmod 0644 /run/test-control/seen-username /run/test-control/seen-password
        cp /run/test-control/token.json "$out"
        ;;
    */getSignature) cp /run/test-control/lease.json "$out" ;;
    */bindPort)
        if [ -f /run/test-control/fail-bind ]; then
            printf '{"status":"ERROR"}' > "$out"
        else
            printf '{"status":"OK"}' > "$out"
        fi
        ;;
    */transmission/rpc) exec /usr/local/bin/real-curl "$@" ;;
    *) exit 22 ;;
esac
''')
        cls.curl_mock.chmod(0o755)
        cls.getent_mock = Path(cls.temp.name) / 'getent-mock'
        cls.getent_mock.write_text('''#!/bin/sh
set -eu
[ ! -f /run/test-control/fail-dns ] || exit 2
if [ -f /run/test-control/bootstrap-addresses ]; then
    cat /run/test-control/bootstrap-addresses
else
    printf '%s STREAM\\n' "''' + cls.server_ip + '''"
fi
''')
        cls.getent_mock.chmod(0o755)

    @classmethod
    def setup_https(cls):
        if hasattr(cls, 'https_ips'):
            return
        cls.https_control = Path(cls.temp.name) / 'https-control'
        cls.https_control.mkdir()
        (cls.https_control / 'regions.json').write_text(json.dumps({'regions': [{
            'id': 'test', 'port_forward': False,
            'servers': {'ovpnudp': [{'ip': cls.server_ip, 'cn': 'fixture-pia'}]}}]}))
        (cls.https_control / 'token.json').write_text(json.dumps({'token': cls.token}))
        subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
                        '-subj', '/CN=serverlist.piaservers.net',
                        '-keyout', str(cls.vpn_files / 'https.key'),
                        '-out', str(cls.vpn_files / 'https.csr')], check=True, capture_output=True)
        extensions = cls.vpn_files / 'https-extensions'
        extensions.write_text('basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n'
                              'subjectAltName=DNS:serverlist.piaservers.net,DNS:www.privateinternetaccess.com\n')
        subprocess.run(['openssl', 'x509', '-req', '-in', str(cls.vpn_files / 'https.csr'),
                        '-CA', str(cls.vpn_files / 'ca.crt'), '-CAkey', str(cls.vpn_files / 'ca.key'),
                        '-CAcreateserial', '-days', '2', '-extfile', str(extensions),
                        '-out', str(cls.vpn_files / 'https.crt')], check=True, capture_output=True)
        cls.https_ips = []
        for index in range(3):
            name = cls.prefix + '-https-' + str(index)
            cls.containers.append(name)
            cls.docker('run', '-d', '--name', name, '--network', cls.network,
                       '--mount', f'type=bind,src={cls.vpn_files},dst=/fixture,readonly',
                       '--mount', f'type=bind,src={cls.https_control},dst=/control,readonly',
                       '--mount', f'type=bind,src={ROOT / "tests/fixtures/bootstrap-https.py"},dst=/server.py,readonly',
                       'python:3.13-alpine', 'python', '/server.py', timeout=180)
            cls.https_ips.append(cls.address(name))
        cls.docker('cp', str(cls.vpn_files / 'ca.crt'), cls.peer + ':/tmp/https-ca.crt')
        # Positive controls establish real TLS reachability at every address.
        for address in cls.https_ips:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                result = cls.docker('exec', cls.peer, 'curl', '-q', '-4', '--silent', '--fail',
                                    '--max-time', '2', '--cacert', '/tmp/https-ca.crt',
                                    '--resolve', f'serverlist.piaservers.net:443:{address}',
                                    'https://serverlist.piaservers.net/probe', check=False)
                if result.returncode == 0 and result.stdout == 'fixture-ok':
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('TLS fixture failed its positive control: ' + result.stderr)
        (cls.https_control / 'dns-addresses').write_text(cls.https_ips[0] + '\n')

    @classmethod
    def cleanup(cls):
        for name in cls.containers:
            cls.docker("rm", "-f", name, check=False)
        for volume in cls.volumes:
            cls.docker("volume", "rm", volume, check=False)
        cls.docker("network", "rm", cls.network, check=False)
        # The real daemon owns its bind-mounted config after privilege drop.
        cls.docker("run", "--rm", "--entrypoint", "/bin/sh", "--mount",
                   f"type=bind,src={cls.temp.name},dst=/cleanup", cls.image,
                   "-c", 'chown -R "$1:$2" /cleanup', "cleanup",
                   str(os.getuid()), str(os.getgid()), check=False)
        cls.docker("image", "rm", cls.image, check=False)

    @classmethod
    def address(cls, name):
        info = json.loads(cls.docker("inspect", name).stdout)[0]
        return info["NetworkSettings"]["Networks"][cls.network]["IPAddress"]

    def start(self, suffix, *, network=None, net_admin=True, fail_auth=False, bad_certificate=False,
              missing_secret=False, bad_token=False, bad_ca=False, reject_vpn_auth=False, pf=False, rpc_auth=False,
              settings=None, overrides=None, storage=None, config_volume=None, dns=None,
              real_bootstrap=False, publish_rpc=False):
        name = self.prefix + "-" + suffix
        self.containers.append(name)
        control = Path(self.temp.name) / suffix
        control.mkdir(mode=0o700)
        (control / "regions.json").write_text(json.dumps({"regions": [{"id": "test", "port_forward": pf, "servers": {
            "ovpnudp": [{"ip": self.server_ip, "cn": "wrong-server" if bad_certificate else "fixture-pia"}]}}]}))
        token = "T" * 62 + "wrong-vpn-password" if reject_vpn_auth else self.token
        (control / "token.json").write_text(json.dumps({"token": "invalid" if bad_token else token}))
        if fail_auth:
            (control / "fail-auth").touch()
        username = control / "username"
        username.write_text("fixture-account\n")
        options = ["run", "-d", "--name", name, "--network", self.network, "--init",
                   "--security-opt", "no-new-privileges:true",
                   "-e", "PUID=001234", "-e", "PGID=002345",
                   "-e", "PIA_REGION=test", "-e", "VPN_START_TIMEOUT=6", "-e", "VPN_RETRY_DELAY=2",
                   "-e", "WEB_BIND_IP=192.0.2.10",
                   "-e", "LOCAL_NETWORK=" + (network or self.cidr),
                   "-e", "PIA_CONTROLLER_TEST_SECRET=do-not-inherit",
                   "--device", "/dev/net/tun",
                   "--mount", f"type=bind,src={control},dst=/run/test-control",
                   "--mount", f"type=bind,src={self.curl_mock},dst=/usr/bin/curl,readonly",
                   "--mount", f"type=bind,src={self.vpn_files / ('wrong-ca.crt' if bad_ca else 'ca.crt')},dst=/usr/local/share/pia/ca.crt,readonly",
                   "--mount", f"type=bind,src={username},dst=/run/secrets/pia_username,readonly"]
        if publish_rpc:
            options += ["--publish", "127.0.0.1:8088:9091/tcp"]
        if pf:
            payload = base64.b64encode(json.dumps({"port":45678,"expires_at":"2099-01-01T00:00:00Z","token":"fixture-pf-token"}).encode()).decode()
            (control / "lease.json").write_text(json.dumps({"status":"OK","payload":payload,"signature":"Zml4dHVyZQ=="}))
        if pf or storage is not None or real_bootstrap:
            options += ["--mount", f"type=bind,src={self.real_curl},dst=/usr/local/bin/real-curl,readonly"]
        if real_bootstrap:
            (control / 'real-bootstrap').touch()
            dns = self.https_ips[0]
            options += ['--mount', f'type=bind,src={self.vpn_files / "ca.crt"},dst=/etc/ssl/certs/ca-certificates.crt,readonly']
        else:
            options += ['--mount', f'type=bind,src={self.getent_mock},dst=/usr/bin/getent,readonly']
        for key, value in (overrides or {}).items():
            options += ["-e", f"{key}={value}"]
        if config_volume is not None:
            options += ["--mount", f"type=volume,src={config_volume},dst=/config"]
        elif rpc_auth or settings is not None or storage is not None:
            config = (storage if storage is not None else control) / "config"
            new_config = not config.exists()
            config.mkdir(exist_ok=True)
            values = dict(settings or {})
            if rpc_auth:
                values.update({"rpc-authentication-required":True,
                               "rpc-username":"fixture-rpc-user", "rpc-password":"fixture-rpc-password",
                               "dht-enabled":False,"lpd-enabled":False,"pex-enabled":False})
            if storage is None or new_config:
                (config / "settings.json").write_text(json.dumps(values))
                (config / "settings.json").chmod(0o644)
            options += ["--mount", f"type=bind,src={config},dst=/config"]
        if storage is not None:
            data = storage / "data"
            data.mkdir(exist_ok=True)
            options += ["--mount", f"type=bind,src={data},dst=/data"]
        if rpc_auth:
            for kind, value in [("username", "fixture-rpc-user"), ("password", "fixture-rpc-password")]:
                secret = control / ("rpc-" + kind)
                secret.write_text(value)
                options += ["--mount", f"type=bind,src={secret},dst=/run/secrets/transmission_rpc_{kind},readonly"]
        if not missing_secret:
            options += ["--mount", f"type=bind,src={self.secret},dst=/run/secrets/pia_password,readonly"]
        if net_admin:
            options += ["--cap-add", "NET_ADMIN"]
        if dns is not None:
            options += ["--dns", dns]
        self.docker(*options, self.image)
        return name

    def exec(self, name, command, check=True):
        return self.docker("exec", name, "/bin/sh", "-c", command, check=check)

    def ready(self, name, rpc_auth=False):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = self.exec(name, "pidof transmission-daemon", check=False)
            if result.returncode == 0:
                # Wait for the actual RPC listener as well as daemon exec.
                response = self.exec(name,
                    "wget -S -T 1 -O /dev/null " +
                    ("--header 'Authorization: Basic " + base64.b64encode(
                        b"fixture-rpc-user:fixture-rpc-password").decode() + "' " if rpc_auth else "") +
                    "http://127.0.0.1:9091/transmission/rpc", check=False)
                if "409" in response.stderr:
                    return result.stdout.strip()
            state = json.loads(self.docker("inspect", name).stdout)[0]["State"]
            if not state["Running"]:
                break
            time.sleep(0.1)
        self.fail("Transmission did not become ready:\n" + self.docker("logs", name).stderr)

    def wait_exit(self, name):
        return int(self.docker("wait", name, timeout=40).stdout.strip())

    def test_installed_version_standard_web_and_runtime_dependencies(self):
        result = self.docker("run", "--rm", "--entrypoint", "/usr/bin/transmission-daemon",
                             self.image, "--version")
        version = (result.stdout + result.stderr).strip()
        self.assertRegex(version, r"^transmission-daemon 4\.1\.3(?:[ (]|$)")
        self.docker("run", "--rm", "--entrypoint", "/bin/sh", self.image, "-ec",
                    'test -s /usr/share/transmission/public_html/index.html; '
                    '! command -v cc; ! command -v cmake; ! command -v ninja')

    def rpc(self, name, method, arguments=None):
        client = ["exec", name, "/usr/local/bin/real-curl", "--silent", "--show-error", "--max-time", "3",
                  "--user", "fixture-rpc-user:fixture-rpc-password"]
        url = "http://127.0.0.1:9091/transmission/rpc"
        challenge = self.docker(*client, "--dump-header", "-", "--output", "/dev/null", url)
        session = next(line.split(":", 1)[1].strip() for line in challenge.stdout.splitlines()
                       if line.strip().lower().startswith("x-transmission-session-id:"))
        result = self.docker(*client, "--fail", "--header", "X-Transmission-Session-Id: " + session,
                             "--data", json.dumps({"method": method, "arguments": arguments or {}}), url)
        response = json.loads(result.stdout)
        self.assertEqual(response["result"], "success")
        return response["arguments"]

    def assert_config_private(self, name, uid, gid):
        modes = self.exec(name, "stat -c '%u:%g:%a' /config /config/settings.json").stdout.splitlines()
        self.assertEqual(modes, [f"{uid}:{gid}:700", f"{uid}:{gid}:600"])
        # 4.1.3 accepts decimal input and serializes the mask as an octal string.
        self.exec(name, "jq -e '.umask == \"077\"' /config/settings.json > /dev/null")
        self.exec(name, "grep -q '^Umask:[[:space:]]*0077$' /proc/$(pidof transmission-daemon)/status")
        self.exec(name, f"drop-privileges {uid} {gid} /bin/sh -ec "
                  "'test -r /config/settings.json; test -w /config/settings.json; "
                  "test ! -r /run/secrets/pia_password; test ! -w /data'")
        # Deny unrelated UIDs even when they share the application's primary GID.
        for other_gid in (gid, 6789):
            denied = self.exec(name, f"drop-privileges 5678 {other_gid} /bin/sh -c "
                               "'cat /config/settings.json > /dev/null'", check=False)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("Permission denied", denied.stderr)
            self.exec(name, f"drop-privileges 5678 {other_gid} /bin/sh -ec "
                      "'test ! -r /config; test ! -x /config'")

    def test_config_permissions_writes_restart_and_recreation(self):
        for fresh in (True, False):
            with self.subTest(fresh_named_volume=fresh):
                suffix = "private-fresh" if fresh else "private-existing"
                storage = Path(self.temp.name) / (suffix + "-storage")
                storage.mkdir()
                data = storage / "data"
                data.mkdir()
                volume = self.prefix + "-config"
                if fresh:
                    self.volumes.append(volume)
                    self.docker("volume", "create", volume)
                    config_mount = f"type=volume,src={volume},dst=/config"
                else:
                    config = storage / "config"
                    config.mkdir()
                    config_mount = f"type=bind,src={config},dst=/config"
                mounts = ["--mount", config_mount, "--mount", f"type=bind,src={data},dst=/data"]
                # Root-owned private legacy settings must migrate without a tree walk.
                seed = "" if fresh else (
                    "printf '%s' '{\"umask\":18,\"speed-limit-up\":73,\"rpc-authentication-required\":true,"
                    "\"rpc-username\":\"fixture-rpc-user\",\"rpc-password\":\"fixture-rpc-password\"}' "
                    "> /config/settings.json; chmod 0600 /config/settings.json; ")
                sentinel = "stat -c '%u:%g:%a:%s:%Y:%i' /config/nested/keep /data/nested/keep"
                before = self.docker("run", "--rm", "--network", "none", *mounts,
                                     "--entrypoint", "/bin/sh", self.image, "-ec",
                                     "chmod 0755 /config; mkdir -p /config/nested /data/nested; "
                                     "printf config-data > /config/nested/keep; printf torrent-data > /data/nested/keep; "
                                     "chmod 0640 /config/nested/keep /data/nested/keep; " + seed + sentinel).stdout
                name = self.start(suffix, storage=storage, config_volume=volume if fresh else None)
                for stage in ("initial", "restart", "recreate"):
                    uid, gid = (3456, 4567) if stage == "recreate" else (1234, 2345)
                    if stage == "restart":
                        self.docker("start", name)
                    elif stage == "recreate":
                        self.docker("rm", name)
                        name = self.start(suffix + "-recreated", storage=storage,
                                          config_volume=volume if fresh else None,
                                          overrides={"PUID": str(uid), "PGID": str(gid)})
                    self.ready(name, rpc_auth=not fresh)
                    if stage != "initial":
                        self.assertEqual(self.rpc(name, "session-get")["speed-limit-up"], 81)
                    # The daemon saves at startup and shutdown. RPC changes must
                    # survive its shutdown rewrite, with authentication retained.
                    self.rpc(name, "session-set", {"speed-limit-up": 81})
                    self.assertEqual(self.rpc(name, "session-get")["speed-limit-up"], 81)
                    self.assert_config_private(name, uid, gid)
                    self.assertEqual(self.exec(name, sentinel).stdout, before)
                    self.exec(name, "test $(cat /config/nested/keep) = config-data; "
                              "test $(cat /data/nested/keep) = torrent-data")
                    self.docker("stop", "-t", "30", name)
                    self.assertEqual(self.wait_exit(name), 0)
                    stopped = self.docker("run", "--rm", "--network", "none", "--volumes-from", name + ":ro",
                                          "--entrypoint", "/bin/sh", self.image, "-ec",
                                          "stat -c '%u:%g:%a' /config /config/settings.json; "
                                          "jq -e '.umask == \"077\" and .[\"speed-limit-up\"] == 81 and "
                                          f".[\"rpc-authentication-required\"] == {str(not fresh).lower()} and "
                                          "(.[\"rpc-password\"] | startswith(\"{\"))' "
                                          "/config/settings.json > /dev/null")
                    self.assertEqual(stopped.stdout.splitlines(), [f"{uid}:{gid}:700", f"{uid}:{gid}:600"])

    def test_legacy_configuration_authenticated_pf_and_restart(self):
        for explicit in (False, True):
            with self.subTest(explicit_overrides=explicit):
                suffix = "config-overrides" if explicit else "config-persisted"
                overrides = {"TRANSMISSION_DOWNLOAD_DIR": "/data/complete",
                             "TRANSMISSION_INCOMPLETE_DIR": "/data/incomplete",
                             "TRANSMISSION_INCOMPLETE_DIR_ENABLED": "true"} if explicit else {}
                name = self.start(suffix, pf=True, rpc_auth=True, overrides=overrides,
                                  settings={"download-dir": "/data/existing",
                                            "incomplete-dir": "/data/partial",
                                            "incomplete-dir-enabled": False,
                                            "speed-limit-up": 73, "speed-limit-up-enabled": True,
                                            "peer-port": 54321, "peer-port-random-on-start": True,
                                            "port-forwarding-enabled": True})
                for restart in (False, True):
                    if restart:
                        self.docker("start", name)
                    self.wait_for(name, 'test -f /run/pia-transmission/pf-active', timeout=75)
                    # The actual daemon response proves legacy RPC compatibility,
                    # authentication and PF readback, not just a settings-file edit.
                    response = json.loads(self.exec(name, 'cat /run/pia-transmission/pf/rpc-response').stdout)
                    self.assertEqual(response["result"], "success")
                    values = response["arguments"]
                    self.assertRegex(values["version"], r"^4\.1\.3(?:[ (]|$)")
                    self.assertEqual(values["peer-port"], 45678)
                    self.assertIs(values["peer-port-random-on-start"], False)
                    self.assertIs(values["port-forwarding-enabled"], False)
                    self.assertEqual(values["download-dir"], "/data/complete" if explicit else "/data/existing")
                    self.assertEqual(values["incomplete-dir"], "/data/incomplete" if explicit else "/data/partial")
                    self.assertIs(values["incomplete-dir-enabled"], explicit)
                    self.assertEqual(values["speed-limit-up"], 73)
                    self.assertIs(values["speed-limit-up-enabled"], True)
                    self.docker("stop", "-t", "30", name)
                    config = Path(self.temp.name) / suffix / "config"
                    saved = json.loads(self.docker(
                        "run", "--rm", "--entrypoint", "/bin/cat", "--mount",
                        f"type=bind,src={config},dst=/config,readonly", self.image,
                        "/config/settings.json").stdout)
                    self.assertEqual(saved["peer-port"], 45678)
                    self.assertIs(saved["rpc-authentication-required"], True)
                    self.assertEqual(saved["rpc-username"], "fixture-rpc-user")
                    self.assertTrue(saved["rpc-password"].startswith("{"))
                    self.assertNotEqual(saved["rpc-password"], "fixture-rpc-password")

    def test_real_process_privileges_secret_isolation_and_descriptor_closure(self):
        name = self.start("privileges")
        pid = self.ready(name)
        raw = self.exec(name, f"cat /proc/{pid}/status").stdout
        status = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)
        self.assertEqual(status["Uid"].split(), ["1234"] * 4)
        self.assertEqual(status["Gid"].split(), ["2345"] * 4)
        self.assertEqual(status["Groups"].split(), [])
        for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            self.assertEqual(int(status[field].strip(), 16), 0, field)
        self.assertEqual(status["NoNewPrivs"].strip(), "1")
        # Read as the daemon's UID; default controller caps exclude SYS_PTRACE.
        environ = self.exec(name,
            "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
            f"/bin/sh -c \"tr '\\000' '\\n' < /proc/{pid}/environ\"").stdout
        self.assertNotIn("PIA_", environ)
        self.assertNotIn("do-not-inherit", environ)
        denied = self.exec(name,
            "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
            "/bin/cat /run/secrets/pia_password", check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(denied.stdout, "")
        self.exec(name,
            "exec 9</run/secrets/pia_password; "
            "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
            "/bin/sh -c 'test ! -e /proc/self/fd/9'")
        self.assertNotIn("fixture-secret", self.docker("logs", name).stderr)
        # The controller must retain NET_ADMIN for future VPN control.
        self.exec(name, "nft list table inet pia_transmission")

    def test_all_packaged_web_ui_selections_restart_and_privilege_boundary(self):
        choices = {"transmission-web": "/usr/share/transmission/web-ui/transmission-web",
                   "transmission-web-legacy": "/usr/share/transmission/web-ui/transmission-web-legacy",
                   "transmission-default": "/usr/share/transmission/public_html"}
        for choice, home in choices.items():
            with self.subTest(choice=choice):
                name = self.start(choice, settings={"speed-limit-up": 73, "default-trackers": "http://127.0.0.1/explicit"},
                                  overrides={"TRANSMISSION_WEB_UI": choice, "TRANSMISSION_WEB_HOME": "/config/attacker"})
                for restart in (False, True):
                    if restart:
                        self.docker("start", name)
                    pid = self.ready(name)
                    raw = self.exec(name, f"cat /proc/{pid}/status").stdout
                    status = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)
                    self.assertEqual(status["Uid"].split(), ["1234"] * 4)
                    self.assertEqual(status["Gid"].split(), ["2345"] * 4)
                    self.assertEqual(status["Groups"].split(), [])
                    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                        self.assertEqual(int(status[field], 16), 0, field)
                    self.assertEqual(status["NoNewPrivs"].strip(), "1")
                    environ = self.exec(name, "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
                                        f"/bin/sh -c \"tr '\\000' '\\n' < /proc/{pid}/environ\"").stdout
                    self.assertIn("TRANSMISSION_WEB_HOME=" + home + "\n", environ)
                    self.assertNotIn("attacker", environ)
                    self.assertNotIn("PIA_", environ)
                    page = self.exec(self.peer, f"wget -T 3 -qO- http://{self.address(name)}:9091/transmission/web/").stdout
                    installed = self.exec(name, f"cat {home}/index.html").stdout
                    self.assertEqual(page, installed)
                    # Packaged UI assets stay root-owned and immutable to Transmission.
                    self.exec(name, f"test $(stat -c %u {home}/index.html) = 0")
                    denied = self.exec(name, f"env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
                                       f"/bin/sh -c 'test ! -w {home}/index.html && test ! -r /run/secrets/pia_password'", check=False)
                    self.assertEqual(denied.returncode, 0)
                    if not restart:
                        self.exec(name, "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
                                  "/bin/sh -c 'printf preserved > /data/complete/webui-persistence-marker'")
                    self.assertEqual(self.exec(name, "cat /data/complete/webui-persistence-marker").stdout, "preserved")
                    self.docker("stop", "-t", "30", name)
                    saved = json.loads(
                        self.docker("run", "--rm", "--entrypoint", "/bin/cat", "--mount",
                                    f"type=bind,src={Path(self.temp.name) / choice / 'config'},dst=/config,readonly",
                                    self.image, "/config/settings.json").stdout)
                    self.assertEqual(saved["speed-limit-up"], 73)
                    self.assertEqual(saved["default-trackers"], "http://127.0.0.1/explicit")

    def test_invalid_web_ui_rejected_without_changing_config_or_data(self):
        for index, choice in enumerate(("", "unknown", "../public_html", "$(id)", "transmission-web;id")):
            with self.subTest(choice=choice):
                name = self.start(f"invalid-ui-{index}", settings={"speed-limit-up": 73},
                                  overrides={"TRANSMISSION_WEB_UI": choice})
                self.assertNotEqual(self.wait_exit(name), 0)
                logs = self.docker("logs", name).stderr
                self.assertIn("TRANSMISSION_WEB_UI must be", logs)
                config = Path(self.temp.name) / f"invalid-ui-{index}" / "config/settings.json"
                self.assertEqual(json.loads(config.read_text()), {"speed-limit-up": 73})
                self.assertEqual(config.stat().st_uid, os.getuid())

    def test_switching_ui_by_recreation_preserves_config_torrents_and_data(self):
        storage = Path(self.temp.name) / "shared-storage"
        storage.mkdir()

        def rpc(name, method, arguments=None):
            challenge = self.docker("exec", name, "/usr/local/bin/real-curl", "--silent", "--max-time", "3",
                                    "--dump-header", "-", "--output", "/dev/null", "http://127.0.0.1:9091/transmission/rpc")
            session = next(line.split(":", 1)[1].strip() for line in challenge.stdout.splitlines()
                           if line.strip().lower().startswith("x-transmission-session-id:"))
            result = self.docker("exec", name, "/usr/local/bin/real-curl", "--fail", "--silent", "--max-time", "3", "--header",
                                 "X-Transmission-Session-Id: " + session, "--data",
                                 json.dumps({"method": method, "arguments": arguments or {}}),
                                 "http://127.0.0.1:9091/transmission/rpc")
            response = json.loads(result.stdout)
            self.assertEqual(response["result"], "success")
            return response["arguments"]

        infohash = "0123456789012345678901234567890123456789"
        for index, choice in enumerate(("transmission-web", "transmission-web-legacy", "transmission-default")):
            name = self.start(f"recreate-ui-{index}", storage=storage,
                              settings={"speed-limit-up": 73, "dht-enabled": False, "pex-enabled": False},
                              overrides={"TRANSMISSION_WEB_UI": choice})
            self.ready(name)
            if index == 0:
                rpc(name, "torrent-add", {"filename": "magnet:?xt=urn:btih:" + infohash, "paused": True})
                rpc(name, "session-set", {"speed-limit-up": 81})
                self.exec(name, "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
                          "/bin/sh -c 'printf preserved > /data/complete/recreation-marker'")
            self.assertEqual(rpc(name, "session-get")["speed-limit-up"], 81)
            torrents = rpc(name, "torrent-get", {"fields": ["hashString"]})["torrents"]
            self.assertEqual(torrents, [{"hashString": infohash}])
            self.assertEqual(self.exec(name, "cat /data/complete/recreation-marker").stdout, "preserved")
            self.docker("stop", "-t", "30", name)
            self.docker("rm", name)

    def test_lan_rpc_replies_work_and_new_lan_egress_is_blocked(self):
        name = self.start("network")
        self.ready(name)
        address = self.address(name)
        response = self.exec(self.peer,
            f"wget -S -T 3 -O /dev/null http://{address}:9091/transmission/rpc", check=False)
        self.assertIn("409", response.stderr)
        self.assertIn("peer-ok", self.exec(self.peer,
            f"wget -T 3 -qO- http://{self.peer_ip}:8080").stdout)
        denied = self.exec(name,
            "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
            f"/bin/busybox wget -T 2 -qO- http://{self.peer_ip}:8080", check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertNotIn("peer-ok", denied.stdout)
        self.exec(name, "nft -f /run/pia-transmission/lock.nft")
        response = self.exec(self.peer,
            f"wget -S -T 3 -O /dev/null http://{address}:9091/transmission/rpc", check=False)
        self.assertIn("409", response.stderr)

    def test_lan_rpc_configured_host_and_unauthorized_host_headers(self):
        name = self.start("host-whitelist", settings={
            "rpc-host-whitelist-enabled": False, "rpc-host-whitelist": "*"})
        self.ready(name)
        address = self.address(name)
        saved = json.loads(self.exec(name, "cat /config/settings.json").stdout)
        self.assertIs(saved["rpc-host-whitelist-enabled"], True)
        self.assertEqual(saved["rpc-host-whitelist"], "192.0.2.10")
        for host, status in (("192.0.2.10:8088", "409"),
                             ("unauthorized.example:8088", "421")):
            with self.subTest(host=host):
                response = self.exec(self.peer,
                    f"wget -S -T 3 --header='Host: {host}' -O /dev/null "
                    f"http://{address}:9091/transmission/rpc", check=False)
                self.assertIn(status, response.stderr)

    def test_compose_direct_rpc_default_and_override(self):
        env_file = Path(self.temp.name) / "compose.env"
        example = (ROOT / ".env.example").read_text()
        for port, setting in (("8088", ""), ("19091", "WEB_HOST_PORT=19091")):
            with self.subTest(port=port):
                env_file.write_text(example.replace("WEB_HOST_PORT=8088", setting))
                config = json.loads(self.docker("compose", "--env-file", str(env_file),
                    "-f", str(ROOT / "compose.yaml"), "config", "--format", "json").stdout)
                services = config["services"]
                self.assertEqual(list(services), ["pia-transmission"])
                self.assertEqual(services["pia-transmission"]["environment"]["WEB_BIND_IP"],
                                 "192.0.2.10")
                self.assertEqual(services["pia-transmission"]["ports"], [{
                    "mode": "ingress", "host_ip": "192.0.2.10", "target": 9091,
                    "published": port, "protocol": "tcp"}])

    def test_published_8088_ui_rpc_and_kill_switch(self):
        # Host loopback works on Docker Desktop as well as Linux. Physical LAN
        # source visibility and host-address binding require deployment checks.
        name = self.start("published-rpc", rpc_auth=True, publish_rpc=True)
        try:
            pid = self.ready(name, rpc_auth=True)
            base = "http://127.0.0.1:8088/transmission"

            def request(command, check=True):
                return subprocess.run(shlex.split(command), capture_output=True,
                                      text=True, check=check, timeout=10)

            auth = "--user fixture-rpc-user:fixture-rpc-password"

            def access():
                status = request(f"curl -sS --max-time 4 -o /dev/null -w '%{{http_code}}' {base}/rpc").stdout
                self.assertEqual(status, "401")
                self.assertEqual(request(
                    f"curl -sS --max-time 4 {auth} -o /dev/null -w '%{{http_code}}' {base}/web/").stdout, "200")
                headers = request(
                    f"curl -sS --max-time 4 {auth} -D - -o /dev/null {base}/rpc").stdout
                self.assertIn("409", headers)
                session = next(line.split(":", 1)[1].strip() for line in headers.splitlines()
                               if line.lower().startswith("x-transmission-session-id:"))
                body = request(f"curl -sS --max-time 4 {auth} "
                    f"-H 'X-Transmission-Session-Id: {session}' "
                    "--data " + shlex.quote(json.dumps({"method": "session-get"})) + f" {base}/rpc").stdout
                self.assertEqual(json.loads(body)["result"], "success")

            access()
            # Positive control: the VPN service is reachable before isolation.
            self.assertEqual(self.user_probe(name, "http://10.8.0.1:8080").returncode, 0)
            self.exec(name, "/usr/local/lib/pia-transmission/vpn-routing.sh close")
            access()
            self.assertEqual(self.exec(name, "pidof transmission-daemon").stdout.strip(), pid)
            self.assertNotEqual(self.user_probe(name, "http://10.8.0.1:8080").returncode, 0)
            self.assertNotEqual(self.user_probe(name, f"http://{self.peer_ip}:8080").returncode, 0)
            # Install the normal policy with an excluded client CIDR. Published
            # ports must not bypass the container's source allowlist.
            self.exec(name, "/usr/local/lib/pia-transmission/network-lock.sh 192.0.2.0/24 | nft -f -")
            denied = request(
                f"curl -sS --max-time 2 {auth} {base}/rpc", check=False)
            self.assertNotEqual(denied.returncode, 0)
        finally:
            self.docker("stop", "-t", "30", name, check=False)

    def test_nonallowlisted_rpc_is_blocked(self):
        name = self.start("rpc-denied", network="192.0.2.0/24")
        self.ready(name)
        address = self.address(name)
        response = self.exec(self.peer,
            f"wget -S -T 2 -O /dev/null http://{address}:9091/transmission/rpc", check=False)
        self.assertNotIn("409", response.stderr)
        self.assertNotEqual(response.returncode, 0)

    def test_no_net_admin_or_invalid_cidr_prevents_transmission_start(self):
        for suffix, options in (("no-cap", {"net_admin": False}),
                                ("bad-cidr", {"network": "999.0.0.0/24"})):
            with self.subTest(suffix=suffix):
                name = self.start(suffix, **options)
                self.assertNotEqual(self.wait_exit(name), 0)
                logs = self.docker("logs", name)
                self.assertIn("network protection failed", logs.stderr)
                self.assertNotIn("Transmission exited", logs.stderr)
                copied = self.docker("cp", f"{name}:/config/settings.json",
                                     str(Path(self.temp.name) / suffix), check=False)
                self.assertNotEqual(copied.returncode, 0)

    def test_shutdown_and_unsolicited_child_exit(self):
        name = self.start("shutdown")
        self.ready(name)
        self.docker("stop", "-t", "10", name)
        self.assertEqual(self.wait_exit(name), 0)
        name = self.start("child-exit")
        pid = self.ready(name)
        self.exec(name, f"kill -TERM {pid}")
        self.assertNotEqual(self.wait_exit(name), 0)

    def wait_for(self, name, command, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.exec(name, command, check=False).returncode == 0:
                return
            time.sleep(0.1)
        self.fail("condition did not become true: " + command)

    def user_probe(self, name, url):
        return self.exec(name,
            "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
            f"/bin/busybox wget -T 2 -qO- {url}", check=False)

    def test_actual_encrypted_tunnel_carries_application_traffic(self):
        name = self.start("tunnel-data")
        self.ready(name)
        response = self.user_probe(name, "http://10.8.0.1:8080")
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertIn("peer-ok", response.stdout)
        self.exec(name, 'ip -4 route get 10.8.0.1 uid 1234 | grep "dev tun0"')
        denied = self.user_probe(name, f"http://{self.server_ip}:8080")
        self.assertNotEqual(denied.returncode, 0)

    def test_credentials_are_file_backed_private_and_not_logged_or_in_argv(self):
        name = self.start("credentials")
        self.ready(name)
        control = Path(self.temp.name) / "credentials"
        self.assertEqual((control / "seen-username").read_text(), "fixture-account")
        self.assertEqual((control / "seen-password").read_text(), self.secret.read_text().strip())
        args = (control / "curl-argv").read_text()
        self.assertIn("username=</run/pia-transmission/username", args)
        self.assertIn("password=</run/pia-transmission/password", args)
        self.assertNotIn(self.secret.read_text().strip(), args)
        self.assertNotIn(self.token, args)
        self.exec(name, 'test "$(stat -c %a /run/pia-transmission/auth)" = 600')
        self.exec(name, 'test ! -e /run/pia-transmission/username; test ! -e /run/pia-transmission/password; test ! -e /run/pia-transmission/token-response')
        forbidden = (self.token, "fixture-account", self.secret.read_text().strip())
        for command in ('for p in /proc/[0-9]*; do cat "$p/cmdline" 2>/dev/null || :; done',
                        'p=$(pidof transmission-daemon); env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 /bin/cat /proc/$p/environ'):
            data = self.exec(name, command).stdout
            for value in forbidden:
                self.assertNotIn(value, data)
        logs = self.docker("logs", name)
        for value in forbidden:
            self.assertNotIn(value, logs.stdout + logs.stderr)
        denied = self.exec(name,
            'env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 /bin/cat /run/pia-transmission/auth', check=False)
        self.assertNotEqual(denied.returncode, 0)

    def test_startup_rejects_authentication_secrets_and_server_certificates(self):
        cases = (("auth-failed", {"fail_auth": True}), ("missing-secret", {"missing_secret": True}),
                 ("invalid-token", {"bad_token": True}), ("wrong-name", {"bad_certificate": True}),
                 ("untrusted-ca", {"bad_ca": True}), ("vpn-auth-rejected", {"reject_vpn_auth": True}))
        names = [self.start(suffix, **options) for suffix, options in cases]
        # More than one complete handshake deadline/retry; no daemon may start.
        time.sleep(10)
        for name in names:
            with self.subTest(name=name):
                self.exec(name, 'test ! -e /run/pia-transmission/ready; test ! -e /config/settings.json; ! pidof transmission-daemon')
                self.assertNotEqual(self.user_probe(name, f"http://{self.peer_ip}:8080").returncode, 0)
                self.assertNotEqual(self.user_probe(name, "http://10.8.0.1:8080").returncode, 0)
                self.docker("stop", "-t", "10", name)

    def test_vpn_disconnect_keeps_rpc_blocks_egress_and_reconnects(self):
        name = self.start("reconnect")
        pid = self.ready(name)
        self.assertEqual(self.user_probe(name, "http://10.8.0.1:8080").returncode, 0)
        control = Path(self.temp.name) / "reconnect"
        (control / "fail-auth").touch()
        # Kill the real OpenVPN process: no down-hook can be relied upon here.
        self.exec(name, 'kill -KILL $(pidof openvpn)')
        self.wait_for(name, 'test ! -e /run/pia-transmission/ready; ! pidof openvpn')
        self.assertEqual(self.exec(name, "pidof transmission-daemon").stdout.strip(), pid)
        address = self.address(name)
        response = self.exec(self.peer,
            f"wget -S -T 3 -O /dev/null http://{address}:9091/transmission/rpc", check=False)
        self.assertIn("409", response.stderr)
        self.assertNotEqual(self.user_probe(name, f"http://{self.peer_ip}:8080").returncode, 0)
        self.assertNotEqual(self.user_probe(name, "http://10.8.0.1:8080").returncode, 0)
        self.exec(name, 'ip -4 route show table 100 | grep "unreachable default"')
        (control / "fail-auth").unlink()
        self.wait_for(name, 'test -e /run/pia-transmission/ready', timeout=20)
        self.assertEqual(self.exec(name, "pidof transmission-daemon").stdout.strip(), pid)
        self.assertEqual(self.user_probe(name, "http://10.8.0.1:8080").returncode, 0)
        self.assertNotEqual(self.user_probe(name, f"http://{self.peer_ip}:8080").returncode, 0)

    def test_port_forward_authenticated_rpc_sync(self):
        name = self.start("pf-auth", pf=True, rpc_auth=True)
        self.wait_for(name, 'test -f /run/pia-transmission/pf-active', timeout=75)
        self.exec(name, 'test "$(cat /run/pia-transmission/pf-active)" = 45678; ss -lnt | grep ":45678 "')
        self.exec(name, '/usr/local/bin/drop-privileges 1234 2345 /bin/sh -c "test ! -r /run/secrets/transmission_rpc_password"')
        raw = self.docker("logs", name)
        self.assertNotIn("fixture-rpc-password", raw.stdout + raw.stderr)

    def test_port_forward_rpc_kernel_ingress_failure_and_reconnect(self):
        name = self.start("pf", pf=True)
        pid = self.ready(name)
        try:
            self.wait_for(name, 'test -f /run/pia-transmission/pf-active', timeout=75)
        except AssertionError:
            diagnostic = self.exec(name, "cat /run/pia-transmission/pf-status; test ! -f /run/pia-transmission/pf-gateway || cat /run/pia-transmission/pf-gateway; test ! -f /run/pia-transmission/pf/rpc-response || jq '{result, fields:(.arguments // {} | keys)}' /run/pia-transmission/pf/rpc-response", check=False)
            self.fail("PF failed: " + diagnostic.stdout + self.docker("logs", name).stderr)
        self.exec(name, 'test "$(cat /run/pia-transmission/pf-active)" = 45678')
        self.exec(name, 'ss -lnt | grep ":45678 "')
        # Real TCP connection through the encrypted fixture tunnel; no torrent payload.
        tunnel_ip = json.loads(self.exec(name, 'ip -j -4 addr show dev tun0').stdout)[0]['addr_info'][0]['local']
        self.exec(self.vpn_server, f'timeout 4 nc -w 1 {tunnel_ip} 45678 </dev/null')
        denied = self.exec(self.peer, f'timeout 3 nc -w 1 {self.address(name)} 45678 </dev/null', check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.exec(name, '/usr/local/bin/drop-privileges 1234 2345 /bin/sh -c "test ! -r /run/pia-transmission/pf-lease.json && test ! -r /run/pia-transmission/pf-token"')
        control = Path(self.temp.name) / "pf"
        (control / "fail-bind").touch()
        # Wake/restart only the worker to exercise a renewal failure immediately.
        self.exec(name, "pkill -TERM -f '^/bin/sh /usr/local/lib/pia-transmission/port-forward.sh '")
        self.wait_for(name, 'test ! -f /run/pia-transmission/pf-active && grep -q retrying /run/pia-transmission/pf-status')
        rules = self.exec(name, 'nft list chain inet pia_transmission vpn_forward').stdout
        self.assertNotIn('accept', rules)
        self.assertEqual(self.exec(name, 'pidof transmission-daemon').stdout.strip(), pid)
        self.assertEqual(self.user_probe(name, 'http://10.8.0.1:8080').returncode, 0)
        (control / "fail-bind").unlink()
        self.exec(name, "pkill -TERM -f '^/bin/sh /usr/local/lib/pia-transmission/port-forward.sh '")
        self.wait_for(name, 'test -f /run/pia-transmission/pf-active')
        stamp = self.exec(name, 'cat /run/pia-transmission/ready').stdout.strip()
        self.exec(name, 'kill -USR1 $(pidof openvpn)')
        self.wait_for(name, 'test -f /run/pia-transmission/ready && test "$(cat /run/pia-transmission/ready)" != "' + stamp + '"')
        self.wait_for(name, 'test -f /run/pia-transmission/pf-active', timeout=75)
        self.assertEqual(self.exec(name, 'pidof transmission-daemon').stdout.strip(), pid)
        tunnel_ip = json.loads(self.exec(name, 'ip -j -4 addr show dev tun0').stdout)[0]['addr_info'][0]['local']
        self.exec(self.vpn_server, f'timeout 4 nc -w 1 {tunnel_ip} 45678 </dev/null')

    def test_soft_reconnect_and_bootstrap_dns_isolation(self):
        name = self.start("soft-reconnect")
        pid = self.ready(name)
        stamp = self.exec(name, 'stat -c %y /run/pia-transmission/ready').stdout.strip()
        vpn_pid = self.exec(name, 'pidof openvpn').stdout.strip()
        self.exec(name, 'kill -USR1 $(pidof openvpn)')
        self.wait_for(name, f'test -f /run/pia-transmission/ready && test "$(stat -c %y /run/pia-transmission/ready)" != "{stamp}"')
        self.assertEqual(self.exec(name, 'pidof openvpn').stdout.strip(), vpn_pid)
        self.assertEqual(self.exec(name, "pidof transmission-daemon").stdout.strip(), pid)
        self.wait_for(name, 'env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 /bin/busybox wget -T 2 -qO- http://10.8.0.1:8080')
        # Docker resolves private bridge names: no public Internet dependency.
        allowed = self.exec(name, f'timeout 3 nslookup {self.peer} 127.0.0.11', check=False)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        denied = self.exec(name,
            'env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 '
            f'/bin/busybox timeout 3 nslookup {self.peer} 127.0.0.11', check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertNotIn(self.peer_ip, denied.stdout)

    def test_root_bootstrap_tls_destination_rotation(self):
        self.setup_https()
        name = self.start('root-https', real_bootstrap=True, network=self.https_ips[2] + '/32')
        self.ready(name)  # Real discovery, multipart token authentication and VPN TLS.
        self.wait_for(name, '! nft list set inet pia_transmission bootstrap_https | grep -q "elements ="')
        hold = self.https_control / 'hold'
        self.addCleanup(lambda: hold.unlink(missing_ok=True))

        def probe(address, hostname='serverlist.piaservers.net'):
            return self.exec(name, '/usr/local/bin/real-curl -q -4 --silent --show-error '
                             '--connect-timeout 1 --max-time 2 --output /dev/null '
                             f'--resolve {hostname}:443:{address} https://{hostname}/probe', check=False)

        for selected, old in ((self.https_ips[0], self.https_ips[1]),
                              (self.https_ips[1], self.https_ips[0])):
            (self.https_control / 'dns-addresses').write_text(selected + '\n')
            hold.touch()
            self.docker('exec', '-d', name, '/bin/sh', '-c',
                        'rm -f /tmp/bootstrap-status; '
                        'cat /run/pia-transmission/bootstrap-resolv.conf > /etc/resolv.conf; '
                        '. /usr/local/lib/pia-transmission/bootstrap-https.sh; '
                        'bootstrap_fetch serverlist.piaservers.net --output /tmp/bootstrap-response '
                        'https://serverlist.piaservers.net/vpninfo/servers/v6; '
                        'echo $? > /tmp/bootstrap-status')
            self.wait_for(name, f'nft list set inet pia_transmission bootstrap_https | grep -q "{selected}"')
            # Denials while the set is populated distinguish an allowlist from
            # a blanket HTTPS block. All peers passed verified TLS controls.
            self.assertNotEqual(probe(old).returncode, 0)
            self.assertNotEqual(probe(self.https_ips[2]).returncode, 0)
            self.assertEqual(probe(selected, 'wrong-host.test').returncode, 60)
            denied = self.exec(name,
                'drop-privileges 1234 2345 /usr/local/bin/real-curl -q -4 --silent '
                '--interface eth0 --connect-timeout 1 --max-time 2 --output /dev/null '
                f'--resolve serverlist.piaservers.net:443:{selected} '
                'https://serverlist.piaservers.net/probe', check=False)
            self.assertNotEqual(denied.returncode, 0)
            hold.unlink()
            self.wait_for(name, 'test -f /tmp/bootstrap-status')
            self.assertEqual(self.exec(name, 'cat /tmp/bootstrap-status').stdout.strip(), '0')
            self.exec(name, 'jq -e .regions /tmp/bootstrap-response > /dev/null')
            self.wait_for(name, '! nft list set inet pia_transmission bootstrap_https | grep -q "elements ="')
            self.assertNotEqual(probe(selected).returncode, 0)
        (self.https_control / 'dns-addresses').write_text(self.https_ips[0] + '\n')

    def test_root_bootstrap_dns_failure_and_vpn_recovery(self):
        self.setup_https()
        (self.https_control / 'dns-addresses').write_text(self.https_ips[0] + '\n')
        failure = self.https_control / 'fail-dns'
        self.addCleanup(lambda: failure.unlink(missing_ok=True))
        failure.touch()
        name = self.start('root-dns-recovery', real_bootstrap=True, network=self.https_ips[2] + '/32')
        self.wait_for(name, 'test -f /run/pia-transmission/lock.nft')
        self.assertNotEqual(self.exec(name, 'pidof transmission-daemon', check=False).returncode, 0)
        self.wait_for(name, '! nft list set inet pia_transmission bootstrap_https | grep -q "elements ="')
        failure.unlink()
        pid = self.ready(name)
        self.wait_for(name, 'drop-privileges 1234 2345 /bin/busybox wget -T 2 -qO- http://10.8.0.1:8080')
        failure.touch()
        self.exec(name, 'kill -KILL $(pidof openvpn)')
        self.wait_for(name, 'test ! -e /run/pia-transmission/ready; ! pidof openvpn')
        self.wait_for(name, '! nft list set inet pia_transmission bootstrap_https | grep -q "elements ="')
        self.assertEqual(self.exec(name, 'pidof transmission-daemon').stdout.strip(), pid)
        self.assertNotEqual(self.user_probe(name, 'http://10.8.0.1:8080').returncode, 0)
        root_wan = self.exec(name, '/usr/local/bin/real-curl -q -4 --silent --interface eth0 '
                             '--connect-timeout 1 --max-time 2 --output /dev/null '
                             f'--resolve serverlist.piaservers.net:443:{self.https_ips[1]} '
                             'https://serverlist.piaservers.net/probe', check=False)
        self.assertNotEqual(root_wan.returncode, 0)
        # The resolver itself is still reachable during the DNS failure: an
        # NXDOMAIN must fail closed without a firewall/bootstrap deadlock.
        response = self.exec(name, f'timeout 3 nslookup serverlist.piaservers.net {self.https_ips[0]}', check=False)
        self.assertIn('NXDOMAIN', response.stdout + response.stderr)
        (self.https_control / 'dns-addresses').write_text(self.https_ips[1] + '\n')
        failure.unlink()
        self.wait_for(name, 'test -f /run/pia-transmission/ready', timeout=25)
        self.assertEqual(self.exec(name, 'pidof transmission-daemon').stdout.strip(), pid)
        self.wait_for(name, 'drop-privileges 1234 2345 /bin/busybox wget -T 2 -qO- http://10.8.0.1:8080')
        self.wait_for(name, '! nft list set inet pia_transmission bootstrap_https | grep -q "elements ="')

    def test_embedded_dns_forwarding_stays_root_only_across_vpn_down(self):
        self.docker("cp", str(ROOT / "tests/fixtures/dns-response.sh"),
                    self.peer + ":/tmp/dns-response")
        self.exec(self.peer, "chmod 0755 /tmp/dns-response")
        self.docker("exec", "-d", self.peer, "nc", "-lk", "-p", "53",
                    "-e", "/tmp/dns-response")
        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09bootstrap\x04test\x00\x00\x01\x00\x01'
        wire = len(query).to_bytes(2, 'big') + query
        escaped = ''.join(f'\\{byte:03o}' for byte in wire)

        def dns_query(address):
            return f"printf '{escaped}' | nc -w 2 {address} 53 | od -An -tx1 | tr -d ' \\n'"

        # Positive control independent of the runtime firewall and tunnel.
        self.wait_for(self.peer, dns_query('127.0.0.1') + ' | grep -q c000027b')
        name = self.start("embedded-dns", dns=self.peer_ip)
        pid = self.ready(name)
        root_query = dns_query('127.0.0.11')
        self.assertIn('c000027b', self.exec(name, root_query).stdout)
        # This is the same root-owned upstream leg seen on Linux Engine, even
        # when Docker Desktop forwards embedded-DNS packets outside the netns.
        direct_query = dns_query(self.peer_ip)
        self.assertIn('c000027b', self.exec(name, direct_query).stdout)
        for query_command in (root_query, direct_query):
            denied = self.exec(name,
                "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
                "/bin/sh -c " + shlex.quote(query_command), check=False)
            self.assertNotIn('c000027b', denied.stdout)
        # Force the controller through VPN-down with authentication unavailable.
        (Path(self.temp.name) / "embedded-dns/fail-auth").touch()
        self.exec(name, 'kill -KILL $(pidof openvpn)')
        self.wait_for(name, 'test ! -e /run/pia-transmission/ready; ! pidof openvpn')
        self.assertEqual(self.exec(name, "pidof transmission-daemon").stdout.strip(), pid)
        self.assertIn('c000027b', self.exec(name, root_query).stdout)
        self.assertNotEqual(self.user_probe(name, "http://10.8.0.1:8080").returncode, 0)
        self.assertNotIn('c000027b', self.exec(name,
            "env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 "
            + "/bin/sh -c " + shlex.quote(root_query), check=False).stdout)
        address = self.address(name)
        response = self.exec(self.peer,
            f"wget -S -T 3 -O /dev/null http://{address}:9091/transmission/rpc", check=False)
        self.assertIn("409", response.stderr)
        # Unavailable bootstrap DNS must not open application egress.
        self.exec(self.peer, "mv /tmp/dns-response /tmp/dns-response-disabled")
        try:
            self.assertNotIn('c000027b', self.exec(name, root_query, check=False).stdout)
            self.assertNotEqual(self.user_probe(name, "http://10.8.0.1:8080").returncode, 0)
        finally:
            self.exec(self.peer, "mv /tmp/dns-response-disabled /tmp/dns-response")
        (Path(self.temp.name) / "embedded-dns/fail-auth").unlink()
        self.wait_for(name, 'test -e /run/pia-transmission/ready', timeout=25)
        self.assertEqual(self.exec(name, "pidof transmission-daemon").stdout.strip(), pid)
        self.assertIn('c000027b', self.exec(name, root_query).stdout)

    def test_vpn_transport_loss_keeps_rpc_and_recovers(self):
        name = self.start("transport-loss")
        pid = self.ready(name)
        self.docker("pause", self.vpn_server)
        try:
            self.wait_for(name, 'test ! -e /run/pia-transmission/ready', timeout=15)
            self.assertEqual(self.exec(name, "pidof transmission-daemon").stdout.strip(), pid)
            response = self.exec(self.peer,
                f"wget -S -T 3 -O /dev/null http://{self.address(name)}:9091/transmission/rpc", check=False)
            self.assertIn("409", response.stderr)
            self.assertNotEqual(self.user_probe(name, f"http://{self.peer_ip}:8080").returncode, 0)
        finally:
            self.docker("unpause", self.vpn_server)
        self.wait_for(name, 'test -e /run/pia-transmission/ready', timeout=25)
        self.assertEqual(self.exec(name, "pidof transmission-daemon").stdout.strip(), pid)
        self.wait_for(name, 'env -i PATH=/usr/bin:/bin /usr/local/bin/drop-privileges 1234 2345 /bin/busybox wget -T 2 -qO- http://10.8.0.1:8080')


if __name__ == "__main__":
    unittest.main()
