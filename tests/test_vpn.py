"""Host-level VPN script checks. curl, nft and routing are mocked here.

The container suite separately uses real OpenVPN/TLS and actual kernel routes.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VPNScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pia-vpn-unit-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / "state"
        self.secrets = self.base / "secrets"
        self.bin = self.base / "bin"
        for directory in (self.state, self.secrets, self.bin):
            directory.mkdir(mode=0o700)
        self.username = 'account-with-$()-chars'
        self.password = 'password "quoted" $() \\ & ; = %'
        (self.secrets / "pia_username").write_text(self.username + "\n")
        (self.secrets / "pia_password").write_text(self.password + "\n")
        self.token = "T" * 62 + "token-tail"
        (self.base / "token.json").write_text(json.dumps({"token": self.token}))
        self.regions = {"regions": [{"id": "test", "servers": {"ovpnudp": [
            {"ip": "198.51.100.2", "cn": "test-server"},
            {"ip": "198.51.100.3", "cn": "test-server-2"}]}}]}
        (self.base / "regions.json").write_text(json.dumps(self.regions))
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        PIA_REGION="test", CONTROLLER_SECRET="must-not-be-in-curl-env")
        self.curl = self.command("curl", f'''
printf '%s\\n' "$@" >> '{self.base}/curl-argv'
env > '{self.base}/curl-env'
out=; previous=
for argument in "$@"; do
    if [ "$previous" = --output ]; then out=$argument; fi
    previous=$argument
done
case "$previous" in
    */servers/v6) cp '{self.base}/regions.json' "$out" ;;
    */token)
        if [ -f '{self.base}/rate-limit' ]; then printf 429; exit 22; fi
        [ ! -f '{self.base}/fail-auth' ] || exit 22
        cp '{self.state}/username' '{self.base}/seen-username'
        cp '{self.state}/password' '{self.base}/seen-password'
        cp '{self.base}/token.json' "$out" ;;
    *) exit 22 ;;
esac
''')
        self.command("nft", f'''if [ "$1" = -f ]; then
    cat >> "{self.base}/nft-batch"
    [ ! -f "{self.base}/fail-publish" ]
else printf "%s\\n" "$*" >> "{self.base}/nft-batch"; fi
[ ! -f "{self.base}/fail-nft" ]''')
        self.command("ip", f"printf '%s\\n' \"$*\" >> '{self.base}/ip-argv'\necho 'inet 10.8.0.2/24'\n[ ! -f '{self.base}/fail-ip' ]")
        self.command("id", "echo 0")
        self.command("getent", f'''echo "$*" >> '{self.base}/dns-argv'
[ ! -f '{self.base}/fail-dns' ]
if [ -f '{self.base}/dns-answers' ]; then cat '{self.base}/dns-answers'; else
    printf '203.0.113.10 STREAM\\n203.0.113.11 STREAM\\n203.0.113.10 DGRAM\\n'
fi''')
        self.script("bootstrap-https.sh")

    def command(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o755)
        return path

    def script(self, name):
        source = (ROOT / "runtime" / name).read_text()
        source = source.replace("/run/pia-transmission", str(self.state))
        source = source.replace("/run/secrets", str(self.secrets))
        source = source.replace("/etc/resolv.conf", str(self.base / "resolv.conf"))
        source = source.replace("/usr/local/lib/pia-transmission", str(self.bin))
        source = source.replace("curl -q", str(self.curl) + " -q")
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)
        return path

    def prepare(self, attempt=0, region="test"):
        self.script("pia-auth.sh")
        return subprocess.run([str(self.script("vpn-prepare.sh")), str(attempt)],
                              env=dict(self.env, PIA_REGION=region), capture_output=True, text=True)

    def test_file_credentials_preserve_special_chars_and_do_not_escape_to_argv_env_or_logs(self):
        result = self.prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.base / "seen-username").read_text(), self.username)
        self.assertEqual((self.base / "seen-password").read_text(), self.password)
        for file in ("curl-argv", "curl-env", "nft-batch"):
            text = (self.base / file).read_text()
            for secret in (self.username, self.password, self.token):
                self.assertNotIn(secret, text)
        self.assertNotIn("CONTROLLER_SECRET", (self.base / "curl-env").read_text())
        self.assertEqual(result.stdout, "")
        self.assertEqual((self.state / "auth").read_text(), "T" * 62 + "\ntoken-tail\n")
        self.assertEqual((self.state / "auth").stat().st_mode & 0o777, 0o600)
        for file in ("username", "password", "token-response", "servers-response"):
            self.assertFalse((self.state / file).exists())
        config = (self.state / "openvpn.conf").read_text()
        for setting in ("remote-cert-tls server", "verify-x509-name test-server name",
                        "tls-version-min 1.2", "auth-nocache", "route-noexec", "log /dev/null"):
            self.assertIn(setting, config)

    def test_retry_selects_next_region_server(self):
        self.assertEqual(self.prepare(attempt=1).returncode, 0)
        self.assertIn("remote 198.51.100.3 8080", (self.state / "openvpn.conf").read_text())

    def test_bootstrap_pins_each_hostname_and_revokes_addresses_after_requests(self):
        self.assertEqual(self.prepare().returncode, 0)
        args = (self.base / 'curl-argv').read_text()
        for host in ('serverlist.piaservers.net', 'www.privateinternetaccess.com'):
            self.assertIn(f'{host}:443:203.0.113.10,203.0.113.11', args)
            self.assertIn(f'ahostsv4 {host}.\n', (self.base / 'dns-argv').read_text())
        self.assertIn('--resolve\n', args)
        self.assertNotIn('--insecure', args)
        self.assertNotIn('--location', args)
        self.assertIn('--proto\n=https\n--tlsv1.2\n', args)
        batch = (self.base / 'nft-batch').read_text()
        self.assertIn('flush set inet pia_transmission bootstrap_https\n'
                      'add element inet pia_transmission bootstrap_https { 203.0.113.10,203.0.113.11 }\n', batch)
        self.assertTrue(batch.endswith('flush set inet pia_transmission bootstrap_https\n'))

    def test_bootstrap_dns_and_firewall_failure_never_start_https(self):
        for failure in ('fail-dns', 'fail-nft', 'fail-publish'):
            with self.subTest(failure=failure):
                (self.base / failure).touch()
                self.assertNotEqual(self.prepare().returncode, 0)
                self.assertFalse((self.base / 'curl-argv').exists())
                for name in ('username', 'password', 'token-response', 'servers-response'):
                    self.assertFalse((self.state / name).exists(), name)
                (self.base / failure).unlink()
        self.assertEqual(self.prepare().returncode, 0)

    def test_cancelled_bootstrap_request_revokes_addresses(self):
        marker = self.base / 'curl-started'
        original = self.curl.read_text()
        for url in ('https://serverlist.piaservers.net/vpninfo/servers/v6',
                    'https://www.privateinternetaccess.com/api/client/v2/token'):
            with self.subTest(url=url):
                marker.unlink(missing_ok=True)
                blocked = (f'if [ "$previous" = "{url}" ]; then\n'
                           f'    touch "{marker}"; exec /bin/sleep 30\nfi\n')
                self.curl.write_text(original.replace('case "$previous" in', blocked + 'case "$previous" in'))
                self.script('pia-auth.sh')
                process = subprocess.Popen([str(self.script('vpn-prepare.sh'))], env=self.env,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and time.monotonic() < deadline and process.poll() is None:
                        time.sleep(.02)
                    self.assertTrue(marker.exists(), 'bootstrap curl did not start')
                finally:
                    process.terminate()
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=35)
                        self.fail('bootstrap request did not stop promptly')
                self.assertNotEqual(process.returncode, 0)
                self.assertTrue((self.base / 'nft-batch').read_text().endswith(
                    'flush set inet pia_transmission bootstrap_https\n'))

    def test_bootstrap_rejects_empty_invalid_or_injected_dns_answers(self):
        for answer in ('', '999.0.0.1 STREAM\n', '::1 STREAM\n',
                       '203.0.113.1;accept STREAM\n', '203.0.113.1 STREAM\ninvalid STREAM\n'):
            with self.subTest(answer=answer):
                (self.base / 'dns-answers').write_text(answer)
                self.assertNotEqual(self.prepare().returncode, 0)
                self.assertFalse((self.base / 'curl-argv').exists())
                self.assertNotIn('add element inet pia_transmission bootstrap_https',
                                 (self.base / 'nft-batch').read_text())

    def test_bootstrap_refreshes_addresses_on_retry_and_dns_failure_revokes_old_set(self):
        self.assertEqual(self.prepare().returncode, 0)
        (self.base / 'dns-answers').write_text('203.0.113.12 STREAM\n')
        (self.base / 'nft-batch').write_text('')
        (self.base / 'curl-argv').unlink()
        self.assertEqual(self.prepare().returncode, 0)
        self.assertNotIn('203.0.113.10', (self.base / 'nft-batch').read_text())
        self.assertIn(':443:203.0.113.12', (self.base / 'curl-argv').read_text())
        (self.base / 'fail-dns').touch()
        (self.base / 'nft-batch').write_text('')
        (self.base / 'curl-argv').unlink()
        self.assertNotEqual(self.prepare().returncode, 0)
        self.assertFalse((self.base / 'curl-argv').exists())
        self.assertNotIn('add element', (self.base / 'nft-batch').read_text())
        self.assertIn('flush set inet pia_transmission bootstrap_https',
                      (self.base / 'nft-batch').read_text())

    def test_pf_authentication_stays_tunnel_bound_without_bootstrap_changes(self):
        result = subprocess.run([str(self.script('pia-auth.sh')), 'pf'],
                                env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--interface\ntun0\n', (self.base / 'curl-argv').read_text())
        self.assertFalse((self.base / 'dns-argv').exists())
        self.assertFalse((self.base / 'nft-batch').exists())

    def test_empty_multiline_and_missing_secrets_fail_before_network_calls(self):
        file = self.secrets / "pia_password"
        for value in ("", "first\nsecond\n", "with\rcarriage", "x" * 4097):
            with self.subTest(value=value[:20]):
                file.write_text(value)
                result = self.prepare()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.base / "curl-argv").exists())
        file.unlink()
        self.assertNotEqual(self.prepare().returncode, 0)
        self.assertFalse((self.base / "curl-argv").exists())

    def test_authentication_failure_and_invalid_tokens_never_create_client_config(self):
        (self.base / "fail-auth").touch()
        self.assertNotEqual(self.prepare().returncode, 0)
        (self.base / "fail-auth").unlink()
        for token in (None, "short", "T" * 63 + "\nnot-a-token", {"token": "object"}):
            with self.subTest(token=token):
                (self.base / "token.json").write_text(json.dumps({"token": token}))
                result = self.prepare()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.state / "openvpn.conf").exists())
                self.assertNotIn(self.password, result.stdout + result.stderr)

    def test_authentication_rate_limit_is_distinct_and_does_not_print_body(self):
        (self.base / "rate-limit").touch()
        result = self.prepare()
        self.assertEqual(result.returncode, 75)
        self.assertIn("rate limited", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertFalse((self.state / "auth-http-code").exists())
        self.assertFalse((self.state / "openvpn.conf").exists())

    def test_unknown_regions_and_config_injection_fail_before_authentication(self):
        self.assertNotEqual(self.prepare(region="unknown").returncode, 0)
        for endpoint in ({"ip": "999.1.1.1", "cn": "test-server"},
                         {"ip": "198.51.100.2", "cn": "x\nscript-security 3"}):
            self.regions["regions"][0]["servers"]["ovpnudp"] = [endpoint]
            (self.base / "regions.json").write_text(json.dumps(self.regions))
            self.assertNotEqual(self.prepare().returncode, 0)
            self.assertFalse((self.base / "seen-password").exists())
            self.assertFalse((self.state / "openvpn.conf").exists())

    def hook(self, kind="route-up", dns="10.8.0.1"):
        self.script("vpn-routing.sh")
        return subprocess.run([str(self.script("vpn-hook.sh"))],
                              env=dict(self.env, dev="tun0", script_type=kind,
                                       foreign_option_1="dhcp-option DNS " + dns),
                              capture_output=True, text=True)

    def test_route_up_requires_addresses_routes_and_firewall_before_readiness(self):
        for failure in ("fail-ip", "fail-nft"):
            (self.base / failure).touch()
            self.assertNotEqual(self.hook().returncode, 0)
            self.assertFalse((self.state / "ready").exists())
            (self.base / failure).unlink()
        self.assertEqual(self.hook().returncode, 0)
        self.assertTrue((self.state / "ready").exists())
        self.assertIn("default dev tun0 metric 10 table 100", (self.base / "ip-argv").read_text())
        self.assertEqual((self.base / "resolv.conf").read_text(), "nameserver 10.8.0.1\n")

    def test_invalid_pushed_dns_never_establishes_readiness(self):
        for dns in ("999.0.0.1", "10.8.0.1;accept", "::1"):
            self.assertNotEqual(self.hook(dns=dns).returncode, 0)
            self.assertFalse((self.state / "ready").exists())

    def test_down_revokes_tunnel_permissions_and_readiness_without_flushing_lan_rules(self):
        self.assertEqual(self.hook().returncode, 0)
        (self.base / "nft-batch").write_text("")
        self.assertEqual(self.hook(kind="route-pre-down").returncode, 0)
        self.assertFalse((self.state / "ready").exists())
        batch = (self.base / "nft-batch").read_text()
        self.assertEqual(batch, "flush chain inet pia_transmission vpn_traffic\nflush chain inet pia_transmission vpn_dns\nflush chain inet pia_transmission vpn_ingress\nflush chain inet pia_transmission vpn_forward\n")


if __name__ == "__main__":
    unittest.main()
