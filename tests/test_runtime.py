"""Host checks: real launcher validation/config merge, mocked controller commands.

These do not establish kernel firewall or container privilege correctness; those
checks live in test_container.py and require a Linux Docker engine.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="pia-launcher-")
        cls.launcher = Path(cls.build.name) / "drop-privileges"
        subprocess.run([
            "cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
            "-o", str(cls.launcher), str(ROOT / "runtime/drop-privileges.c"),
        ], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pia-runtime-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.events = self.base / "events"
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        PUID="1234", PGID="2345", LOCAL_NETWORK="192.0.2.0/24",
                        PIA_REGION="test", WEB_BIND_IP="192.0.2.10", VPN_START_TIMEOUT="3", VPN_RETRY_DELAY="1",
                        EVENTS=str(self.events), CONTROLLER_SECRET="not-for-child")

    def command(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\nset -eu\n" + body + "\n")
        path.chmod(0o755)
        return path

    def run_lock(self, value):
        return subprocess.run(["/bin/sh", str(ROOT / "runtime/network-lock.sh"), value],
                              capture_output=True, text=True)

    def controller(self, nft_status=0, child_body="exit 23"):
        runtime = self.base / "runtime"
        shutil.copytree(ROOT / "runtime", runtime)
        for file in runtime.glob("*.sh"):
            file.chmod(0o755)
        ui_root = self.base / "usr/share/transmission"
        for directory in ("public_html", "web-ui/transmission-web", "web-ui/transmission-web-legacy"):
            path = ui_root / directory
            path.mkdir(parents=True, exist_ok=True)
            (path / "index.html").write_text("fixture")
        selector = runtime / "select-web-ui.sh"
        selector.write_text(selector.read_text().replace("/usr/share/transmission", str(ui_root)))
        self.command("id", "echo 0")
        self.command("chown", ":")
        self.command("nft", f'echo nft >> "$EVENTS"\nexit {nft_status}')
        state = self.base / "run/pia-transmission"
        (runtime / "vpn-routing.sh").write_text(f'''#!/bin/sh
if [ "$1" = close ]; then rm -f '{state}/ready'; fi
''')
        (runtime / "vpn-prepare.sh").write_text("#!/bin/sh\nexit 0\n")
        self.command("ip", "echo 'default dev tun0 metric 10'")
        openvpn = self.command("openvpn", f'''trap 'exit 0' TERM
touch '{state}/ready'
while :; do sleep 0.1; done''')
        # Only substitute filesystem locations and the launcher in this isolated
        # harness. Keep the controller's actual control flow and environment scrub.
        launcher = self.command("drop-privileges", f'''
if [ "$1" = --check-ids ]; then exec '{self.launcher}' "$@"; fi
printf 'launch:%s:%s\\n' "$1" "$2" >> '{self.events}'
env > '{self.base / "child-env"}'
exec /bin/sh -c '{child_body}'
''')
        source = (runtime / "entrypoint.sh").read_text()
        for path in ("/run", "/config", "/data"):
            source = source.replace(path, str(self.base) + path)
        source = source.replace("/usr/local/lib/pia-transmission", str(runtime))
        source = source.replace("drop-privileges", str(launcher))
        resolv = self.base / "resolv.conf"
        resolv.write_text("nameserver 127.0.0.11\n")
        source = source.replace("/etc/resolv.conf", str(resolv))
        source = source.replace("openvpn --config", f"{openvpn} --config")
        script = self.base / "entrypoint.sh"
        script.write_text(source)
        return ["/bin/sh", str(script)]

    def test_auth_rate_limit_controller_backs_off_before_startup(self):
        command = self.controller()
        (self.base / "runtime/vpn-prepare.sh").write_text("#!/bin/sh\nexit 75\n")
        self.command("sleep", 'echo "sleep:$1" >> "$EVENTS"\nexec /bin/sleep "$1"')
        process = subprocess.Popen(command, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+5
            while time.monotonic()<deadline:
                if self.events.exists() and "sleep:300" in self.events.read_text():
                    break
                time.sleep(.02)
            else:
                self.fail("controller did not apply authentication backoff")
            self.assertNotIn("launch:", self.events.read_text())
        finally:
            process.terminate()
            process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)

    def test_launcher_id_validation(self):
        for uid, gid in [("1", "2"), ("1000", "1000"), ("4294967294", "65534")]:
            with self.subTest(uid=uid, gid=gid):
                result = subprocess.run([str(self.launcher), "--check-ids", uid, gid],
                                        capture_output=True)
                self.assertEqual(result.returncode, 0)

        for value in ("", "0", "-1", "+1", "1x", " 1", "4294967295", "999999999999999999999"):
            for position in (0, 1):
                ids = ["1000", "1000"]
                ids[position] = value
                with self.subTest(value=value, position=position):
                    result = subprocess.run([str(self.launcher), "--check-ids", *ids],
                                            capture_output=True)
                    self.assertNotEqual(result.returncode, 0)

    def test_root_https_requires_destination_set_and_respects_lan_deny(self):
        rules = self.run_lock('192.0.2.0/24').stdout
        self.assertIn('add set inet pia_transmission bootstrap_https { type ipv4_addr; flags timeout; timeout 45s; }', rules)
        rule = ('meta skuid 0 oifname "eth0" ip daddr @bootstrap_https '
                'tcp dport 443 ct mark set 0x50494101 accept')
        self.assertIn(rule, rules)
        self.assertNotIn('meta nfproto ipv4 tcp dport 443', rules)
        self.assertGreater(rules.index(rule), rules.index('ip daddr 192.0.2.0/24 drop'))

    def test_launcher_refuses_nonroot_execution(self):
        if os.geteuid() == 0:
            self.skipTest("host test requires a nonroot caller")
        result = subprocess.run([str(self.launcher), "1000", "1000", "/bin/true"],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires root", result.stderr)

    def test_launcher_does_not_exec_when_namespace_forbids_group_drop(self):
        if not shutil.which("unshare"):
            self.skipTest("unshare is unavailable")
        namespace = ["unshare", "--user", "--map-root-user"]
        available = subprocess.run([*namespace, "/bin/cat", "/proc/self/setgroups"],
                                   capture_output=True, text=True)
        if available.returncode or available.stdout.strip() != "deny":
            self.skipTest("a user namespace denying setgroups is unavailable")
        sentinel = self.base / "executed"
        result = subprocess.run([
            *namespace, str(self.launcher),
            "1234", "2345", "/bin/touch", str(sentinel),
        ], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("clear supplementary groups", result.stderr)
        self.assertFalse(sentinel.exists())

    def test_shell_syntax(self):
        for path in (ROOT / "runtime").glob("*.sh"):
            subprocess.run(["/bin/sh", "-n", str(path)], check=True)

    def test_lock_ipv4_ipv6_multiple_cidrs(self):
        result = self.run_lock("192.0.2.0/24, 198.51.100.0/24, fd00::/64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ip6 saddr fd00::/64 tcp dport 9091", result.stdout)
        self.assertEqual(result.stdout.count("tcp sport 9091 ct direction reply"), 3)
        self.assertEqual(result.stdout.count("policy drop"), 3)
        self.assertNotIn("flush ruleset", result.stdout)
        self.assertNotIn("related", result.stdout)
        self.assertLess(result.stdout.index("udp dport 53 drop"),
                        result.stdout.index('output oifname "lo" accept'))
        self.assertIn("hook output priority -150", result.stdout)

    def test_lock_rejects_empty_entries_injection_and_non_cidrs(self):
        for value in ("", "192.0.2.0/24,", ",192.0.2.0/24", "192.0.2.0/24,,fd00::/64",
                      "192.0.2.1", "192.0.2.0/24;accept", "192.0.2.0/24\n", "$(id)"):
            with self.subTest(value=value):
                self.assertNotEqual(self.run_lock(value).returncode, 0)

    def test_firewall_failure_never_launches_child_even_with_stale_marker(self):
        cmd = self.controller(nft_status=1)
        marker = self.base / "run/pia-transmission/ready"
        marker.parent.mkdir(parents=True)
        marker.touch()
        result = subprocess.run(cmd, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events.read_text(), "nft\n")
        self.assertFalse((self.base / "child-env").exists())

    def test_config_is_private_even_when_network_startup_fails(self):
        command = self.controller(nft_status=1)
        config = self.base / "config"
        config.mkdir(mode=0o755)
        settings = config / "settings.json"
        settings.write_text('{"speed-limit-up":73}')
        result = subprocess.run(command, env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.stat().st_mode & 0o777, 0o700)
        self.assertEqual(settings.read_text(), '{"speed-limit-up":73}')
        self.assertFalse((self.base / "child-env").exists())

    def test_docker_embedded_dns_upstreams_are_controller_only(self):
        command = self.controller(nft_status=1)
        (self.base / "resolv.conf").write_text(
            'nameserver 127.0.0.11\n'
            '# ExtServers: [192.0.2.1 1.1.1.1 host(127.0.0.53) 2001:db8::53]\n'
        )
        result = subprocess.run(command, env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        rules = (self.base / "run/pia-transmission/lock.nft").read_text()
        for address in ('127.0.0.11', '192.0.2.1', '1.1.1.1'):
            for protocol in ('udp', 'tcp'):
                self.assertIn(
                    f'meta skuid 0 ip daddr {address} {protocol} dport 53 '
                    'ct mark set 0x50494101 accept', rules)
        self.assertNotIn('127.0.0.53', rules)
        self.assertNotIn('2001:db8::53', rules)
        self.assertIn('output ip daddr 127.0.0.11 drop', rules)
        self.assertLess(rules.index('output udp dport 53 drop'),
                        rules.index('output oifname "lo" accept'))
        self.assertFalse((self.base / "child-env").exists())

    def test_docker_embedded_dns_invalid_upstream_fails_closed(self):
        command = self.controller()
        (self.base / "resolv.conf").write_text(
            'nameserver 127.0.0.11\n# ExtServers: [192.0.2.999]\n')
        result = subprocess.run(command, env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())
        self.assertFalse((self.base / "child-env").exists())

    def test_symlink_config_or_settings_is_rejected_without_touching_target(self):
        command = self.controller()
        target = self.base / "untouched"
        target.mkdir(mode=0o755)
        original = target.stat()
        config = self.base / "config"
        config.symlink_to(target, target_is_directory=True)
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink directory", result.stderr)
        self.assertEqual(target.stat(), original)
        config.unlink()
        config.mkdir()
        (config / "settings.json").symlink_to(target)
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlink settings", result.stderr)
        self.assertEqual(target.stat(), original)
        self.assertFalse(self.events.exists())

    def test_invalid_configuration_never_launches_child(self):
        for changes in ({"PUID": "0"}, {"PGID": "0"}, {"PUID": ""},
                        {"TRANSMISSION_RPC_PORT": "9092"}, {"WEB_BIND_IP": ""},
                        {"LOCAL_NETWORK": "bad;accept"}):
            with self.subTest(changes=changes):
                # New harness per case to avoid sharing previous command output.
                if (self.base / "runtime").exists():
                    shutil.rmtree(self.base / "runtime")
                result = subprocess.run(self.controller(), env=dict(self.env, **changes),
                                        capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.events.exists())

    def test_startup_order_environment_and_exit_status(self):
        result = subprocess.run(self.controller(), env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 23)
        self.assertEqual(self.events.read_text().splitlines(), ["nft", "launch:1234:2345"])
        child_env = (self.base / "child-env").read_text()
        self.assertNotIn("CONTROLLER_SECRET", child_env)
        self.assertNotIn("LOCAL_NETWORK", child_env)
        self.assertIn("WEB_BIND_IP=192.0.2.10\n", child_env)
        self.assertIn(f"HOME={self.base}/config", child_env)
        self.assertEqual((self.base / "run/secrets").stat().st_mode & 0o777, 0o700)

    def test_clean_unsolicited_child_exit_is_failure(self):
        result = subprocess.run(self.controller(child_body="exit 0"), env=self.env,
                                capture_output=True)
        self.assertEqual(result.returncode, 1)

    def test_web_ui_selections_forward_only_packaged_paths(self):
        command = self.controller()
        choices = {"transmission-web": "web-ui/transmission-web",
                   "transmission-web-legacy": "web-ui/transmission-web-legacy",
                   "transmission-default": "public_html"}
        for choice, directory in choices.items():
            with self.subTest(choice=choice):
                result = subprocess.run(command, env=dict(self.env, TRANSMISSION_WEB_UI=choice,
                                          TRANSMISSION_WEB_HOME="/config/attacker", NODE_OPTIONS="unsafe"),
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 23, result.stderr)
                child_env = (self.base / "child-env").read_text()
                self.assertIn(f"TRANSMISSION_WEB_HOME={self.base}/usr/share/transmission/{directory}\n", child_env)
                self.assertNotIn("attacker", child_env)
                self.assertNotIn("NODE_OPTIONS", child_env)
                self.assertNotIn("TRANSMISSION_WEB_UI=", child_env)

    def test_invalid_web_ui_fails_before_persistent_directory_changes(self):
        command = self.controller()
        for choice in ("", "official", "../public_html", "$(id)", "transmission-web;id"):
            with self.subTest(choice=choice):
                result = subprocess.run(command, env=dict(self.env, TRANSMISSION_WEB_UI=choice),
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("TRANSMISSION_WEB_UI must be", result.stderr)
                self.assertFalse(self.events.exists())
                self.assertFalse((self.base / "config").exists())
                self.assertFalse((self.base / "data").exists())

    def test_missing_web_ui_assets_fail_closed(self):
        command = self.controller()
        (self.base / "usr/share/transmission/web-ui/transmission-web/index.html").unlink()
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("assets are missing", result.stderr)
        self.assertFalse(self.events.exists())

    def test_leading_zero_ids_are_normalized_before_routing_and_launch(self):
        result = subprocess.run(self.controller(), env=dict(self.env, PUID="001234", PGID="002345"),
                                capture_output=True)
        self.assertEqual(result.returncode, 23)
        self.assertIn("launch:1234:2345", self.events.read_text())

    def test_term_is_forwarded_and_child_reaped(self):
        # exec ensures the controller signals its actual direct child.
        child = self.command("child", f'''
trap 'echo stopped >> "{self.events}"; exit 0' TERM
echo running >> "{self.events}"
while :; do sleep 0.1; done
''')
        cmd = self.controller(child_body=f'exec {child}')
        with subprocess.Popen(cmd, env=self.env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as process:
            self.addCleanup(lambda: process.kill() if process.poll() is None else None)
            deadline = time.monotonic() + 5
            while not self.events.exists() or "running" not in self.events.read_text():
                if time.monotonic() > deadline:
                    self.fail("child did not start")
                time.sleep(0.02)
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, stderr)
        self.assertIn("stopped", self.events.read_text())

    def prepare_settings(self, existing=None, overrides=None):
        config = self.base / "config"
        config.mkdir(exist_ok=True)
        settings = config / "settings.json"
        if existing is not None:
            settings.write_text(existing if isinstance(existing, str) else json.dumps(existing))
        daemon = self.command("daemon", f'echo daemon >> "{self.events}"')
        source = (ROOT / "runtime/start-transmission.sh").read_text()
        source = source.replace("/config", str(config))
        source = source.replace("/usr/bin/transmission-daemon", str(daemon))
        script = self.base / "prepare.sh"
        script.write_text(source)
        env = dict(self.env)
        for key in ("TRANSMISSION_DOWNLOAD_DIR", "TRANSMISSION_INCOMPLETE_DIR",
                    "TRANSMISSION_INCOMPLETE_DIR_ENABLED"):
            env.pop(key, None)
        env.update(overrides or {})
        result = subprocess.run(["/bin/sh", str(script)], env=env,
                                capture_output=True, text=True)
        return result, settings

    def test_new_settings_have_contract_defaults(self):
        result, settings = self.prepare_settings()
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(settings.read_text())
        self.assertEqual(values["rpc-port"], 9091)
        self.assertEqual(values["download-dir"], "/data/complete")
        self.assertEqual(values["incomplete-dir"], "/data/incomplete")
        self.assertIs(values["incomplete-dir-enabled"], True)
        self.assertEqual(settings.stat().st_mode & 0o777, 0o600)
        self.assertEqual(values["umask"], 0o077)

    def test_host_whitelist_overrides_unsafe_persisted_settings(self):
        for host in ("192.0.2.10", "198.51.100.20"):
            with self.subTest(host=host):
                result, settings = self.prepare_settings(
                    {"rpc-host-whitelist-enabled": False, "rpc-host-whitelist": "*",
                     "rpc-authentication-required": True, "rpc-username": "user",
                     "rpc-password": "{persisted-hash}"},
                    {"WEB_BIND_IP": host})
                self.assertEqual(result.returncode, 0, result.stderr)
                values = json.loads(settings.read_text())
                self.assertIs(values["rpc-host-whitelist-enabled"], True)
                self.assertEqual(values["rpc-host-whitelist"], host)
                self.assertIs(values["rpc-authentication-required"], True)
                self.assertEqual(values["rpc-username"], "user")
                self.assertEqual(values["rpc-password"], "{persisted-hash}")

    def test_daemon_umask_overrides_persisted_values(self):
        for mask in (0, 0o022, 0o077):
            with self.subTest(mask=mask):
                result, settings = self.prepare_settings({"umask": mask, "speed-limit-up": 73})
                self.assertEqual(result.returncode, 0, result.stderr)
                values = json.loads(settings.read_text())
                self.assertEqual(values["umask"], 0o077)
                self.assertEqual(values["speed-limit-up"], 73)
                self.assertEqual(settings.stat().st_mode & 0o777, 0o600)

    def test_explicit_overrides_preserve_other_settings(self):
        result, settings = self.prepare_settings(
            {"peer-port": 54321, "rpc-authentication-required": True,
             "download-dir": "/existing", "incomplete-dir-enabled": True},
            {"TRANSMISSION_DOWNLOAD_DIR": "/new", "TRANSMISSION_INCOMPLETE_DIR_ENABLED": "false"})
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads(settings.read_text())
        self.assertEqual(values["download-dir"], "/new")
        self.assertEqual(values["peer-port"], 54321)
        self.assertIs(values["rpc-authentication-required"], True)
        self.assertIs(values["incomplete-dir-enabled"], False)

    def test_absent_overrides_preserve_persisted_values(self):
        result, settings = self.prepare_settings({"download-dir": "/existing",
                                                  "incomplete-dir-enabled": False})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(settings.read_text())["download-dir"], "/existing")
        self.assertIs(json.loads(settings.read_text())["incomplete-dir-enabled"], False)

    def test_invalid_settings_or_boolean_preserve_original_and_do_not_start(self):
        for original, overrides in (("broken", {}), ("[]", {}),
                                    ('{"peer-port":12345}', {"TRANSMISSION_INCOMPLETE_DIR_ENABLED": "yes"})):
            with self.subTest(original=original, overrides=overrides):
                result, settings = self.prepare_settings(original, overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(settings.read_text(), original)
                self.assertFalse(self.events.exists())
                self.assertEqual(list(settings.parent.glob(".settings.*")), [])


if __name__ == "__main__":
    unittest.main()
