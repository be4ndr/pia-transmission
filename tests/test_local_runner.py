"""Offline permission/context regressions for the local unittest runner."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from run_local import local_engine, private_write, run_suite


class LocalRunnerTests(unittest.TestCase):
    def test_evidence_stays_private_without_changing_fixture_umask(self):
        for mask in [0o022, 0o077]:
            with self.subTest(mask=mask), tempfile.TemporaryDirectory() as folder:
                before = os.umask(mask)
                try:
                    root = Path(folder)
                    private_write(root / 'result.json', {'result': 'PASS'})
                    self.assertEqual(stat.S_IMODE((root / 'result.json').stat().st_mode), 0o600)
                    fixture = root / 'data'
                    fixture.mkdir()
                    self.assertEqual(stat.S_IMODE(fixture.stat().st_mode), 0o777 & ~mask)
                    current = os.umask(mask)
                    self.assertEqual(current, mask)
                finally:
                    os.umask(before)

    def test_atomic_evidence_replace_keeps_0600_and_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            other = root / 'unchanged'
            other.write_text('unchanged')
            target = root / 'result.json'
            target.symlink_to(other)
            private_write(target, {'result': 'PASS'})
            self.assertFalse(target.is_symlink())
            self.assertEqual(other.read_text(), 'unchanged')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_remote_endpoint_rejected_before_engine_access(self):
        for endpoint in ['ssh://forbidden-host', 'tcp://192.0.2.1:2375']:
            calls = []
            def fake(args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, json.dumps(endpoint), '')
            with self.subTest(endpoint=endpoint), self.assertRaises(RuntimeError):
                local_engine(fake)
            self.assertEqual(len(calls), 1)

    def test_local_engine_selection_is_explicit(self):
        calls = []
        def fake(args, **kwargs):
            calls.append(args)
            return subprocess.CompletedProcess(args, 0, json.dumps(
                'unix:///var/run/docker.sock' if 'inspect' in args else {'Os': 'linux'}), '')
        self.assertEqual(local_engine(fake)['context'], 'default')
        self.assertEqual(calls[1][:3], ['docker', '--context', 'default'])

    def test_suite_logs_are_private_and_failures_are_not_retried(self):
        calls = []
        class Fixture(unittest.TestCase):
            def runTest(self):
                calls.append(True)
                self.fail('expected injected fixture failure')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before = os.umask(0o022)
            try:
                summary = run_suite(unittest.TestSuite([Fixture()]), root,
                                    {'context': 'default', 'endpoint': 'unix:///var/run/docker.sock'})
            finally:
                current = os.umask(before)
            self.assertEqual(current, 0o022)
            self.assertEqual(calls, [True])
            self.assertEqual(summary['result'], 'FAIL')
            for path in root.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            row = json.loads((root / 'test-results.json').read_text())['tests'][0]
            self.assertEqual(row['status'], 'FAIL')
            self.assertIn('expected injected fixture failure', row['diagnostic'])


if __name__ == '__main__':
    unittest.main()
