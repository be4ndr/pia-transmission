"""Focused PF state-machine checks with mocked provider/RPC/nft/sleep.
The Docker suite separately verifies real daemon RPC and kernel ingress rules.
"""
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PortForwardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pia-pf-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / 'state'
        self.bin = self.base / 'bin'
        self.secrets = self.base / 'secrets'
        for p in (self.state, self.bin, self.secrets):
            p.mkdir(mode=0o700)
        for name, value in [('ready', 'generation-one'), ('pf-supported', 'true'),
                            ('pf-gateway', '10.8.0.1'), ('endpoint', '198.51.100.2 fixture-pia'),
                            ('pf-token', 'private-token-do-not-log')]:
            (self.state / name).write_text(value)
        self.lease(45678)
        self.command('nft', f'cat >> "{self.base}/nft"\n[ ! -f "{self.base}/nft-fail" ]')
        self.command('sleep', f'''echo "$1" >> '{self.base}/delays'
touch '{self.base}/paused'
while [ ! -f '{self.base}/resume' ]; do /bin/sleep .02; done
rm -f '{self.base}/resume' '{self.base}/paused'
''')
        self.command('pia-auth.sh', f"touch '{self.base}/refreshed'\nprintf 'refreshed-private-token' > '{self.state}/pf-token'")
        mock = self.bin / 'curl'
        mock.write_text('''#!/usr/bin/python3
import json,sys,pathlib
b=pathlib.Path(''' + repr(str(self.base)) + ''')
a=sys.argv[1:]
with (b/'argv').open('a') as f:f.write(json.dumps(a)+'\\n')
def arg(k): return a[a.index(k)+1] if k in a else None
url=a[-1]
if url.endswith('/getSignature'):
 if (b/'get-rate-limit').exists():print('429',end='');sys.exit(22)
 if (b/'reject-token').exists() and not (b/'refreshed').exists():print('403',end='');sys.exit(22)
 if (b/'get-fail').exists():sys.exit(28)
 if (b/'server-error').exists():print('503',end='');sys.exit(22)
 pathlib.Path(arg('--output')).write_text((b/'lease').read_text())
 if (b/'change-generation').exists(): (b/'state/ready').write_text('generation-two')
elif url.endswith('/bindPort'):
 if (b/'bind-http-reject').exists():print('403',end='');sys.exit(22)
 if (b/'server-error').exists():print('503',end='');sys.exit(22)
 with (b/'bindings').open('a') as f:f.write(next(x for x in a if x.startswith('payload@'))+'\\n')
 pathlib.Path(arg('--output')).write_text(json.dumps({'status':'ERROR' if (b/'bind-fail').exists() else 'OK'}))
elif url.endswith('/transmission/rpc'):
 request=json.loads(pathlib.Path(arg('--data-binary')[1:]).read_text())
 headers=pathlib.Path(arg('--header')[1:]).read_text()
 if (b/'rpc-fail').exists():code='401'; response={}
 elif 'X-Transmission-Session-Id:' not in headers:
  code='409'; response={}
 else:
  code='200'
  if request['method']=='session-set':
   (b/'peer-port').write_text(str(request['arguments']['peer-port']))
   response={'result':'success'}
  else:
   response={'result':'success','arguments':{'peer-port':int((b/'peer-port').read_text()),'peer-port-random-on-start':False,'port-forwarding-enabled':False}}
   if (b/'rpc-readback-mismatch').exists():
    key=(b/'rpc-readback-mismatch').read_text()
    response['arguments'][key]=12345 if key=='peer-port' else True
  if (b/'rpc-result-error').exists():response={'result':'invalid argument'}
 pathlib.Path(arg('--dump-header')).write_text('X-Transmission-Session-Id: fixtureSession123\\r\\n')
 pathlib.Path(arg('--output')).write_text(json.dumps(response));print(code,end='')
else:sys.exit(22)
''')
        mock.chmod(0o755)
        source = (ROOT / 'runtime/port-forward.sh').read_text()
        source = source.replace('/run/pia-transmission', str(self.state)).replace('/run/secrets', str(self.secrets))
        source = source.replace('/usr/local/lib/pia-transmission', str(self.bin)).replace('curl -q', str(mock) + ' -q')
        self.worker = self.bin / 'port-forward.sh'
        self.worker.write_text(source)
        self.worker.chmod(0o755)
        self.processes = []
        self.addCleanup(self.stop_all)

    def command(self, name, body):
        p = self.bin / name
        p.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
        p.chmod(0o755)

    def lease(self, port, expires='2099-01-01T00:00:00Z'):
        payload = base64.b64encode(json.dumps({'port':port,'expires_at':expires,'token':'payload-private-token'}).encode()).decode()
        self.payload = payload
        (self.base / 'lease').write_text(json.dumps({'status':'OK','payload':payload,'signature':'cHJpdmF0ZS1zaWduYXR1cmU='}))

    def start(self, generation='generation-one'):
        p = subprocess.Popen([str(self.worker), generation], env=dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH']), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.processes.append(p)
        self.wait(lambda:(self.base/'paused').exists() or p.poll() is not None)
        return p

    def wait(self, condition):
        deadline = time.monotonic()+5
        while time.monotonic()<deadline:
            if condition():return
            time.sleep(.02)
        self.fail('worker did not reach expected state')

    def step(self):
        (self.base/'paused').unlink(missing_ok=True)
        (self.base/'resume').touch()
        self.wait(lambda:(self.base/'paused').exists())

    def stop_all(self):
        for p in self.processes:
            if p.poll() is None:p.terminate()
            out,err=p.communicate(timeout=5)
            for secret in ['private-token-do-not-log','payload-private-token',self.payload,'cHJpdmF0ZS1zaWduYXR1cmU=']:
                self.assertNotIn(secret,out+err)

    def test_obtain_bind_sync_and_renew_without_secret_arguments(self):
        self.start()
        self.assertEqual((self.state/'pf-active').read_text().strip(),'45678')
        self.assertEqual((self.base/'peer-port').read_text(),'45678')
        self.assertEqual((self.base/'delays').read_text().strip(),'900')
        argv=(self.base/'argv').read_text()
        for secret in ['private-token-do-not-log',self.payload,'cHJpdmF0ZS1zaWduYXR1cmU=']:
            self.assertNotIn(secret,argv)
        self.assertIn('--interface',argv)
        self.assertIn('--cacert',argv)
        self.assertIn('fixture-pia:19999:10.8.0.1:19999',argv)
        self.step()
        self.assertEqual(len((self.base/'bindings').read_text().splitlines()),2)
        self.assertEqual(argv.count('/getSignature'),1)

    def test_server_error_does_not_refresh_auth_or_discard_cached_lease(self):
        (self.state/'pf-lease.json').write_text((self.base/'lease').read_text())
        (self.base/'server-error').touch()
        self.start()
        self.assertTrue((self.state/'pf-lease.json').exists())
        self.assertFalse((self.base/'refreshed').exists())
        self.assertFalse((self.state/'pf-active').exists())
        (self.base/'server-error').unlink()
        self.step()
        self.assertEqual((self.state/'pf-active').read_text().strip(),'45678')

    def test_pf_api_rate_limit_does_not_refresh_auth_token(self):
        (self.base/'get-rate-limit').touch()
        self.start()
        self.assertEqual((self.base/'delays').read_text().strip(),'300')
        self.assertFalse((self.base/'refreshed').exists())
        self.assertFalse((self.state/'pf-active').exists())

    def test_token_api_rate_limit_backs_off_without_opening_port(self):
        (self.base/'reject-token').touch()
        self.command('pia-auth.sh', 'exit 75')
        self.start()
        self.assertEqual((self.base/'delays').read_text().strip(),'300')
        self.assertFalse((self.state/'pf-active').exists())

    def test_transport_failure_does_not_reauthenticate(self):
        (self.base/'get-fail').touch()
        self.start()
        self.assertFalse((self.base/'refreshed').exists())
        self.assertFalse((self.state/'pf-active').exists())

    def test_expired_api_token_refreshes_without_modifying_vpn_auth(self):
        (self.base/'reject-token').touch()
        (self.state/'auth').write_text('existing-vpn-auth')
        self.start()
        self.assertTrue((self.base/'refreshed').exists())
        self.assertEqual((self.state/'auth').read_text(),'existing-vpn-auth')
        self.assertEqual((self.state/'pf-status').read_text().strip(),'active')

    def test_bind_failure_closes_only_pf_and_recovers(self):
        (self.base/'bind-fail').touch()
        self.start()
        self.assertFalse((self.state/'pf-active').exists())
        self.assertIn('flush chain inet pia_transmission vpn_forward',(self.base/'nft').read_text())
        self.assertNotIn('vpn_traffic',(self.base/'nft').read_text())
        self.assertEqual((self.base/'delays').read_text().strip(),'60')
        (self.base/'bind-fail').unlink()
        self.step()
        self.assertEqual((self.state/'pf-active').read_text().strip(),'45678')

    def test_http_rejected_cached_lease_is_reacquired(self):
        (self.state/'pf-lease.json').write_text((self.base/'lease').read_text())
        (self.base/'bind-http-reject').touch()
        self.start()
        self.assertFalse((self.state/'pf-lease.json').exists())
        self.assertFalse((self.state/'pf-active').exists())
        (self.base/'bind-http-reject').unlink()
        self.lease(45681)
        self.step()
        self.assertEqual((self.state/'pf-active').read_text().strip(),'45681')

    def test_rpc_failure_never_opens_ingress_and_recovers(self):
        (self.base/'rpc-fail').touch()
        self.start()
        self.assertNotIn('accept',(self.base/'nft').read_text())
        self.assertEqual((self.base/'delays').read_text().strip(),'60')
        (self.base/'rpc-fail').unlink()
        self.step()
        self.assertIn('tcp dport 45678',(self.base/'nft').read_text())

    def test_rpc_success_requires_matching_port_and_disabled_mapping(self):
        for key in ('peer-port', 'peer-port-random-on-start', 'port-forwarding-enabled'):
            with self.subTest(key=key):
                (self.base/'rpc-readback-mismatch').write_text(key)
                self.start()
                self.assertFalse((self.state/'pf-active').exists())
                self.assertNotIn('accept', (self.base/'nft').read_text())
                self.assertEqual((self.base/'delays').read_text().splitlines()[-1], '5')
                self.stop_all(); self.processes.clear()
                (self.base/'paused').unlink(missing_ok=True)

    def test_rpc_http_success_with_method_error_leaves_ingress_closed(self):
        (self.base/'rpc-result-error').touch()
        self.start()
        self.assertFalse((self.state/'pf-active').exists())
        self.assertNotIn('accept', (self.base/'nft').read_text())
        (self.base/'rpc-result-error').unlink()
        self.step()
        self.assertEqual((self.state/'pf-active').read_text().strip(), '45678')

    def test_generation_change_during_request_does_not_apply_old_port(self):
        (self.base/'change-generation').touch()
        self.start()
        self.assertFalse((self.base/'peer-port').exists())
        self.assertFalse((self.state/'pf-active').exists())
        self.assertNotIn('accept',(self.base/'nft').read_text())

    def test_new_gateway_reuses_valid_lease_and_rebinds(self):
        (self.state/'pf-lease.json').write_text((self.base/'lease').read_text())
        (self.state/'pf-gateway').write_text('10.9.0.1')
        (self.state/'endpoint').write_text('198.51.100.3 other-server')
        self.start()
        argv=(self.base/'argv').read_text()
        self.assertNotIn('/getSignature',argv)
        self.assertIn('other-server:19999:10.9.0.1:19999',argv)
        self.assertEqual((self.state/'pf-active').read_text().strip(),'45678')

    def test_expired_lease_is_replaced(self):
        self.lease(45679,'2000-01-01T00:00:00+00:00')
        (self.state/'pf-lease.json').write_text((self.base/'lease').read_text())
        self.lease(45680)
        self.start()
        self.assertEqual((self.state/'pf-active').read_text().strip(),'45680')

    def test_unsupported_region_does_not_call_provider_or_rpc(self):
        (self.state/'pf-supported').write_text('false')
        self.start()
        self.assertEqual((self.state/'pf-status').read_text().strip(),'unsupported')
        self.assertFalse((self.base/'argv').exists())

    def test_malformed_payload_reserved_rpc_port_and_bad_expiry_are_rejected(self):
        for port,expires in [(9091,'2099-01-01T00:00:00Z'),(0,'2099-01-01T00:00:00Z'),(65536,'2099-01-01T00:00:00Z'),('45678','2099-01-01T00:00:00Z'),(45678,'not-a-date')]:
            with self.subTest(port=port,expires=expires):
                self.lease(port,expires)
                self.start()
                self.assertFalse((self.state/'pf-active').exists())
                self.assertFalse((self.base/'peer-port').exists())
                self.stop_all();self.processes.clear()
                (self.base/'paused').unlink(missing_ok=True)

    def test_near_expiry_schedules_early_lease_replacement(self):
        expires = (datetime.now(timezone.utc)+timedelta(seconds=300)).strftime('%Y-%m-%dT%H:%M:%S.000+00:00')
        self.lease(45678, expires)
        self.start()
        self.assertGreaterEqual(int((self.base/'delays').read_text()),100)
        self.assertLessEqual(int((self.base/'delays').read_text()),120)

    def test_optional_rpc_authentication_stays_file_backed(self):
        (self.secrets/'transmission_rpc_username').write_text('rpc-user')
        (self.secrets/'transmission_rpc_password').write_text('rpc-password-sensitive')
        self.start()
        argv=(self.base/'argv').read_text()
        self.assertNotIn('rpc-password-sensitive',argv)
        header=(self.state/'pf/rpc-headers').read_text()
        self.assertIn('Authorization: Basic ',header)
        self.assertEqual((self.state/'pf/rpc-headers').stat().st_mode & 0o777,0o600)


if __name__ == '__main__':unittest.main()
