"""Run the existing suite on local Docker; keep evidence private, not fixture parents."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


def private_write(path, value):
    """Atomic mode-0600 output without changing the process/fixture umask."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(json.dumps(value, indent=2) + '\n')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def local_engine(run=subprocess.run):
    # Inspecting context metadata does not connect to the endpoint. Refuse remote
    # endpoints BEFORE issuing any engine command; never change the default.
    endpoint = json.loads(run(['docker', 'context', 'inspect', 'default', '--format',
                              '{{json .Endpoints.docker.Host}}'], check=True,
                             capture_output=True, text=True, timeout=15).stdout)
    if not endpoint.startswith('unix://'):
        raise RuntimeError('default must select a local Unix-socket Docker engine')
    version = json.loads(run(['docker', '--context', 'default', 'version', '--format',
                             '{{json .Server}}'], check=True, capture_output=True,
                            text=True, timeout=15).stdout)
    if version.get('Os') != 'linux':
        raise RuntimeError('local tests require a Linux Docker engine')
    return {'context': 'default', 'endpoint': endpoint, 'server': version}


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def run_suite(suite, directory, engine):
    rows = {test.id(): {'test': test.id(), 'status': 'NOT RUN', 'started_at': None,
                        'completed_at': None} for test in flatten(suite)}

    def save():
        private_write(directory / 'test-results.json', {'scope': 'local Docker; fixture PIA APIs',
                      'engine': engine, 'tests': list(rows.values())})

    class Result(unittest.TextTestResult):
        def startTest(self, test):
            super().startTest(test)
            self.began = time.monotonic()
            rows[test.id()]['started_at'] = stamp()
            save()

        def record(self, test, status, error=None, reason=None):
            row = rows.setdefault(test.id(), {'test': test.id(), 'started_at': None})
            row.update(status=status, completed_at=stamp())
            if reason:
                row['reason'] = reason
            if error:
                row.update(exception_type=error[0].__name__, diagnostic=self._exc_info_to_string(error, test))
                if isinstance(error[1], (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
                    row.update(command=error[1].cmd,
                               stdout=decode(error[1].stdout), stderr=decode(error[1].stderr))
            save()

        def stopTest(self, test):
            row = rows[test.id()]
            row.update(completed_at=stamp(), duration_seconds=time.monotonic() - self.began)
            save()
            super().stopTest(test)

        def addSuccess(self, test):
            super().addSuccess(test)
            self.record(test, 'PASS')

        def addFailure(self, test, error):
            super().addFailure(test, error)
            self.record(test, 'FAIL', error)

        def addError(self, test, error):
            super().addError(test, error)
            status = 'TIMEOUT' if isinstance(error[1], (TimeoutError, subprocess.TimeoutExpired)) else 'FAIL'
            self.record(test, status, error)

        def addSkip(self, test, reason):
            super().addSkip(test, reason)
            self.record(test, 'NOT RUN', reason=reason)

        def addSubTest(self, test, subtest, error):
            super().addSubTest(test, subtest, error)
            if error:
                self.record(test, 'FAIL', error)

    save()
    began, started = time.monotonic(), stamp()
    # mkstemp protects the log before unittest writes anything, irrespective of
    # the ordinary fixture umask inherited from the caller.
    fd, temporary = tempfile.mkstemp(prefix='.unittest-', dir=directory)
    try:
        with os.fdopen(fd, 'w') as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=Result).run(suite)
        os.replace(temporary, directory / 'unittest.log')
    finally:
        Path(temporary).unlink(missing_ok=True)
    summary = {'result': 'PASS' if result.wasSuccessful() else 'FAIL', 'started_at': started,
               'completed_at': stamp(), 'duration_seconds': time.monotonic() - began,
               'tests_run': result.testsRun, 'failures': len(result.failures),
               'errors': len(result.errors), 'skips': len(result.skipped),
               'context': engine['context'], 'endpoint': engine['endpoint']}
    private_write(directory / 'suite-summary.json', summary)
    return summary


def decode(value):
    return value.decode(errors='replace') if isinstance(value, bytes) else value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--test', action='append', help='test module/class/method; default: mandatory discovery')
    args = parser.parse_args()
    directory = args.evidence_dir.resolve()
    directory.mkdir(mode=0o700)  # Never overwrite an earlier run.
    directory.chmod(0o700)
    engine = local_engine()
    private_write(directory / 'local-engine-proof.json', engine)
    os.environ['PIA_TEST_DOCKER_CONTEXT'] = 'default'
    os.environ['PIA_RUN_CONTAINER_TESTS'] = '1'
    os.environ.pop('PIA_TEST_IMAGE', None)
    sys.path.insert(0, str(ROOT / 'tests'))
    suite = (unittest.defaultTestLoader.loadTestsFromNames(args.test) if args.test
             else unittest.defaultTestLoader.discover(str(ROOT / 'tests')))
    summary = run_suite(suite, directory, engine)
    print(json.dumps(summary), flush=True)
    raise SystemExit(summary['result'] != 'PASS')


if __name__ == '__main__':
    main()
