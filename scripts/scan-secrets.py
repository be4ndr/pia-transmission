#!/usr/bin/env python3
"""Scan publication inputs with Gitleaks; private local state is never copied."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scope', choices=['working', 'staged', 'history'])
    args = parser.parse_args()
    scanner = os.environ.get('GITLEAKS', 'gitleaks')
    config = ROOT / '.gitleaks.toml'
    flags = ['--config', str(config), '--redact', '--no-banner',
             '--ignore-gitleaks-allow']
    indexed = git('ls-files', '-z').split(b'\0')
    for name in indexed:
        if name and Path(os.fsdecode(name)).parts[0] in {
                '.local', '.artifacts', '.aws', '.agents', '.codex'}:
            raise RuntimeError('private local directory is staged or tracked')
    if args.scope == 'history':
        subprocess.run([scanner, 'git', str(ROOT), '--log-opts=--all', *flags], check=True)
        return
    with tempfile.TemporaryDirectory(prefix='pia-publication-scan-') as folder:
        snapshot = Path(folder)
        if args.scope == 'staged':
            subprocess.run(['git', '-C', str(ROOT), 'checkout-index', '--all',
                            '--prefix=' + str(snapshot) + '/'], check=True)
        else:
            names = git('ls-files', '--cached', '--others', '--exclude-standard', '-z')
            for name in set(names.split(b'\0')) - {b''}:
                relative = Path(os.fsdecode(name))
                source = ROOT / relative
                if source.is_symlink():
                    raise RuntimeError('review symlink before publication: ' + str(relative))
                if not source.exists():  # Tracked file deleted in the working tree.
                    continue
                destination = snapshot / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        subprocess.run([scanner, 'dir', str(snapshot), *flags], check=True)


if __name__ == '__main__':
    main()
