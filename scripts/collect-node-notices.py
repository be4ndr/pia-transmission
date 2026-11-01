#!/usr/bin/env python3
"""Collect frontend dependency license identifiers and available notice texts."""
import json
from pathlib import Path
import sys

store, output = map(Path, sys.argv[1:3])
rows = []
manifests = list(store.glob('*/node_modules/*/package.json'))
manifests += list(store.glob('*/node_modules/@*/*/package.json'))
for manifest in manifests:
    package_dir = manifest.parent
    if package_dir.is_symlink():
        continue
    try:
        package = json.loads(manifest.read_text())
    except (OSError, json.JSONDecodeError):
        continue
    name, version = package.get('name'), package.get('version')
    if not name or not version:
        continue
    license_value = package.get('license', 'NOASSERTION')
    if isinstance(license_value, dict):
        license_value = license_value.get('type', 'NOASSERTION')
    files = sorted((p for p in package_dir.iterdir() if p.is_file() and
                    p.name.lower().startswith(('license', 'licence', 'notice', 'copying', 'copyright'))),
                   key=lambda p: p.name.lower())
    rows.append((name, version, str(license_value), files))
rows.sort(key=lambda row: (row[0], row[1]))
if not rows:
    raise SystemExit(f'no packages found under {store}')
output.parent.mkdir(parents=True, exist_ok=True)
with output.open('w') as result:
    result.write('Third-party frontend dependency notices\n')
    result.write('========================================\n\n')
    result.write('Each package keeps its own license; this file does not relicense them.\n\n')
    for name, version, license_value, files in rows:
        result.write(f'{name} {version} — declared license: {license_value}\n')
        if not files:
            result.write('No license/notice text file was present in the installed package.\n\n')
        for path in files:
            result.write(f'\n--- {name} {version}: {path.name} ---\n')
            result.write(path.read_text(errors='replace').rstrip() + '\n\n')
