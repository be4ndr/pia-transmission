#!/usr/bin/env python3
"""Build pinned upstream assets plus the local patch in a new disposable directory."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parent
COMMIT = "b8e3ff39c9ebeef07bf196ce4bb3ff9236f632f1"
SOURCE_SHA256 = "4fab7668c98a2606c301a48b8d67fea8b14a39f62b813f4850be521affcb8bf1"
SOURCE_URL = f"https://api.github.com/repos/jianxcao/transmission-web/tarball/{COMMIT}"


def run(*args, cwd):
    return subprocess.run(args, cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="new working directory, preferably under /tmp")
    parser.add_argument("--source-archive", type=Path, help="reuse an archive; checksum still enforced")
    parser.add_argument("--baseline", action="store_true", help="build unmodified upstream for comparison")
    args = parser.parse_args()
    work = args.directory.resolve()
    work.mkdir(parents=True, exist_ok=False)
    archive = work / "upstream.tar.gz"
    if args.source_archive:
        archive.write_bytes(args.source_archive.read_bytes())
    else:
        urllib.request.urlretrieve(SOURCE_URL, archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise RuntimeError("upstream source checksum mismatch")
    with tarfile.open(archive) as source:
        source.extractall(work / "source", filter="data")
    checkout, = (work / "source").iterdir()
    patch = ROOT / "compatibility.patch"
    if not args.baseline:
        run("git", "apply", "--check", str(patch), cwd=checkout)
        run("git", "apply", str(patch), cwd=checkout)
    pnpm = ROOT / "node_modules/.bin/pnpm"
    if not pnpm.exists():
        raise RuntimeError("run npm ci in webui/transmission-web first")
    run(str(pnpm), "install", "--frozen-lockfile", "--registry=https://registry.npmjs.org",
        "--store-dir=" + str(work / "pnpm-store"), cwd=checkout)
    # Vite loads this alongside the pinned upstream production environment.
    (checkout / ".env.production.local").write_text("VITE_BASE_URL=/transmission/web\n")
    run(str(pnpm), "run", "build", cwd=checkout)
    assets = checkout / "dist"
    provenance = {
        "upstream_commit": COMMIT,
        "source_sha256": SOURCE_SHA256,
        "patch_sha256": None if args.baseline else hashlib.sha256(patch.read_bytes()).hexdigest(),
        "pnpm_lock_sha256": hashlib.sha256((checkout / "pnpm-lock.yaml").read_bytes()).hexdigest(),
        "node": subprocess.check_output(["node", "--version"], text=True).strip(),
        "pnpm": subprocess.check_output([str(pnpm), "--version"], text=True).strip(),
        "assets": {
            str(p.relative_to(assets)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(assets.rglob("*")) if p.is_file()
        },
    }
    (work / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Assets: {assets}")
    print(f"Provenance: {work / 'provenance.json'}")


if __name__ == "__main__":
    main()
