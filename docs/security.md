# Security checks

Install [Gitleaks](https://github.com/gitleaks/gitleaks) v8.30.1 with Go 1.24+
into a directory on your PATH:

```sh
go install github.com/zricethezav/gitleaks/v8@v8.30.1
python3 scripts/scan-secrets.py working
# After git add, scan the complete index snapshot:
python3 scripts/scan-secrets.py staged
python3 scripts/scan-secrets.py history
```

The working scan includes tracked and unignored untracked files. The staged scan
checks the complete index, including the initial commit. The history scan checks
all reachable refs, including changes since removed from the working tree.
CI uses the same three commands with full Git history. Run them before committing
and repeat the history scan after committing.

Default Gitleaks rules remain enabled, plus a private-user-path rule. Findings
must be investigated. No project baseline, file exclusions, inline suppressions
or broad fixture allowlists are configured. Logs redact candidate values.
The scanner copies publication files into a temporary directory; ignored local
credentials, evidence and development context are outside its working-tree scope.
It rejects tracked/staged private-context directories. It is not an audit of your
ignored local credentials or a guarantee that every secret format is detectable.

Also review hostnames, IPs, mounts, URLs and Git author metadata manually. Public
provider endpoints, Docker/VPN defaults and synthetic test addresses have distinct
purposes; do not suppress all private-address patterns to silence findings.
Keep credentials outside the repository, and never stage `.local/` or package
workspace directories wholesale. If a real secret enters history, revoke it and
sanitize history before sharing any refs.
