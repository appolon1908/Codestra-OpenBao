#!/usr/bin/env bash
set -Eeuo pipefail

output="${1:?usage: capture_ssh_baseline.sh OUTPUT.json}"
[[ ! -e "$output" ]] || {
  echo 'SSH baseline output already exists; refusing to overwrite it.' >&2
  exit 2
}
umask 077
tmp="${output}.partial.$PPID"
trap 'find "$tmp" -type f -delete 2>/dev/null || true' EXIT

python3 - "$tmp" <<'PY'
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


paths = [Path('/etc/ssh/sshd_config')]
paths.extend(sorted(Path('/etc/ssh/sshd_config.d').glob('*')) if Path('/etc/ssh/sshd_config.d').is_dir() else [])
paths.extend(sorted(Path('/root/.ssh').glob('authorized_keys*')) if Path('/root/.ssh').is_dir() else [])

effective = subprocess.run(['sshd', '-T'], check=False, capture_output=True)
if effective.returncode != 0:
    raise SystemExit('cannot read effective SSH configuration')

firewall_commands = [
    ['nft', '--stateless', 'list', 'ruleset'],
    ['iptables-save'],
    ['ip6tables-save'],
]
firewall = []
for command in firewall_commands:
    try:
        result = subprocess.run(command, check=False, capture_output=True)
    except FileNotFoundError:
        continue
    if result.returncode == 0:
        ssh_lines = []
        for line in result.stdout.splitlines():
            lowered = line.lower()
            if command[0] == 'nft':
                matches = (
                    b'tcp dport 22' in lowered or b'udp dport 22' in lowered or
                    b'tcp sport 22' in lowered or b'udp sport 22' in lowered
                )
            else:
                tokens = lowered.split()
                matches = any(
                    tokens[index] in {b'--dport', b'--sport', b'--dports', b'--sports'} and
                    b'22' in tokens[index + 1].split(b',')
                    for index in range(len(tokens) - 1)
                )
            if matches:
                ssh_lines.append(line.strip())
        normalized = b'\n'.join(ssh_lines)
        firewall.append({
            'command': command[0],
            'sshRuleSha256': hashlib.sha256(normalized).hexdigest(),
        })

document = {
    'schemaVersion': 1,
    'capturedAt': datetime.now(timezone.utc).isoformat(),
    'files': [
        {'path': str(path), 'sha256': digest(path)}
        for path in paths
        if path.is_file()
    ],
    'effectiveSshdSha256': hashlib.sha256(effective.stdout).hexdigest(),
    'firewall': firewall,
}
Path(sys.argv[1]).write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
PY
chmod 400 "$tmp"
mv "$tmp" "$output"
trap - EXIT
echo 'SSH_BASELINE_CAPTURED=YES'
echo 'SSH_CHANGED=NO'
