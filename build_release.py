#!/usr/bin/env python3
"""Rebuild the self-contained installer and a source ZIP. No network/system changes."""
import base64
import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
VERSION = '0.7.1'
EXCLUDED = {'install-aegis.sh', 'SHA256SUMS', 'release.json'}


def sources():
    return sorted(p for p in ROOT.rglob('*') if p.is_file() and p.name not in EXCLUDED
                  and '__pycache__' not in p.parts and p.suffix not in ('.pyc', '.zip', '.tar.gz'))


def main():
    updater = (ROOT / 'aegis/selfupdate.py').read_text()
    wrapper = '''#!/usr/bin/env bash
# Aegis update helper. Download before running; requires Python 3.9+ and sudo.
set -euo pipefail
umask 077
aegis_update_dir="$(mktemp -d)"
trap 'rm -rf -- "$aegis_update_dir"' EXIT
cat > "$aegis_update_dir/update.py" <<'AEGIS_UPDATE_PYTHON'
'''+updater+"\nraise SystemExit(standalone())\nAEGIS_UPDATE_PYTHON\npython3 \"$aegis_update_dir/update.py\" \"$@\"\n"
    (ROOT / 'update-aegis.sh').write_text(wrapper)
    memory = io.BytesIO()
    with tarfile.open(fileobj=memory, mode='w:gz') as archive:
        for path in sources():
            item = archive.gettarinfo(str(path), arcname=str(path.relative_to(ROOT)))
            item.uid = item.gid = 0
            item.uname = item.gname = 'root'
            item.mtime = 0
            item.mode = 0o644
            with path.open('rb') as source: archive.addfile(item, source)
    data = memory.getvalue()
    stage = (ROOT / 'install_stage.py').read_text().replace('__AEGIS_PAYLOAD__', base64.b64encode(data).decode()).replace('__AEGIS_DIGEST__', hashlib.sha256(data).hexdigest())
    header = '''#!/usr/bin/env bash
# Aegis release: __AEGIS_RELEASE_VERSION__
# Aegis Linux Hardener — self-contained installer. Download before running.
# EL: Πρώτα λήψη αρχείου, μετά sudo bash install-aegis.sh.
set -euo pipefail
if ! command -v python3 >/dev/null 2>&1; then
    echo 'Python 3.9+ is required. On Debian/Ubuntu: sudo apt install python3 ca-certificates' >&2
    exit 1
fi
python3 -c 'import sys,ssl,sqlite3,fcntl; sys.exit(0 if sys.version_info >= (3,9) else 1)' || {
    echo 'Python 3.9+ with ssl/sqlite3/fcntl is required. The system Python will not be replaced.' >&2
    exit 1
}
umask 022
aegis_temp_dir="$(mktemp -d)"
chmod 700 "$aegis_temp_dir"
trap 'rm -rf -- "$aegis_temp_dir"' EXIT
cat > "$aegis_temp_dir/install_stage.py" <<'AEGIS_INTERNAL_PYTHON_STAGE'
'''
    footer = '''AEGIS_INTERNAL_PYTHON_STAGE
python3 "$aegis_temp_dir/install_stage.py" "$@"
'''
    (ROOT / 'install-aegis.sh').write_text(header.replace('__AEGIS_RELEASE_VERSION__',VERSION) + stage + footer)
    (ROOT / 'release.json').write_text(json.dumps({'schema':1,'version':VERSION,
        'installer_url':'https://karanik.gr/scripts/linux/aegis-linux-hardener/install-aegis.sh',
        'sha256':hashlib.sha256((ROOT/'install-aegis.sh').read_bytes()).hexdigest()},indent=2)+'\n')
    files = sources() + [ROOT / 'install-aegis.sh', ROOT / 'release.json']
    (ROOT / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(ROOT)) + '\n' for p in files))
    output = ROOT.parent / ('aegis-linux-hardener-v' + VERSION + '.zip')
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in files + [ROOT / 'SHA256SUMS']:
            archive.write(path, 'aegis-linux-hardener/' + str(path.relative_to(ROOT)))
    assert zipfile.ZipFile(output).testzip() is None
    print('Created: ' + str(output))


if __name__ == '__main__': main()
