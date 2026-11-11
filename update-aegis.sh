#!/usr/bin/env bash
# Aegis update helper. Download before running; requires Python 3.9+ and sudo.
set -euo pipefail
umask 077
aegis_update_dir="$(mktemp -d)"
trap 'rm -rf -- "$aegis_update_dir"' EXIT
cat > "$aegis_update_dir/update.py" <<'AEGIS_UPDATE_PYTHON'
"""Explicit updates from karanik.gr / Ενημέρωση μόνο με επιβεβαίωση.

TLS and a same-origin hash verify transfer integrity, not an independent release
signature. No downloaded shell/Python code runs before explicit authorization.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request

BASE='https://karanik.gr/scripts/linux/aegis-linux-hardener/'
INSTALL_URL=BASE+'install-aegis.sh'
UPDATE_URL=BASE+'update-aegis.sh'
MANIFEST_URL=BASE+'release.json'
TARGET=Path('/opt/aegis-linux-hardener')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        raise ValueError('Update redirects are not accepted; publish files at the configured URLs')


def fetch(url,limit):
    if url not in (INSTALL_URL,MANIFEST_URL):raise ValueError('Unapproved update URL')
    opener=urllib.request.build_opener(NoRedirect())
    request=urllib.request.Request(url,headers={'User-Agent':'Aegis-Updater/0.8.0','Cache-Control':'no-cache'})
    with opener.open(request,timeout=30) as response:
        if response.geturl()!=url:raise ValueError('Unexpected update destination')
        data=response.read(limit+1)
    if len(data)>limit:raise ValueError('Update download exceeds size limit')
    return data


def version_tuple(value):
    if not isinstance(value,str) or not re.fullmatch(r'\d{1,5}\.\d{1,5}\.\d{1,5}',value):raise ValueError('Invalid release version')
    return tuple(map(int,value.split('.')))


def metadata(data):
    record=json.loads(data)
    if not isinstance(record,dict) or record.get('schema')!=1:raise ValueError('Unsupported release metadata')
    version_tuple(record.get('version'))
    if record.get('installer_url')!=INSTALL_URL:raise ValueError('Unexpected installer URL')
    if not re.fullmatch(r'[a-f0-9]{64}',str(record.get('sha256',''))):raise ValueError('Missing installer SHA-256')
    return record


def verify(data,record):
    if hashlib.sha256(data).hexdigest()!=record['sha256']:raise ValueError('Installer checksum mismatch; nothing executed')
    marker=('# Aegis release: '+record['version']+'\n').encode()
    if not data.startswith(b'#!/usr/bin/env bash\n') or marker not in data[:1024]:raise ValueError('Installer release marker mismatch')


def run(confirm,current='0.0.0'):
    print('Update source: '+BASE)
    try:record=metadata(fetch(MANIFEST_URL,65536))
    except Exception as error:
        raise RuntimeError('Cannot check updates. Publish release.json and install-aegis.sh from the SAME release. '+str(error)) from error
    print('Installed/running: '+current+' | Available: '+record['version'])
    if version_tuple(record['version'])<=version_tuple(current):
        print('No newer release. Downgrades/reinstall are not performed by the updater.');return False
    print('Installer: '+INSTALL_URL+'\nSHA-256: '+record['sha256'])
    print('HTTPS + same-site checksum; no independent signing key is configured.')
    if not confirm('Download and verify this update?'):return False
    data=fetch(INSTALL_URL,32*1024*1024);verify(data,record)
    # A root-owned private temp file prevents substitution before privileged execution.
    if os.geteuid()!=0:raise RuntimeError('Run the updater with sudo. No installer was executed.')
    with tempfile.TemporaryDirectory(prefix='aegis-update-') as folder:
        path=Path(folder)/'install-aegis.sh';path.write_bytes(data);path.chmod(0o600)
        if not confirm('Install Aegis '+record['version']+'? Existing program backup/undo is kept.'):return False
        subprocess.run(['bash',str(path),'--check'],check=True)
        subprocess.run(['bash',str(path),'--install'],check=True)
        # Installer cancellation exits zero: inspect the published version before claiming success.
        if installed_version()!=record['version']:
            print('Update was cancelled or not published; running version remains unchanged.');return False
    print('Updated. Start a fresh session with: aegis');return True


def installed_version():
    try:
        source=(TARGET/'aegis/__init__.py').read_text()
        match=re.search(r"^VERSION\s*=\s*['\"]([0-9.]+)['\"]",source,re.M)
        return match.group(1) if match else '0.0.0'
    except OSError:return '0.0.0'


def standalone():
    import sys
    if os.geteuid()!=0:raise RuntimeError('Use: sudo bash update-aegis.sh')
    def confirm(label):
        value=input(label+' [Y/n, Enter=yes; q=cancel]: ').strip().lower()
        if value in ('q','/back','/cancel'):raise KeyboardInterrupt()
        return value in ('','y','yes')
    try:run(confirm,installed_version())
    except (KeyboardInterrupt,EOFError):print('\nCancelled.');return 20
    except Exception as error:print('Aegis update: '+str(error),file=sys.stderr);return 1
    return 0

raise SystemExit(standalone())
AEGIS_UPDATE_PYTHON
python3 "$aegis_update_dir/update.py" "$@"
