"""Verified-release clients / Εγκατάσταση μόνο επιλεγμένων upstream artifacts."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from . import system
from .actions import Plan, ENTRY

BINARY_REPOS={
 'bandwhich':('imsnif/bandwhich','bandwhich'), 'docker-dash':('GustavoCaso/docker-dash','docker-dash'),
 'dockmate':('shubh-io/DockMate','dockmate'), 'dtop':('amir20/dtop','dtop'),
 'fresh':('sinelaw/fresh','fresh'), 'lazyide':('TysonLabs/lazyide','lazyide'),
 'lazydocker':('jesseduffield/lazydocker','lazydocker'), 'microneo':('sollawen/microNeo','microneo'),
}


def asset_pattern(key,arch):
    if arch not in ('amd64','arm64'):raise ValueError('Upstream binary path supports amd64/arm64 only; inspect official build instructions.')
    x='x86_64' if arch=='amd64' else 'aarch64'
    specs={
      'bandwhich':r'bandwhich-.*-'+x+r'-unknown-linux-musl\.tar\.gz',
      'docker-dash':r'docker-dash_.*_linux-'+arch,
      'dockmate':r'dockmate-linux-'+arch,
      'dtop':r'dtop-'+x+r'-unknown-linux-gnu\.tar\.gz',
      'fresh':r'fresh-editor-'+x+r'-unknown-linux-musl\.tar\.gz',
      'lazyide':r'lazyide-linux-'+x+r'\.tar\.gz',
      'lazydocker':r'lazydocker_.*_Linux_'+('x86_64' if arch=='amd64' else 'arm64')+r'\.tar\.gz',
      'microneo':r'microneo-.*-'+('linux64' if arch=='amd64' else 'linux-arm64')+r'\.tar\.gz',
    }
    return specs[key]


def archive_binary(data,name,aliases=()):
    """Read only one regular executable. Never extract links, paths or scripts."""
    if data.startswith(b'\x7fELF'):return data
    matches=[]
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as archive:
        members=archive.getmembers()
        if len(members)>20000:raise ValueError('Archive has too many members')
        for item in members:
            p=PurePosixPath(item.name)
            if p.is_absolute() or '..' in p.parts:raise ValueError('Unsafe archive path')
            if p.name not in (name,)+tuple(aliases):continue
            if not item.isfile() or item.size>256*1024*1024:raise ValueError('Executable is not a bounded regular file')
            matches.append(archive.extractfile(item).read())
    if len(matches)!=1:raise ValueError('Expected exactly one executable named '+name+'; inspect upstream release layout.')
    return matches[0]


def validate_elf(data,arch):
    machine={'amd64':62,'arm64':183}.get(arch)
    if not machine or len(data)<20 or data[:4]!=b'\x7fELF' or data[4]!=2 or data[5]!=1 or struct.unpack('<H',data[18:20])[0]!=machine:
        raise ValueError('Artifact is not a matching 64-bit Linux ELF binary')


def verify_checksum(release,asset,data,repo,fetch):
    digest=hashlib.sha256(data).hexdigest()
    provided=asset.get('digest')
    if provided:
        if provided!='sha256:'+digest:raise ValueError('GitHub asset SHA256 mismatch')
        return digest,'GitHub asset SHA256 verified'
    names={a['name']:a for a in release.get('assets',[])}
    check=next((names[n] for n in (asset['name']+'.sha256',asset['name']+'.sha','checksums.txt','checksums.sha256','sha256.sum') if n in names),None)
    if check:
        url=check['browser_download_url']
        if not url.startswith('https://github.com/'+repo+'/releases/download/'):raise ValueError('Checksum URL outside expected upstream')
        text=fetch(url,4*1024*1024).decode()
        # Accept a single artifact-sidecar hash or a matching checksum manifest line.
        tokens=text.split()
        found=None
        if len(tokens)==1 and re.fullmatch(r'[0-9a-fA-F]{64}',tokens[0]):found=tokens[0]
        for line in text.splitlines():
            parts=line.split()
            if len(parts)>=2 and parts[-1].lstrip('*')==asset['name'] and re.fullmatch(r'[0-9a-fA-F]{64}',parts[0]):found=parts[0]
        if found is None or found.lower()!=digest:raise ValueError('Upstream checksum missing or mismatched for selected artifact')
        return digest,'Upstream SHA256 verified'
    return digest,'No upstream checksum supplied; HTTPS origin and displayed local SHA256 only'


def binary_plan(key):
    from .catalog import fetch
    arch=system.command(['dpkg','--print-architecture'])[1]
    if key=='ngrok':
        if arch not in ('amd64','arm64'):raise ValueError('Unsupported ngrok architecture')
        url='https://bin.ngrok.com/c/bNyj1mQVY4c/ngrok-v3-stable-linux-'+arch+'.tgz'
        data=fetch(url);name='ngrok';tag='v3-stable'
        digest=hashlib.sha256(data).hexdigest();verification='HTTPS vendor download; local SHA256 displayed (not an independent signature)'
    else:
        repo,name=BINARY_REPOS[key]
        release=json.loads(fetch('https://api.github.com/repos/'+repo+'/releases/latest',4*1024*1024))
        matches=[a for a in release.get('assets',[]) if re.fullmatch(asset_pattern(key,arch),a['name'])]
        if len(matches)!=1:raise ValueError('No unique Linux asset for this architecture. Inspect official releases; no guessed download is run.')
        asset=matches[0];url=asset['browser_download_url'];tag=release.get('tag_name','unknown')
        if not url.startswith('https://github.com/'+repo+'/releases/download/'):raise ValueError('Asset URL outside expected upstream repository')
        data=fetch(url);digest,verification=verify_checksum(release,asset,data,repo,fetch)
    binary=archive_binary(data,name,('micro',) if key=='microneo' else ())
    validate_elf(binary,arch)
    target='/usr/local/bin/'+name
    if Path(target).exists() or Path(target).is_symlink():raise ValueError('Destination exists; existing tool is left untouched: '+target)
    return Plan('Install '+key+' '+tag,writes={target:binary},modes={target:0o755},
                details=['Source: '+url,'Version: '+tag,'Archive SHA256: '+digest,verification,
                         'Installs one executable only. No vendor installer scripts, containers or public endpoints are started.',
                         'Runtime library compatibility is checked when the tool is first launched; install in a VM first.'])


def python_compatible(spec,version=None):
    current=tuple(version or sys.version_info[:3])
    for item in (spec or '').split(','):
        if not item.strip():continue
        match=re.fullmatch(r'\s*(>=|<=|==|!=|>|<)\s*(\d+(?:\.\d+){0,2})\s*',item)
        if not match:raise ValueError('Unrecognized Requires-Python expression: '+str(spec))
        op,target=match.groups();target=tuple(int(v) for v in target.split('.'));target=target+(0,)*(3-len(target))
        if not {'>=':current>=target,'<=':current<=target,'==':current==target,'!=':current!=target,'>':current>target,'<':current<target}[op]:return False
    return True


def python_plan(key,user):
    from .catalog import fetch
    if key not in ('rovr','hwinfo-tui'):raise ValueError('Unknown Python tool')
    account=pwd.getpwnam(user)
    if account.pw_uid<1000:raise ValueError('Run Aegis from a regular sudo-capable account for isolated Python tool installation.')
    info=json.loads(fetch('https://pypi.org/pypi/'+key+'/json',4*1024*1024))['info']
    version=info['version']
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+-]*',version):raise ValueError('Unexpected upstream version')
    if not python_compatible(info.get('requires_python')):raise ValueError(key+' needs Python '+str(info.get('requires_python'))+'. This host uses '+str(sys.version_info.major)+'.'+str(sys.version_info.minor)+'. The system interpreter will not be replaced.')
    dest='/opt/aegis-tools/'+key
    return Plan('Install '+key+' '+version+' (isolated environment)',
        details=['Official project uses Python package '+key+' from PyPI.',
                 'Requires-Python: '+str(info.get('requires_python')),
                 'Build/install executes as '+user+', then the environment becomes root-owned.',
                 'Dependency compatibility is resolved by pip; no changes to system Python packages.',
                 'hwinfo-tui reads Windows HWiNFO CSV files; it does not collect Linux sensors.' if key=='hwinfo-tui' else 'Local file manager; no network listener is enabled.'],
        before=[['apt-get','update'],['apt-get','install','python3-venv']],package_change=True,
        backup_paths=[dest,'/usr/local/bin/'+key],persist_runner=True,
        commands=[[sys.executable,str(ENTRY),'--python-tool',json.dumps({'key':key,'user':user,'version':version})]])


def install_python(data):
    """Root helper executes package build scripts under a regular UID, never root."""
    key,user,version=data['key'],data['user'],data['version']
    if key not in ('rovr','hwinfo-tui') or not re.fullmatch(r'[0-9][A-Za-z0-9.+-]*',version):raise ValueError('Invalid Python tool request')
    account=pwd.getpwnam(user)
    if account.pw_uid<1000:raise ValueError('Regular build account required')
    dest=Path('/opt/aegis-tools')/key
    if dest.exists() or dest.is_symlink():raise ValueError('Existing environment is left untouched')
    dest.mkdir(parents=True,mode=0o755)
    os.chown(dest,account.pw_uid,account.pw_gid)
    env=['runuser','-u',user,'--','env','HOME='+account.pw_dir,'PIP_DISABLE_PIP_VERSION_CHECK=1','PIP_NO_CACHE_DIR=1']
    try:
        subprocess.run(env+[sys.executable,'-m','venv',str(dest/'venv')],check=True)
        subprocess.run(env+[str(dest/'venv/bin/python'),'-m','pip','install',key+'=='+version],check=True)
        from .actions import write_file
        write_file('/usr/local/bin/'+key,'#!/bin/sh\nexec '+str(dest/'venv/bin'/key)+' "$@"\n',0o755)
    finally:
        # Keep user build artifacts from becoming a writable root-executed environment.
        for path in [dest]+list(dest.rglob('*')):
            os.chown(path,0,0,follow_symlinks=False)
            if not path.is_symlink():path.chmod(path.stat().st_mode & 0o755)
