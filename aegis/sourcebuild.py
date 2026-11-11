"""Pinned, checksum-verified netscanner source; isolated unprivileged Rust build."""
import hashlib
import io
import json
import os
from pathlib import Path,PurePosixPath
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
from . import system
from .actions import Plan,ENTRY,write_file
from .toolinstall import validate_elf

CACHE=Path('/var/cache/aegis-linux-hardener')
HOSTS={'amd64':'x86_64-unknown-linux-gnu','arm64':'aarch64-unknown-linux-gnu'}


def verified_source(version,checksum,data):
    if not re.fullmatch(r'\d+\.\d+\.\d+',version) or not re.fullmatch('[a-f0-9]{64}',checksum):raise ValueError('Invalid pinned source identity')
    if hashlib.sha256(data).hexdigest()!=checksum:raise ValueError('Source crate SHA256 mismatch')
    return data


def extract_source(data,version,destination):
    """No links/devices/escape paths or executable root scripts are extracted."""
    expected='netscanner-'+version;total=0
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
        members=archive.getmembers()
        if len(members)>10000:raise ValueError('Too many crate members')
        for item in members:
            path=PurePosixPath(item.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0]!=expected:raise ValueError('Unsafe source archive path')
            if not item.isdir() and not item.isfile():raise ValueError('Source links and special files are refused')
            total+=item.size
            if total>64*1024*1024:raise ValueError('Source archive exceeds size limit')
        for item in members:
            path=Path(destination).joinpath(*PurePosixPath(item.name).parts)
            if item.isdir():path.mkdir(parents=True,exist_ok=True)
            else:
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(archive.extractfile(item).read());path.chmod(0o644)
    source=Path(destination)/expected
    if not (source/'Cargo.lock').is_file():raise ValueError('Upstream crate has no lockfile; no unlocked build is run automatically.')
    return source


def run_user(args,account,environment,cwd):
    argv=list(args)
    env={**os.environ,**environment,'HOME':str(cwd/'home')}
    if os.geteuid()==0:
        argv=['runuser','-u',account.pw_name,'--','env']+[key+'='+value for key,value in environment.items()]+['HOME='+str(cwd/'home')]+argv
    elif os.geteuid()!=account.pw_uid:raise ValueError('Build UID mismatch')
    process=subprocess.Popen(argv,cwd=cwd,env=env,start_new_session=True)
    try:
        code=process.wait()
        if code:raise RuntimeError('Source build step failed (exit '+str(code)+'): '+Path(args[0]).name+'. No executable was published.')
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=8)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
        raise


def build(version,source_bytes,rustup_bytes,account,arch,root):
    """All toolchain/cargo homes live in the temporary build workspace."""
    root=Path(root);source=extract_source(source_bytes,version,root)
    rustup=root/'rustup-init';rustup.write_bytes(rustup_bytes);rustup.chmod(0o755)
    (root/'home').mkdir()
    if os.geteuid()==0:
        for path in [root]+list(root.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
    env={'RUSTUP_HOME':str(root/'rustup'),'CARGO_HOME':str(root/'cargo'),
         'CARGO_TARGET_DIR':str(root/'target'),'RUSTUP_INIT_SKIP_PATH_CHECK':'yes','CARGO_BUILD_JOBS':'1'}
    print('Installing isolated stable Rust; your system Rust and user shell profile are not changed.',flush=True)
    run_user([str(rustup),'-y','--no-modify-path','--profile','minimal','--default-host',HOSTS[arch],'--default-toolchain','stable'],account,env,root)
    print('Building pinned netscanner '+version+' with Cargo.lock (may take several minutes)…',flush=True)
    run_user([str(root/'cargo/bin/cargo'),'install','--path',str(source),'--locked','--root',str(root/'output'),'--bin','netscanner','--jobs','1'],account,env,root)
    binary=root/'output/bin/netscanner'
    fd=os.open(binary,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):raise ValueError('Built output is not a regular file')
        data=stream.read(256*1024*1024+1)
    if len(data)>256*1024*1024:raise ValueError('Built output is too large')
    validate_elf(data,arch)
    return data


def source_plan(user):
    from .catalog import fetch
    account=pwd.getpwnam(user)
    if not 1000<=account.pw_uid<60000:raise ValueError('Start Aegis from a regular sudo-capable account for source builds.')
    arch=system.command(['dpkg','--print-architecture'])[1]
    if arch not in HOSTS:raise ValueError('Automatic source build currently supports Debian amd64/arm64.')
    if shutil.disk_usage('/var/tmp').free<4*1024**3:raise ValueError('Source build needs at least 4 GiB free in /var/tmp; free space and retry.')
    metadata=json.loads(fetch('https://crates.io/api/v1/crates/netscanner',4*1024*1024))
    version=metadata['crate']['newest_version'];entry=next(x for x in metadata['versions'] if x['num']==version and not x.get('yanked'))
    if not re.fullmatch(r'\d+\.\d+\.\d+',version):raise ValueError('No stable netscanner crate selected')
    checksum=entry['checksum'];data=verified_source(version,checksum,fetch('https://static.crates.io/crates/netscanner/netscanner-'+version+'.crate',64*1024*1024))
    url='https://static.rust-lang.org/rustup/dist/'+HOSTS[arch]+'/rustup-init'
    rustup=fetch(url,64*1024*1024);rust_hash=fetch(url+'.sha256',16384).decode().split()[0]
    if not re.fullmatch('[a-fA-F0-9]{64}',rust_hash) or hashlib.sha256(rustup).hexdigest()!=rust_hash.lower():raise ValueError('Official rustup-init SHA256 mismatch')
    source_path=CACHE/('netscanner-'+version+'.crate');rust_path=CACHE/('rustup-init-'+arch)
    info={'user':user,'version':version,'checksum':checksum,'rustup_sha256':rust_hash.lower(),'arch':arch}
    target='/usr/local/bin/netscanner';receipt='/opt/aegis-tools/receipts/netscanner.json'
    return Plan('Build/install netscanner '+version+' from verified source',
        before=[['apt-get','update'],['apt-get','install','build-essential','pkg-config','libssl-dev','libpcap-dev','iw','ca-certificates']],
        writes={str(source_path):data,str(rust_path):rustup},modes={str(rust_path):0o755},
        backup_paths=[target,receipt],package_change=True,persist_runner=True,
        commands=[[sys.executable,str(ENTRY),'--build-netscanner',json.dumps(info)]],
        details=['No APT/prebuilt binary was selected. Official crates.io source SHA256: '+checksum,
                 'Version: '+version+' | Rust host: '+HOSTS[arch]+' | Build UID: '+str(account.pw_uid),
                 'Official rustup-init SHA256: '+rust_hash,
                 'Uses a temporary isolated stable Rust toolchain and --locked dependencies. Compiles as a regular user, never root.',
                 'May download hundreds of MiB and take several minutes. Needs 4+ GiB temporary free space.',
                 'Installs only /usr/local/bin/netscanner with mode 0755 (no SUID). User profiles and system Rust are unchanged.',
                 'Uninstall/Undo covers the executable and receipt; APT build prerequisites have normal conditional package recovery.'])


def install(info):
    user=info['user'];account=pwd.getpwnam(user);arch=info['arch'];version=info['version']
    if not 1000<=account.pw_uid<60000 or arch not in HOSTS:raise ValueError('Invalid source-build identity')
    if system.command(['dpkg','--print-architecture'])[1]!=arch:raise ValueError('Host architecture changed')
    data=verified_source(version,info['checksum'],(CACHE/('netscanner-'+version+'.crate')).read_bytes())
    rustup=(CACHE/('rustup-init-'+arch)).read_bytes()
    if hashlib.sha256(rustup).hexdigest()!=info['rustup_sha256']:raise ValueError('Staged rustup checksum changed')
    target=Path('/usr/local/bin/netscanner')
    if target.exists() or target.is_symlink():raise ValueError('Executable destination appeared; refusing overwrite.')
    with tempfile.TemporaryDirectory(prefix='aegis-netscanner-',dir='/var/tmp') as folder:
        binary=build(version,data,rustup,account,arch,Path(folder))
        write_file(target,binary,0o755)
        write_file('/opt/aegis-tools/receipts/netscanner.json',json.dumps({'app':'netscanner','version':version,'source_sha256':info['checksum'],'binary_sha256':hashlib.sha256(binary).hexdigest(),'target':str(target)})+'\n',0o644)
    print('Installed netscanner '+version+'; source workspace/toolchain removed. No SUID/capture capabilities were granted.')
