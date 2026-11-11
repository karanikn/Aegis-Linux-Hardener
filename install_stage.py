#!/usr/bin/env python3
"""Internal installation stage / Το shell bootstrap supplies the embedded payload."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

# Build-time placeholders, replaced in the distributed self-contained shell file.
PAYLOAD = '__AEGIS_PAYLOAD__'
DIGEST = '__AEGIS_DIGEST__'


def extract(data, destination):
    root = destination.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not (member.isdir() or member.isfile()):
                raise ValueError('Unsafe archive member')
            path = root.joinpath(*name.parts)
            if root not in path.resolve().parents and path.resolve() != root:
                raise ValueError('Archive path escapes destination')
            if path.is_symlink(): raise ValueError('Destination contains symlink')
            if member.isdir(): path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                with path.open('wb') as out: shutil.copyfileobj(source, out)
                path.chmod(0o644)


def main():
    parser = argparse.ArgumentParser(description='Install Aegis Linux Hardener 0.8.0')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--portable', action='store_true', help='Run the unpacked UI without installing /opt or a launcher')
    modes.add_argument('--install', action='store_true', help='Install/update Aegis explicitly')
    parser.add_argument('--check', action='store_true', help='Verify embedded payload without installing')
    parser.add_argument('--extract', metavar='DIRECTORY', help='Extract source without system installation')
    parser.add_argument('--no-launch', action='store_true', help='Install without opening the menu')
    args = parser.parse_args()
    data = base64.b64decode(PAYLOAD, validate=True)
    if hashlib.sha256(data).hexdigest() != DIGEST: raise ValueError('Payload checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='aegis-verify-') as temporary:
        source = Path(temporary)
        extract(data, source)
        for path in source.rglob('*.py'): compile(path.read_text(), str(path), 'exec')
        if args.check:
            print('Aegis payload SHA256 and Python syntax: OK. No installation performed.')
            return
        if args.extract:
            destination = Path(args.extract).expanduser()
            destination.mkdir(parents=True, exist_ok=True)
            extract(data, destination)
            print('Extracted: ' + str(destination.resolve()))
            return
        sys.path.insert(0, str(source))
        from aegis import console
        if not args.install and not args.portable:
            console.section('Aegis Linux Hardener — startup mode')
            print('1  Install / Update (default)\n2  Run portable (no program installation)')
            choice = console.ask('Select mode', '1')
            choice = {'y':'1','yes':'1','p':'2','portable':'2'}.get(choice.lower(),choice)
            if choice not in ('1', '2'): raise ValueError('Select 1 or 2')
            args.portable = choice == '2'
        if args.portable:
            print('Portable mode: no /opt installation or aegis launcher is created.')
            subprocess.run([sys.executable, str(source / 'aegis.py')], check=True)
            return
        if os.geteuid() != 0: raise RuntimeError('Run installation with sudo bash install-aegis.sh --install, or select portable mode')
        if sys.version_info < (3, 9): raise RuntimeError('Python 3.9+ required')
        sys.path.insert(0, str(source))
        from aegis.system import debian_based
        if not debian_based(): raise RuntimeError('A Debian-based Linux system is required')
        if not Path('/run/systemd/system').is_dir(): raise RuntimeError('An active systemd host is required; no minimal containers')
        target = Path('/opt/aegis-linux-hardener')
        launcher = Path('/usr/local/bin/aegis')
        if target.is_symlink() or (target.exists() and not (target / '.aegis-managed').is_file()):
            raise RuntimeError('Target exists without an Aegis ownership marker')
        if launcher.is_symlink() or (launcher.exists() and 'aegis-linux-hardener' not in launcher.read_text()):
            raise RuntimeError('Existing unrelated /usr/local/bin/aegis; refusing overwrite')
        for manifest in Path('/var/lib/aegis-linux-hardener/backups').glob('*/manifest.json'):
            if json.loads(manifest.read_text()).get('status') in ('armed', 'applying', 'awaiting-activation', 'activating', 'awaiting-confirmation'):
                raise RuntimeError('Confirm or restore the pending change before upgrading Aegis')
        print('Aegis Linux Hardener 0.8.0\nSystem info, security hardening and Telegram alerts in one tool.')
        print('Installs program files in /opt/aegis-linux-hardener and the /usr/local/bin/aegis launcher.')
        print('No firewall, SSH, optional packages or Telegram configuration is changed by this bootstrap.')
        if not console.confirm('Install/update Aegis on this machine?'):
            print('Cancelled. No installation performed.')
            return
        from aegis import actions
        with actions.state_lock():
            snapshot_plan = actions.Plan('Install/update Aegis program',
                backup_paths=[str(target), str(launcher)], persist_runner=True)
            recovery_folder, recovery_manifest = actions.backup(snapshot_plan, '')
            recovery_manifest['operation'] = 'program-install'
            actions.save_json(recovery_folder / 'manifest.json', recovery_manifest)
        print('Program undo ID: ' + recovery_manifest['id'])
        print('Recovery command: sudo ' + sys.executable + ' ' + recovery_manifest['runner'] + ' rollback ' + recovery_manifest['id'])
        if target.exists():
            backup = Path('/var/backups') / ('aegis-linux-hardener-' + time.strftime('%Y%m%d-%H%M%S'))
            backup.mkdir(mode=0o700)
            shutil.copytree(target, backup / 'program')
            if launcher.exists(): shutil.copy2(launcher, backup / 'launcher')
            print('Previous program backup: ' + str(backup))
        target.parent.mkdir(parents=True, exist_ok=True)
        staged = Path(tempfile.mkdtemp(prefix='.aegis-new-', dir=target.parent))
        old = None
        old_launcher = launcher.read_bytes() if launcher.exists() else None
        try:
            extract(data, staged)
            (staged / '.aegis-managed').write_text('Aegis Linux Hardener 0.8.0\n')
            if target.exists():
                old = Path(tempfile.mkdtemp(prefix='.aegis-old-', dir=target.parent))
                old.rmdir()
                os.replace(target, old)
            staged.chmod(0o755)
            os.replace(staged, target)
            target.chmod(0o755)
            launcher.parent.mkdir(parents=True, exist_ok=True)
            fd, temp_launcher = tempfile.mkstemp(dir=launcher.parent, prefix='.aegis-')
            with os.fdopen(fd, 'w') as stream:
                stream.write('#!/bin/sh\nexec ' + __import__('shlex').quote(sys.executable) + ' /opt/aegis-linux-hardener/aegis.py "$@"\n')
                os.fchmod(stream.fileno(), 0o755)
            os.replace(temp_launcher, launcher)
        except BaseException:
            if old and old.exists():
                if target.exists(): shutil.rmtree(target)
                os.replace(old, target)
            elif target.exists() and (target / '.aegis-managed').exists(): shutil.rmtree(target)
            if old_launcher is not None: launcher.write_bytes(old_launcher); launcher.chmod(0o755)
            elif launcher.exists(): launcher.unlink()
            raise
        finally:
            if staged.exists(): shutil.rmtree(staged)
            if old and old.exists(): shutil.rmtree(old)
        recovery_manifest['status'] = 'applied'
        actions.save_json(recovery_folder / 'manifest.json', recovery_manifest)
        actions.event('applied', recovery_manifest['id'], 'Install/update Aegis program')
        print('Installed. Start with: aegis\nRead-only CLI: aegis info --json | aegis monitor --sort cpu | aegis audit')
        if not args.no_launch and sys.stdin.isatty(): subprocess.run([str(launcher)])


if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt: print('Cancelled.'); sys.exit(130)
    except Exception as error: print('Aegis installer: ' + str(error), file=sys.stderr); sys.exit(1)
