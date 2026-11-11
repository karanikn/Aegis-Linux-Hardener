"""Reviewed change plans, backups and rollback / Σχέδια αλλαγών και επαναφορά."""
import dataclasses
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from . import system, console, recovery

STATE = Path('/var/lib/aegis-linux-hardener')
POLICY = Path('/usr/sbin/policy-rc.d')
ENTRY = Path(__file__).resolve().parent.parent / 'aegis.py'
ACTIVE_FOLDER = None
PENDING = ('armed', 'applying', 'awaiting-activation', 'activating', 'awaiting-confirmation')


@dataclasses.dataclass
class Plan:
    title: str
    details: list = dataclasses.field(default_factory=list)
    writes: dict = dataclasses.field(default_factory=dict)
    # commands before/after file writes; no shell strings / μόνο argv lists.
    before: list = dataclasses.field(default_factory=list)
    validate: list = dataclasses.field(default_factory=list)
    commands: list = dataclasses.field(default_factory=list)
    late_writes: dict = dataclasses.field(default_factory=dict)
    post_validate: list = dataclasses.field(default_factory=list)
    modes: dict = dataclasses.field(default_factory=dict)
    acl_paths: list = dataclasses.field(default_factory=list)
    samba_users: list = dataclasses.field(default_factory=list)
    account_users: list = dataclasses.field(default_factory=list)
    account_groups: list = dataclasses.field(default_factory=list)
    metadata: dict = dataclasses.field(default_factory=dict)
    detached: bool = False
    persist_runner: bool = False
    backup_paths: list = dataclasses.field(default_factory=list)
    rollback_before: list = dataclasses.field(default_factory=list)
    rollback_commands: list = dataclasses.field(default_factory=list)
    critical: bool = False
    package_change: bool = False
    suppress_services: bool = False
    guard: object = None
    verify: object = None
    secrets: bool = False
    def preview(self):
        lines = [self.title, ''] + self.details
        lines += ['', 'Managed file changes:']
        for name, content in self.writes.items():
            lines.append(name)
            lines.extend('    ' + x for x in ('<content hidden: private configuration>' if self.secrets else (content if isinstance(content, str) else '<binary file>')).splitlines())
        for name in self.late_writes:
            lines.append(name + ' (configured after package installation, before service start)')
        for name, mode in self.metadata.items():
            lines.append(name + ' permissions → ' + oct(mode))
        lines += ['', 'Commands:']
        lines += ['  ' + shlex.join(cmd) for cmd in self.before + self.validate + self.post_validate + self.commands]
        if self.critical:
            lines += ['', 'Automatic rollback is armed for 180 seconds BEFORE changes.',
                      'Open a SECOND SSH connection and run the displayed confirm command.']
        if self.package_change:
            lines += ['', 'Package state and APT marks are snapshotted; old .deb versions are retained when available.',
                      'Package undo is conditional: unavailable old versions/vendor side effects need a system snapshot.']
        return '\n'.join(lines)


def checked(args):
    if ACTIVE_FOLDER is not None:
        recovery.retain_old_debs(args, ACTIVE_FOLDER)
    print(console.paint('+ ' + shlex.join(args), 'muted'), flush=True)
    # Interactive APT keeps its own final dependency confirmation / διάλογος APT.
    result = subprocess.run(args, env={**os.environ, 'LC_ALL': 'C'})
    if result.returncode:
        raise RuntimeError('Command failed: ' + args[0] + ' (exit ' + str(result.returncode) + ')')


def write_file(path, value, mode=0o644):
    path = Path(path)
    missing = []
    parent = path.parent
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
    if path.is_symlink():
        raise RuntimeError('Refusing to replace symlink: ' + str(path))
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(value.encode() if isinstance(value, str) else value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)


def save_json(path, value):
    write_file(path, json.dumps(value, indent=2) + '\n', 0o600)


def state_lock():
    STATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    STATE.chmod(0o700)
    f = (STATE / 'change.lock').open('a')
    os.chmod(STATE / 'change.lock', 0o600)
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


def event(kind, ident, title):
    STATE.mkdir(parents=True, mode=0o700, exist_ok=True)
    path = STATE / 'history.jsonl'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, 'a') as stream:
        stream.write(json.dumps({'time': datetime.datetime.now().astimezone().isoformat(),
                                 'event': kind, 'id': ident, 'title': title}, ensure_ascii=False) + '\n')


def backup(plan, origin):
    ident = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:8]
    folder = STATE / 'backups' / ident
    folder.mkdir(parents=True, mode=0o700)
    records = []
    paths = sorted(set(list(plan.writes) + list(plan.late_writes) + plan.backup_paths))
    # Parent directory snapshots cover their children; avoid duplicate restoration.
    selected = []
    for name in paths:
        p = Path(name)
        if not p.is_absolute() or '..' in p.parts:
            raise ValueError('Backup path must be absolute')
        if any(Path(parent).is_dir() and p != Path(parent) and Path(parent) in p.parents for parent in selected):
            continue
        selected.append(name)
    for index, name in enumerate(selected):
        p = Path(name)
        target = folder / str(index)
        exists = p.exists() or p.is_symlink()
        kind = 'missing'
        mode = 0o644
        owner = None
        tree_owners = []
        if exists:
            info = p.lstat()
            owner = [info.st_uid, info.st_gid]
            mode = stat.S_IMODE(p.lstat().st_mode)
            if p.is_symlink():
                raise RuntimeError('Refusing managed symlink: ' + name)
            if p.is_dir():
                kind = 'dir'
                shutil.copytree(p, target, symlinks=True)
                for child in [p] + list(p.rglob('*')):
                    info = child.lstat()
                    tree_owners.append([str(child.relative_to(p)), info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), child.is_symlink()])
            elif p.is_file():
                kind = 'file'
                shutil.copy2(p, target)
            else:
                raise ValueError('Unsupported backup object: ' + name)
        records.append({'path': name, 'copy': str(index), 'kind': kind, 'mode': mode, 'owner': owner, 'tree_owners': tree_owners})
    for name, mode in plan.metadata.items():
        p = Path(name)
        if p.is_symlink() or not p.exists(): raise RuntimeError('Cannot change metadata of missing/symlink path: ' + name)
        value = p.stat()
        records.append({'path': name, 'kind': 'metadata', 'mode': stat.S_IMODE(value.st_mode),
                        'uid': value.st_uid, 'gid': value.st_gid,'device':value.st_dev,'inode':value.st_ino})
    if plan.samba_users:
        from . import shares
        records.append({'kind':'samba-users','old':shares.credential_rows(plan.samba_users)})
    if plan.account_users or plan.account_groups:
        from . import users
        records.append({'kind':'accounts','old':users.capture(plan.account_users,plan.account_groups)})
    for name in plan.acl_paths:
        p=Path(name)
        if p.is_symlink() or not p.exists():raise ValueError('ACL target must be an existing real object')
        code,text,error=system.command(['getfacl','--absolute-names','--numeric','--',name])
        if code:raise RuntimeError('Cannot snapshot POSIX ACL; install acl first.')
        info=p.stat()
        records.append({'kind':'acl','path':name,'acl':text+'\n','device':info.st_dev,'inode':info.st_ino})
    runner = str(ENTRY)
    internal_helper = any(str(ENTRY) in [str(x) for x in args] for args in plan.commands + plan.rollback_commands + plan.rollback_before)
    if plan.critical or plan.persist_runner or internal_helper or plan.account_users or plan.account_groups or plan.samba_users or plan.acl_paths:
        runner_dir = folder / 'runner'
        runner_dir.mkdir(mode=0o700)
        shutil.copy2(ENTRY, runner_dir / 'aegis.py')
        shutil.copytree(ENTRY.parent / 'aegis', runner_dir / 'aegis', ignore=shutil.ignore_patterns('__pycache__'))
        runner = str(runner_dir / 'aegis.py')
    def durable(args):
        return [runner if str(value) == str(ENTRY) else value for value in args]
    manifest = {'id': ident, 'title': plan.title, 'files': records,
                'rollback_before': [durable(args) for args in plan.rollback_before],
                'rollback_commands': [durable(args) for args in plan.rollback_commands], 'origin': origin,
                'runner': runner, 'apply_commands': [durable(args) for args in plan.commands],
                'critical': plan.critical, 'status': 'prepared', 'package_change': plan.package_change,
                'created': time.time()}
    if plan.package_change:
        recovery.save_inventory(folder, 'before')
    save_json(folder / 'manifest.json', manifest)
    return folder, manifest


def restore(folder, manifest, outcome='rolled-back'):
    # Rollback inputs must be root-owned stored manifests, never downloaded files.
    failures = []
    for args in manifest.get('rollback_before', []):
        try: checked(args)
        except Exception as error: failures.append(str(error))
    for item in manifest['files']:
        if item['kind']=='samba-users':
            try:
                from . import shares
                shares.restore_credentials(item)
            except Exception as error:failures.append(str(error))
            continue
        if item['kind']=='accounts':
            try:
                from . import users
                users.restore_accounts(item)
            except Exception as error:failures.append(str(error))
            continue
        path = Path(item['path'])
        if item['kind']=='acl':
            try:
                info=path.stat()
                if path.is_symlink() or (info.st_dev,info.st_ino)!=(item['device'],item['inode']):raise RuntimeError('ACL target was replaced; inspect before recovery.')
                result=subprocess.run(['setfacl','--restore=-'],input=item['acl'],text=True,capture_output=True)
                if result.returncode:raise RuntimeError('POSIX ACL restore failed: '+str(path))
            except Exception as error:failures.append(str(error))
            continue
        if item['kind'] == 'metadata':
            try:
                if path.is_symlink() or not path.exists():raise RuntimeError('Metadata target changed: '+str(path))
                info=path.stat()
                if 'inode' in item and (info.st_dev,info.st_ino)!=(item['device'],item['inode']):raise RuntimeError('Metadata target was replaced: '+str(path))
                path.chmod(item['mode'])
                if os.geteuid()==0:os.chown(path,item['uid'],item['gid'])
            except Exception as error:failures.append(str(error))
            continue
        original = folder / item['copy']
        if path.is_symlink() or path.is_file(): path.unlink()
        elif path.is_dir(): shutil.rmtree(path)
        if item['kind'] == 'dir':
            shutil.copytree(original, path, symlinks=True)
            for relative, uid, gid, mode, is_link in item.get('tree_owners', []):
                child = path / relative
                if os.geteuid() == 0: os.chown(child, uid, gid, follow_symlinks=False)
                if not is_link: child.chmod(mode)
        elif item['kind'] == 'file':
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, path)
            if item.get('owner') and os.geteuid() == 0: os.chown(path, *item['owner'])
    for args in manifest['rollback_commands']:
        try:
            checked(args)
        except Exception as error:
            failures.append(str(error))
    manifest['status'] = 'rollback-incomplete' if failures else outcome
    save_json(folder / 'manifest.json', manifest)
    event(manifest['status'], manifest['id'], manifest['title'])
    if failures: raise RuntimeError('; '.join(failures))


def load_manifest(ident):
    if not re_id(ident): raise ValueError('Invalid change ID')
    folder = STATE / 'backups' / ident
    path = folder / 'manifest.json'
    if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
        raise RuntimeError('Unsafe manifest ownership/mode')
    return folder, json.loads(path.read_text())


def re_id(value):
    import re
    return bool(re.fullmatch(r'\d{8}-\d{6}-[a-f0-9]{8}', value))


def rollback(ident, automatic=False):
    with state_lock():
        folder, manifest = load_manifest(ident)
        if automatic and manifest['status'] not in PENDING:
            return
        package_error = None
        if not automatic and manifest.get('package_change') and (folder / 'packages-before.json').exists():
            if console.confirm('Undo recorded package additions/versions when safely retrievable?'):
                try: recovery.undo_packages(folder)
                except Exception as error:
                    package_error = str(error)
                    print(console.paint(package_error, 'yellow'))
                    if not console.confirm('Continue with managed files/settings only?'): return
            else:
                package_error = 'Package undo was not requested; only managed files/settings were restored'
        restore(folder, manifest, 'rolled-back-config-only' if package_error else 'rolled-back')
        if package_error:
            manifest['status'] = 'rolled-back-config-only'
            manifest['package_undo_error'] = package_error
            save_json(folder / 'manifest.json', manifest)
        system.command(['systemctl', 'stop', 'aegis-rollback-' + ident + '.timer'])


def confirm(ident, origin):
    with state_lock():
        folder, manifest = load_manifest(ident)
        if manifest['status'] != 'awaiting-confirmation':
            raise ValueError('This change is not awaiting confirmation')
        if manifest['origin'] and manifest['origin'] == origin:
            raise ValueError('Confirm from a NEW SSH connection, not the connection used to apply the change')
        if manifest['origin'] and not origin:
            raise ValueError('SSH session identity is missing; reconnect and run aegis confirm without clearing SSH_CONNECTION')
        if not console.confirm('Verify access works in this NEW session. Keep the change?'): return
        checked(['systemctl', 'stop', 'aegis-rollback-' + ident + '.timer'])
        manifest['status'] = 'confirmed'
        save_json(folder / 'manifest.json', manifest)
        event('confirmed', ident, manifest['title'])
        print('Change confirmed; automatic rollback cancelled.')


def apply(plan, origin=''):
    global ACTIVE_FOLDER
    if os.geteuid() != 0: raise RuntimeError('Root required to apply changes')
    console.section(plan.title)
    print(plan.preview())
    if not console.confirm('Apply this plan?'):
        print('Cancelled. No plan changes applied.')
        return None
    with state_lock():
        # Do not allow overlapping changes to invalidate an armed rollback snapshot.
        for manifest_path in (STATE / 'backups').glob('*/manifest.json'):
            if json.loads(manifest_path.read_text()).get('status') in PENDING:
                raise RuntimeError('A previous change is still awaiting confirmation or rollback')
        if plan.guard: plan.guard()
        if plan.critical and not shutil.which('systemd-run'):
            raise RuntimeError('systemd-run is required for timed rollback; nothing changed')
        if plan.suppress_services and (POLICY.exists() or POLICY.is_symlink()):
            raise RuntimeError('Existing policy-rc.d detected. Use the system package manager for this application.')
        folder, manifest = backup(plan, origin)
        print('Backup/change ID: ' + manifest['id'])
        timer = 'aegis-rollback-' + manifest['id']
        ACTIVE_FOLDER = folder if plan.package_change else None
        try:
            if plan.critical:
                manifest['status'] = 'armed'
                save_json(folder / 'manifest.json', manifest)
                checked(['systemd-run', '--unit=' + timer, '--on-active=180s', '--timer-property=AccuracySec=1s',
                         sys.executable, manifest['runner'], 'rollback', manifest['id'], '--automatic'])
                if system.command(['systemctl', 'is-active', timer + '.timer'])[1] != 'active':
                    raise RuntimeError('Rollback timer did not become active')
                print('Confirm in a NEW connection: sudo ' + shlex.quote(sys.executable) + ' ' + shlex.quote(manifest['runner']) + ' confirm ' + manifest['id'])
            manifest['status'] = 'applying'
            save_json(folder / 'manifest.json', manifest)
            if plan.suppress_services:
                write_file(POLICY, '#!/bin/sh\n# Aegis managed temporary service-start guard\nexit 101\n', 0o755)
            try:
                for args in plan.before: checked(args)
                for path, content in plan.writes.items(): write_file(path, content, plan.modes.get(path, 0o644))
                for path, mode in plan.metadata.items(): Path(path).chmod(mode)
                for args in plan.validate: checked(args)
                for path, content in plan.late_writes.items():
                    value = content(system.read(path)) if callable(content) else content
                    write_file(path, value, plan.modes.get(path, 0o644))
                for args in plan.post_validate: checked(args)
                if plan.verify: plan.verify()
            finally:
                if plan.suppress_services:
                    POLICY.unlink(missing_ok=True)
            if plan.detached:
                manifest['status'] = 'awaiting-activation'
                save_json(folder / 'manifest.json', manifest)
                checked(['systemd-run', '--unit=aegis-apply-' + manifest['id'], '--collect',
                         '--property=Type=oneshot', '--property=TimeoutStartSec=90s',
                         sys.executable, manifest['runner'], 'activate', manifest['id']])
            else:
                for args in plan.commands: checked(args)
            for record in manifest['files']:
                if record['kind']=='samba-users':
                    from . import shares
                    record['expected']=shares.credential_rows(list(record['old']))
                if record['kind']=='accounts':
                    from . import users
                    record['expected']=users.capture(record['old']['users'],record['old']['groups'])
            if plan.package_change: recovery.save_inventory(folder, 'after')
            if not plan.detached: manifest['status'] = 'awaiting-confirmation' if plan.critical else 'applied'
            save_json(folder / 'manifest.json', manifest)
            ACTIVE_FOLDER = None
            event(manifest['status'], manifest['id'], plan.title)
            if plan.critical:
                print('\nOpen a NEW SSH connection (use the NEW IP after a network change), then run:\nsudo ' + shlex.quote(sys.executable) + ' ' + shlex.quote(manifest['runner']) + ' confirm ' + manifest['id'])
                print('If not confirmed, the managed files/rules will be restored after 180 seconds.')
            else:
                print('Applied. Managed-file backup: ' + str(folder))
            return manifest['id']
        except BaseException:
            ACTIVE_FOLDER = None
            if plan.package_change:
                try: recovery.save_inventory(folder, 'after')
                except Exception: pass
            try:
                restore(folder, manifest)
                if plan.critical: system.command(['systemctl', 'stop', timer + '.timer'])
            except Exception as error:
                print('Rollback requires attention: ' + str(error), file=sys.stderr)
            raise


def activate(ident):
    """Independent systemd worker survives loss of the originating SSH connection."""
    if os.geteuid() != 0: raise RuntimeError('Root required')
    with state_lock():
        folder, manifest = load_manifest(ident)
        if manifest['status'] != 'awaiting-activation': raise RuntimeError('Change is not awaiting activation')
        manifest['status'] = 'activating'
        save_json(folder / 'manifest.json', manifest)
        try:
            for args in manifest['apply_commands']: checked(args)
            manifest['status'] = 'awaiting-confirmation'
            save_json(folder / 'manifest.json', manifest)
            event('awaiting-confirmation', ident, manifest['title'])
        except BaseException:
            restore(folder, manifest)
            raise
