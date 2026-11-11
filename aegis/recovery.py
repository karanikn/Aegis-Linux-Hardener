"""Package-state snapshots and conservative undo / Καταγραφή πακέτων και ελεγχόμενο undo."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from . import system


def inventory():
    code, text, _ = system.command(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'], 30)
    if code: raise RuntimeError('Cannot snapshot installed package state; operation cancelled')
    packages = {}
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) == 3 and parts[2] == 'installed': packages[parts[0]] = parts[1]
    if not packages: raise RuntimeError('Installed package inventory is empty; refusing an untracked package operation')
    code, manual, _ = system.command(['apt-mark', 'showmanual'], 30)
    if code: raise RuntimeError('Cannot snapshot APT manual/auto marks')
    return {'packages': packages, 'manual': manual.splitlines()}


def save_inventory(folder, phase):
    value = inventory()
    path = folder / ('packages-' + phase + '.json')
    path.write_text(json.dumps(value, indent=2) + '\n')
    path.chmod(0o600)
    return value


def retain_old_debs(args, folder):
    """Before each direct APT install/upgrade, retain old versions when retrievable."""
    if Path(args[0]).name not in ('apt', 'apt-get') or not set(args) & {'install', 'remove', 'upgrade', 'full-upgrade', 'dist-upgrade'}: return
    old = inventory()['packages']
    code, simulation, _ = system.command([args[0], '-s'] + args[1:], 60)
    if code:
        print('Package simulation unavailable; package inventory remains available for recovery.')
        return
    cache = folder / 'old-debs'
    cache.mkdir(mode=0o700, exist_ok=True)
    records_path = folder / 'old-debs.json'
    records = json.loads(records_path.read_text()) if records_path.exists() else {}
    for line in simulation.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] not in ('Inst', 'Remv'): continue
        package = fields[1]
        if package not in old or package in records: continue
        # Download exact old version BEFORE applying; absence does not invent an undo guarantee.
        try:
            result = subprocess.run(['apt-get', 'download', package + '=' + old[package]], cwd=cache,
                                    capture_output=True, text=True, timeout=60)
            if result.returncode: raise RuntimeError('Old version not in reachable repositories')
            found = None
            for path in cache.glob('*.deb'):
                code, value, _ = system.command(['dpkg-deb', '-f', str(path), 'Package', 'Version'])
                if code == 0 and ('Package: ' + package.split(':')[0]) in value and ('Version: ' + old[package]) in value:
                    found = path; break
            if found:
                found.chmod(0o600)
                records[package] = {'file': found.name, 'version': old[package],
                                    'sha256': hashlib.sha256(found.read_bytes()).hexdigest()}
            else: raise RuntimeError('Old package metadata did not match')
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            print('Old .deb unavailable for ' + package + '; full package undo may require a VM/filesystem snapshot.')
    records_path.write_text(json.dumps(records, indent=2) + '\n')
    records_path.chmod(0o600)


def diff(folder):
    before = json.loads((folder / 'packages-before.json').read_text())
    after_path = folder / 'packages-after.json'
    after = json.loads(after_path.read_text()) if after_path.exists() else inventory()
    b, a = before['packages'], after['packages']
    return before, after, sorted(set(a)-set(b)), sorted(p for p in b if a.get(p) != b[p])


def undo_packages(folder):
    before, after, added, changed = diff(folder)
    current = inventory()['packages']
    records_path = folder / 'old-debs.json'
    records = json.loads(records_path.read_text()) if records_path.exists() else {}
    paths = []
    missing = []
    for package in changed:
        if current.get(package) == before['packages'][package]: continue
        record = records.get(package)
        if not record or record['version'] != before['packages'][package]: missing.append(package); continue
        path = folder / 'old-debs' / record['file']
        if path.parent != folder / 'old-debs' or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise RuntimeError('Stored package validation failed')
        paths.append(str(path))
    if missing:
        raise RuntimeError('Old packages unavailable for: ' + ', '.join(missing) + '. Use a system snapshot or config-only restore.')
    added = [p for p in added if p in current]
    commands = []
    if added: commands.append(['apt-get', 'remove', '--no-auto-remove', '--'] + added)
    if paths: commands.append(['apt-get', 'install', '--allow-downgrades', '--'] + paths)
    for args in commands:
        code, text, _ = system.command([args[0], '-s'] + args[1:], 60)
        if code: raise RuntimeError('Package undo simulation failed; nothing removed')
        removals = {line.split()[1] for line in text.splitlines() if line.startswith('Remv ')}
        if not removals <= set(added): raise RuntimeError('Undo would remove pre-existing/unrelated packages; refusing')
    for args in commands:
        print('+ ' + ' '.join(args))
        if subprocess.run(args).returncode: raise RuntimeError('APT package undo did not complete')
    # Restore only manual/auto marks changed by the recorded operation, not all host marks.
    auto_again = sorted((set(after['manual']) - set(before['manual'])) & set(before['packages']) & set(inventory()['packages']))
    if auto_again and subprocess.run(['apt-mark', 'auto'] + auto_again).returncode:
        raise RuntimeError('Could not restore APT marks')
    return {'removed_new': added, 'restored_old': changed}
