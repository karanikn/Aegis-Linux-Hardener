"""Explicit per-app removal with recovery; no purge/autoremove or user-data deletion."""
import os
from pathlib import Path
import re
import shutil
from . import catalog,system
from .actions import Plan

CONFIGS={'caddy':['/etc/caddy'],'webmin':['/etc/webmin'],'cockpit':['/etc/cockpit','/etc/systemd/system/cockpit.socket.d'],
         'docker':['/etc/docker'],'nmtui':['/etc/NetworkManager'],'samba':['/etc/samba']}
PROTECTED={'apt','dpkg','python3','python3-minimal','sudo','openssh-server','openssh-client','systemd','systemd-sysv','libc6','iproute2'}


def plan(key):
    if key not in {row[0] for row in catalog.all_apps()}:raise ValueError('Unknown application')
    if key=='nmtui' and system.service('NetworkManager')=='active':raise ValueError('NetworkManager is active. Migrate/verify networking separately before removing its nmtui package.')
    if key=='docker' and system.command(['docker','ps','-q'])[1]:raise ValueError('Running containers exist. Stop/migrate workloads explicitly before removing the engine.')
    if key=='samba' and any(system.service(unit)=='active' for unit in ('smbd','nmbd','samba-ad-dc','winbind')):raise ValueError('Stop Samba explicitly and check client sessions before removing it. Shares/data are preserved.')
    package=catalog.package_for(key)
    if key.startswith('custom-'):
        _,flags,_=system.command(['dpkg-query','-W','-f=${Essential} ${Protected}',package])
        if package in PROTECTED or 'yes' in flags.split():raise ValueError('Refusing to remove an essential/protected system package.')
    targets=[package] if system.installed(package) else []
    if key=='docker':targets=[p for p in ('docker-ce','docker-ce-cli','docker-buildx-plugin','docker-compose-plugin','docker.io') if system.installed(p)]
    if targets:
        args=['apt-get','remove','--no-auto-remove','--']+targets
        code,text,_=system.command(['apt-get','-s']+args[1:],timeout=60)
        if code:raise ValueError('APT removal simulation failed; resolve package state first.')
        removed={line.split()[1].split(':')[0] for line in text.splitlines() if line.startswith('Remv ')}
        if removed&PROTECTED:raise ValueError('Removal would affect protected administration/system packages.')
        if removed-set(targets):raise ValueError('Removal also affects other packages: '+', '.join(sorted(removed-set(targets)))+'. Review dependency changes using your package manager.')
        return Plan('Uninstall '+key+' (keep data/config)',commands=[args],package_change=True,backup_paths=CONFIGS.get(key,[]),
            details=['Packages: '+', '.join(targets),'Uses remove, not purge; never autoremove. User data, Docker images/volumes and shared folders are retained.',
                     'Exact old .deb files are retained when available. Package Undo depends on old versions and safe dependency resolution.'])
    if key.startswith('custom-'):raise ValueError('The custom APT package is not installed; external files are not removed.')
    command=catalog.COMMANDS.get(key,key);executable=shutil.which(command)
    if not executable:raise ValueError('No installed package or executable found. Refresh application status.')
    path=Path(executable)
    if path.parent!=Path('/usr/local/bin') or path.is_symlink() or path.stat().st_uid!=0:
        raise ValueError('External/non-owned installation: automatic removal is limited to a root-owned regular /usr/local/bin executable or known APT package. Use its original installer.')
    env=Path('/opt/aegis-tools')/key
    paths=[str(path)];commands=[['rm','--',str(path)]]
    if key in ('rovr','hwinfo-tui') and env.exists():
        expected='#!/bin/sh\nexec '+str(env/'venv/bin'/key)+' "$@"\n'
        if env.is_symlink() or env.stat().st_uid!=0 or path.read_text()!=expected:raise ValueError('Managed Python environment identity did not match; inspect manually.')
        paths.append(str(env));commands.append(['rm','-rf','--',str(env)])
    receipt=Path('/opt/aegis-tools/receipts')/(key+'.json')
    if receipt.is_file() and not receipt.is_symlink():
        paths.append(str(receipt));commands.append(['rm','--',str(receipt)])
    return Plan('Uninstall '+key+' executable',backup_paths=paths,commands=commands,
        details=['Removes the displayed executable/managed environment only. Existing files and ownership are backed up for Undo.',
                 'Application configuration, user documents, workspaces and runtime data elsewhere are preserved.'])
