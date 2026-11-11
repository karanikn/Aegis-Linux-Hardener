#!/usr/bin/env python3
"""Aegis Linux Hardener — Debian-based servers and desktops."""
import argparse
import datetime
import getpass
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys

from aegis import VERSION, TITLE, TAGLINE, system, actions, security, catalog, console, networking, lynis, panels, defense, toolinstall, logs, launch, dependencies, users, shares, nameconfig, management, uninstall, themes, sourcebuild, categories, selfupdate, appregistry, catalogmanager, appsearch
from aegis.ui import UI, table

ENTRY = Path(__file__).resolve()


def original_user():
    return os.environ.get('SUDO_USER') or getpass.getuser()


def preferences():
    local = Path.home() / '.config/aegis-linux-hardener/ui.json'
    global_path = Path('/etc/aegis-linux-hardener/ui.json')
    for path in (local, global_path):
        try:
            value = json.loads(path.read_text())
            return {'language': value.get('language', 'en'), 'theme': value.get('theme', 'slate')}
        except (OSError, ValueError): pass
    return {'language': 'en', 'theme': 'slate'}


def save_preferences(ui):
    path = Path('/etc/aegis-linux-hardener/ui.json') if os.geteuid() == 0 else Path.home() / '.config/aegis-linux-hardener/ui.json'
    content=json.dumps({'language':ui.language,'theme':ui.theme},indent=2)+'\n'
    if os.geteuid()==0:
        actions.apply(actions.Plan('UI preferences',writes={str(path):content}))
    else:
        if path.exists():
            backup=path.with_name(path.name+'.bak-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
            shutil.copy2(path,backup)
        actions.write_file(path,content)


def call_root(request, origin=None):
    origin = system.ssh_connection() if origin is None else origin
    if os.geteuid() != 0:
        if not shutil.which('sudo'): raise RuntimeError('sudo unavailable; log in as root to apply changes')
        p = subprocess.run(['sudo', sys.executable, str(ENTRY), '--action', json.dumps(request), '--origin', origin])
        if p.returncode in (20,21):return False
        if p.returncode == 90: raise SystemExit(0)
        if p.returncode: raise RuntimeError('Action did not complete; review the output above')
        return True
    return dispatch(request, origin)


def dispatch(request, origin):
    """Rebuild known plans at the privilege boundary; never accept arbitrary argv."""
    if not system.debian_based(): raise RuntimeError('This action requires Debian/Ubuntu or a Debian-based system')
    console.LANGUAGE = request.get('language') or os.environ.get('AEGIS_LANGUAGE', 'en')
    console.THEME=themes.valid(request.get('theme',console.THEME))
    kind = request.get('kind')
    user = request.get('user') or original_user()
    request.setdefault('user',user)
    if kind=='dependencies-only':return dependencies.ensure(request.get('target',{}),origin)
    if request.get('interactive') and not dependencies.ensure(request,origin):return False
    if kind=='lynis-control' and request.get('control')=='password-quality' and request.get('prompt_minlen'):
        while True:
            value=console.ask('Minimum length / Ελάχιστο μήκος (8–128, q=cancel)','14')
            if value.lower() in ('q','cancel'):
                print('Cancelled; no password-quality policy change applied.');return False
            if value.isdigit() and 8<=int(value)<=128:request['minlen']=value;break
            print('Enter a number from 8 to 128, or q to cancel.')
    if kind == 'app':
        plan = catalog.app_plan(request['app'], user)
    elif kind=='catalog-manager':catalogmanager.menu(console.LANGUAGE,console.THEME);return
    elif kind=='self-update':return selfupdate.run(console.confirm,VERSION)
    elif kind=='hostname':plan=nameconfig.hostname_plan(request['hostname'],request.get('update_hosts',True))
    elif kind=='uninstall-app':plan=uninstall.plan(request['app'])
    elif kind=='users-browser':management.users_menu(console.LANGUAGE,user,request.get('theme','slate'));return
    elif kind=='shares-browser':management.shares_menu(console.LANGUAGE,user,request.get('theme','slate'));return
    elif kind=='dns-browser':management.dns_menu(console.LANGUAGE,user,request.get('theme','slate'));return
    elif kind=='hosts-browser':management.hosts_menu(console.LANGUAGE,request.get('theme','slate'));return
    elif kind == 'open-app':
        launch.open_app(request['app'],user,request.get('detail',''));return
    elif kind == 'logs-browser':
        logs.menu(console.LANGUAGE,user);return
    elif kind == 'install-security':
        groups = {'fail2ban': ['fail2ban', 'python3-systemd'], 'ufw': ['ufw'],
                  'apparmor': ['apparmor', 'apparmor-utils', 'apparmor-profiles'],
                  'updates': ['unattended-upgrades'], 'freerdp': ['freerdp3-x11']}
        key = request['package']
        if key not in groups: raise ValueError('Invalid security package')
        plan = catalog.package_plan(groups[key])
        if key == 'updates':
            plan.writes['/etc/apt/apt.conf.d/52aegis-unattended-upgrades'] = (
                'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
                'Unattended-Upgrade::Automatic-Reboot "false";\n')
            plan.details += ['Uses distribution/vendor origin policies already configured by unattended-upgrades.',
                             'Automatic reboot is explicitly disabled.']
    elif kind == 'ssh':
        plan = security.ssh_plan(request['mode'], user, request['source'], request.get('value'))
        if request['mode'] == 'keys-only' and request.get('keys_verified') not in (True, 'KEYS VERIFIED'):
            raise ValueError('A successful second-session key login must be verified first')
    elif kind == 'fail2ban':
        plan = security.fail2ban_plan(request['jails'], request['ignore'], request['retries'],
                                     request['window'], request['duration'], request['port'])
    elif kind == 'ufw':
        plan = security.ufw_plan(request['mode'], request['source'], request['port'], request.get('protocol', 'tcp'))
    elif kind == 'report-export':
        path=Path(request['path'])
        if not path.is_absolute():raise ValueError('Use an absolute report path')
        plan=actions.Plan('Export system inventory report', writes={str(path):json.dumps(system.snapshot(),ensure_ascii=False,indent=2)+'\n'},modes={str(path):0o600},
            details=['An existing destination file is backed up before replacement. Host/network inventory can be sensitive.'])
    elif kind == 'defense-install':plan=defense.install_plan(request['tool'])
    elif kind == 'defense-status':
        key=request['tool']
        if key not in defense.TOOLS:raise ValueError('Unknown tool')
        print(defense.information(key))
        print(output(['systemctl','status',key+'.service','--no-pager']))
        print(output(['journalctl','-u',key+'.service','-n','30','--no-pager']))
        return
    elif kind == 'nmtui':
        if not shutil.which('nmtui') or system.service('NetworkManager')!='active':
            raise ValueError('nmtui needs an installed, active NetworkManager. Use the existing-backend wizard; no network migration is performed.')
        if system.command(['nmcli','device','checkpoint','--help'])[0]:
            raise ValueError('This NetworkManager lacks checkpoint support; use the protected Aegis network wizard.')
        plan=actions.Plan('Interactive NetworkManager configuration (nmtui)',
            backup_paths=['/etc/NetworkManager','/var/lib/NetworkManager','/etc/resolv.conf'] if not Path('/etc/resolv.conf').is_symlink() else ['/etc/NetworkManager','/var/lib/NetworkManager'],
            persist_runner=True,rollback_commands=[['nmcli','connection','reload'],['systemctl','restart','NetworkManager']],
            details=['Saves current configuration for later Undo, then launches nmtui under a native NetworkManager checkpoint.',
                     'NetworkManager restores device state after 150 seconds unless its own prompt is confirmed.',
                     'Finish within the checkpoint period. Keep console/new SSH access available.'])
        ident=actions.apply(plan,origin)
        if ident:
            # Outside Aegis state lock: a disconnected interactive process cannot block recovery.
            print('Configuration backup ID: '+ident+'; native NetworkManager checkpoint: 150 seconds.')
            subprocess.run(['nmcli','device','checkpoint','--timeout','150','--','nmtui'])
        return
    elif kind == 'network':
        plan = networking.network_plan(request['iface'], request['mode'], request.get('address',''), request.get('gateway',''), request.get('dns',''))
    elif kind == 'network-helper':
        plan = catalog.package_plan(['iproute2', 'python3-yaml'], 'Install network configuration helpers')
    elif kind == 'activate': actions.activate(request['id']); return
    elif kind == 'hardening-install': plan = lynis.install_profile(request['profile'])
    elif kind == 'lynis-control': plan = lynis.plan(request['control'], request)
    elif kind == 'lynis-report':
        rows = lynis.findings()
        print(table(['Type', 'Control', 'Aegis support', 'Finding'], [(x['kind'], x['id'], x['coverage'], x['description']) for x in rows]) if rows else 'No readable Lynis report found. Run a Lynis audit first.')
        return
    elif kind == 'security-inspect':
        inspect_security(request)
        return
    elif kind == 'undo-picker':
        ui = UI(console.LANGUAGE)
        entries = []
        for path in sorted((actions.STATE / 'backups').glob('*/manifest.json'), reverse=True):
            value = json.loads(path.read_text())
            entries.append((value['id'], value['id'] + ' | ' + value['title'], 'State: ' + value['status'] + '. Undo uses recorded files/permissions/runtime values; package undo is conditional.'))
        selected = ui.choose('Undo actions / backups', entries) if entries else None
        if selected and selected != '__refresh__' and console.confirm('Undo ' + selected + '?'):
            actions.rollback(selected)
            manifest=json.loads((actions.STATE/'backups'/selected/'manifest.json').read_text())
            if manifest.get('operation','').startswith('program-'):
                print('Program version changed. Reopen Aegis to use the restored program.')
                raise SystemExit(90)
        return
    elif kind == 'sysctl': plan = security.sysctl_plan()
    elif kind == 'apparmor': plan = security.apparmor_plan(request['profile'], request['mode'])
    elif kind in ('ban', 'unban'):
        plan = security.authentication_plan(request['jail'], request['ip'], kind == 'ban')
    elif kind == 'docker-access':
        account = pwd.getpwnam(user)
        if account.pw_uid < 1000: raise ValueError('Select a regular desktop account')
        if system.command(['getent', 'group', 'docker'])[0]: raise ValueError('docker group does not exist; install Docker first')
        plan = actions.Plan('Grant Docker group access',
            details=['Account: ' + user, 'Docker group membership grants root-equivalent host access.',
                     'Log out and back in before running WinBoat.'],
            backup_paths=['/etc/group', '/etc/gshadow'], commands=[['usermod', '-aG', 'docker', user]])
    elif kind == 'repair-policy':
        with actions.state_lock():
            text = system.read(actions.POLICY)
            if '# Aegis managed temporary service-start guard' not in text:
                raise ValueError('No stale Aegis-owned guard found. Administrator policy remains untouched.')
            print('Remove the stale Aegis service-start guard left by an interrupted package operation.')
            print('Verify no package operation is still running. This does not repair dpkg/package state.')
            if console.confirm('Remove this stale Aegis startup guard?'):
                folder, manifest = actions.backup(actions.Plan('Repair stale startup guard', backup_paths=[str(actions.POLICY)]), '')
                actions.POLICY.unlink()
                manifest['status']='applied'
                actions.save_json(folder/'manifest.json',manifest)
                actions.event('applied',manifest['id'],manifest['title'])
                print('Guard removed. Backup ID: '+manifest['id'])
        return
    elif kind == 'maintenance':
        modes = {'refresh': [['apt-get', 'update']], 'upgrade': [['apt-get', 'upgrade']],
                 'clean': [['apt-get', 'clean']], 'ucare': [['ucaresystem-core']]}
        mode = request['mode']
        if mode not in modes: raise ValueError('Invalid maintenance action')
        if mode == 'ucare': security.require('ucaresystem-core')
        plan = actions.Plan('Maintenance: ' + mode,
            details=['Inspect the commands before proceeding.',
                     'Package/cache maintenance has no automatic package/data rollback.',
                     'uCareSystem performs its own update/cleanup tasks when selected.'],
            commands=modes[mode], package_change=True,
            backup_paths=['/var/cache/apt/archives'] if mode == 'clean' else (['/etc/apt','/var/cache/apt/archives'] if mode == 'ucare' else []))
    elif kind == 'alerts':
        op = request['op']
        if op not in ('install', 'configure', 'status', 'test', 'uninstall'): raise ValueError('Invalid alert operation')
        folder=manifest=None
        if op in ('install','configure','uninstall'):
            if not console.confirm('Start alert setup/removal with a configuration/program backup?'): return
            timer='linux-telegram-alerts.timer'
            enabled=system.command(['systemctl','is-enabled',timer])[1]=='enabled'
            active=system.service(timer)=='active'
            snapshot=actions.Plan('Telegram alerts: '+op, backup_paths=[
                '/usr/local/sbin/linux-telegram-alerts','/etc/linux-telegram-alerts',
                '/etc/systemd/system/linux-telegram-alerts.service','/etc/systemd/system/linux-telegram-alerts.timer'],
                rollback_before=[[sys.executable,str(ENTRY),'--alerts-runtime','stop']],
                rollback_commands=[['systemctl','daemon-reload']] +
                    ([['systemctl','enable',timer]] if enabled else []) +
                    ([['systemctl','start',timer]] if active else []), persist_runner=True)
            with actions.state_lock():
                folder,manifest=actions.backup(snapshot,'')
                manifest['status']='setup-started'
                actions.save_json(folder/'manifest.json',manifest)
            print('Alerts backup ID: '+manifest['id']+'; live queue is retained, not rewound.')
        p = subprocess.run([sys.executable, str(ENTRY.parent / 'aegis/alerts.py'), 'install' if op == 'configure' else op],env={**os.environ,'AEGIS_DIALOGS':os.environ.get('AEGIS_DIALOGS','1'),'AEGIS_THEME':console.THEME,'AEGIS_UI_ROOT':str(ENTRY.parent)})
        if manifest:
            manifest['status']='applied' if p.returncode==0 else 'setup-cancelled' if p.returncode in (20,130) else 'setup-failed'
            actions.save_json(folder/'manifest.json',manifest)
            actions.event(manifest['status'],manifest['id'],manifest['title'])
        if p.returncode in (20,130):return False
        if p.returncode: raise RuntimeError('Alerts action returned exit code ' + str(p.returncode))
        return
    elif kind == 'confirm': actions.confirm(request['id'], origin); return
    elif kind == 'rollback':
        if not request.get('automatic') and not console.confirm('Restore this change?'): return
        actions.rollback(request['id'], request.get('automatic', False)); return
    elif kind == 'apparmor-status':
        security.require('aa-status')
        subprocess.run(['aa-status'])
        return
    elif kind == 'lynis':
        security.require('lynis')
        subprocess.run(['lynis', 'audit', 'system', '--quick'])
        return
    elif kind == 'uninstall':
        target = Path('/opt/aegis-linux-hardener')
        launcher = Path('/usr/local/bin/aegis')
        if target.is_symlink() or not (target / '.aegis-managed').is_file():
            raise ValueError('No owned Aegis installation found at /opt/aegis-linux-hardener')
        print('Remove program/launcher. Existing alerts, reports and state remain. A recoverable program snapshot is kept.')
        if not console.confirm('Remove Aegis program files?'): return
        with actions.state_lock():
            folder, manifest = actions.backup(actions.Plan('Uninstall Aegis program',
                backup_paths=[str(target),str(launcher)], persist_runner=True), '')
            manifest['operation']='program-uninstall'
            print('UNDO: sudo '+sys.executable+' '+manifest['runner']+' rollback '+manifest['id'])
            if launcher.exists() and 'aegis-linux-hardener' in launcher.read_text(): launcher.unlink()
            shutil.rmtree(target)
            manifest['status']='applied'
            actions.save_json(folder/'manifest.json',manifest)
            actions.event('applied',manifest['id'],manifest['title'])
        print('Aegis removed. The separate alerts collector is retained.')
        return
    elif kind == 'history':
        print(system.read(actions.STATE / 'history.jsonl', 'No readable history.'))
        for path in sorted((actions.STATE / 'backups').glob('*/manifest.json')):
            value = json.loads(path.read_text())
            print(value['id'], value['status'], value['title'])
        return
    else: raise ValueError('Unknown action')
    if kind == 'app':
        previous_guard = plan.guard
        def app_guard():
            if catalog.app_version(request['app']):
                raise RuntimeError('Application became installed while preparing the plan; refresh and inspect it')
            if previous_guard: previous_guard()
            for path in ('/etc/caddy/Caddyfile', '/etc/webmin/miniserv.conf'):
                if path in plan.late_writes and Path(path).exists():
                    raise RuntimeError('New existing configuration detected; refusing overwrite: ' + path)
        plan.guard = app_guard
    actions.apply(plan, origin)


def output(args):
    code, text, error = system.command(args)
    return (text + ('\n' + error if error else '')).strip() or ('Exit code: ' + str(code))


def dashboard():
    s = system.snapshot()
    m = s['memory']
    lines = [s['hostname'], s['os'], 'Kernel: {} | Architecture: {}'.format(s['kernel'], s['architecture']),
             'CPU: {} | {} threads'.format(s['cpu'], s['cpu_threads']),
             'CPU now: {}% | Load 1/5/15m: {}'.format(s['cpu_pct'], ', '.join('{:.2f}'.format(x) for x in s['load'])),
             'RAM: {:.1f}% of {:.2f} GiB | Swap: {:.1f}% of {:.2f} GiB'.format(m['used_pct'], m['total_gib'], m['swap_pct'], m['swap_gib']),
             'Uptime: {:.2f} hours | Virtualization: {}'.format(s['uptime_hours'], s['virtualization']),
             'Desktop detected: {} | Reboot flag: {}'.format(s['desktop_detected'], s['reboot_required']), '',
             'Network:', s['addresses'], s['default_route'], s['dns'], '',
             table(['Filesystem', 'GiB', 'Used %', 'Inodes %'], [(x['path'], '{:.1f}'.format(x['gib']), '{:.1f}'.format(x['used_pct']),
                  '{:.1f}'.format(x['inode_pct']) if x['inode_pct'] is not None else 'n/a') for x in s['filesystems']]), '',
             'SSH: {} | Fail2Ban: {} | AppArmor: {}'.format(s['ssh'], s['fail2ban'], s['apparmor']),
             'Firewall: ' + s['firewall'], 'Telegram timer: ' + s['alerts'],
             'Updates listed from local APT cache; use Maintenance to inspect/refresh.', 'Collected: ' + s['timestamp']]
    return '\n'.join(lines)


def process_table(sort):
    return ('CPU % is sampled over a short interval; 100% = one logical CPU. RAM = RSS.\n\n' +
        table(['PID', 'User', 'CPU %', 'RSS MiB', 'Process'], [(p['pid'], p['user'], '{:.1f}'.format(p['cpu_pct']),
                    '{:.1f}'.format(p['rss_mib']), p['name']) for p in system.processes(sort)]))


def pause():
    console.pause()


def do(ui, request):
    console.LANGUAGE = ui.language
    request['language'] = ui.language
    request['interactive'] = True
    request['theme'] = ui.theme
    console.section(ui.t('Action / questions', 'Ενέργεια / ερωτήσεις'))
    try: call_root(request)
    except (console.Cancelled,KeyboardInterrupt):print('\nCancelled / interrupted; returned to menu. Check change history if an operation had started.')
    except Exception as error: print('\n' + str(error), file=sys.stderr)
    pause()


def prepare_dependencies(ui,request):
    request.setdefault('user',original_user())
    if all(dependencies.available(row) for row in dependencies.requirements(request)):return True
    console.LANGUAGE=ui.language
    return call_root({'kind':'dependencies-only','target':request,'language':ui.language}) is not False


@console.cancellable_menu
def monitors(ui):
    while True:
        selected = ui.choose(ui.t('System Monitor', 'Παρακολούθηση συστήματος'), [
            ('tools','Monitoring applications','All relevant installed/app-installable CPU, disk, network and container monitors. Missing tools can be installed and opened here.'),
            ('ram', 'Top RAM processes', 'Resident memory usage, sorted descending. Refresh with r.'),
            ('cpu', 'Top CPU processes', 'Current sampled CPU use; this is not lifetime-average ps CPU.'),
            ('ports', 'Listening ports', 'Local TCP/UDP listeners. Process details may require root.'),
            ('connections', 'Connections', 'Established TCP connections, without packet contents.'),
            ('services', 'Failed services', 'Failed systemd service units.'),
            ('docker', 'Docker containers', 'Container state. Missing Docker does not affect other pages.'),
            ('disks', 'Filesystems', 'Capacity, usage and inode usage.'),
            ('btop', 'Open btop', 'Optional interactive resource monitor.'),
            ('ncdu', 'Open ncdu (read-only)', 'Inspect disk usage; deletion is disabled.')])
        if selected is None: return
        if selected=='tools': monitoring_tools(ui)
        elif selected in ('cpu', 'ram'): ui.view('Top ' + selected.upper(), lambda: process_table(selected))
        elif selected in ('ports', 'connections', 'services', 'docker'):
            if selected in ('ports','connections') and not prepare_dependencies(ui,{'kind':'monitor-command','command':'ss'}):continue
            if selected=='docker' and not prepare_dependencies(ui,{'kind':'open-app','app':'docker'}):continue
            commands = {'ports': ['ss', '-lntup'], 'connections': ['ss', '-ntp', 'state', 'established'],
                        'services': ['systemctl', '--failed', '--no-pager'], 'docker': ['docker', 'ps', '-a']}
            ui.view(selected, lambda: output(commands[selected]) )
        elif selected == 'disks': ui.view('Filesystems', lambda: dashboard().split('Network:', 1)[-1])
        elif selected in ('btop', 'ncdu'):
            if not shutil.which(selected):
                do(ui,{'kind':'open-app','app':selected,'user':original_user()});continue
            subprocess.run([selected] if selected == 'btop' else ['ncdu', '-r', '/'])


MONITOR_APPS={'btop','htop','glances','nmon','collectl','iotop','ncdu','pydf','hddtemp','lm-sensors',
    'iftop','iptraf','nload','nethogs','bmon','tcptrack','vnstat','apachetop','bandwhich','netscanner','nmap','rtop','termshark','tcpdump',
    'docker-dash','dockmate','dtop','lazydocker'}


@console.cancellable_menu
def monitoring_tools(ui):
    while True:
        versions=catalog.catalog_versions()
        entries=[(key,label+(' [Installed]' if versions.get(key) else ' [Install + open]'),catalog.app_information(key,versions.get(key)))
                 for key,label,*_ in catalog.visible_apps() if key in MONITOR_APPS or (key.startswith('custom-') and catalog.category_for(key) in ('Dashboards','System & hardware'))]
        key=ui.choose('Monitoring applications',entries)
        if key is None:return
        if key=='__refresh__':continue
        detail=''
        if key in ('iftop','tcptrack','tcpdump'):
            chosen=ui.choose('Interface',[(name,name,'Use this interface.') for _,name in system.socket.if_nameindex() if name!='lo'])
            if not chosen or chosen=='__refresh__':continue
            detail=chosen
        elif key in ('apachetop','termshark'):detail=ui.prompt('Log file / PCAP path','Διαδρομή log / PCAP','/var/log/apache2/access.log' if key=='apachetop' else '')
        elif key=='hddtemp':detail=ui.prompt('Disk device','Συσκευή δίσκου','/dev/sda')
        do(ui,{'kind':'open-app','app':key,'user':original_user(),'detail':detail})


@console.cancellable_menu
def fail2ban_menu(ui):
    while True:
        version=system.installed('fail2ban')
        choice = ui.choose('Fail2Ban Manager', [
            ('status', 'Status / jails', 'Show current Fail2Ban server state.'),
            ('install', installed_label('Install Fail2Ban',version), 'Install fail2ban and python3-systemd using configured APT repositories.'),
            ('configure', 'Configure protection', 'Select available jails, whitelist, thresholds and SSH port.'),
            ('jail', 'Inspect jail', 'Show banned IPs and counters for one jail.'),
            ('ban', 'Ban IP', 'Explicit live ban in a selected jail.'), ('unban', 'Unban IP', 'Explicit live unban.')])
        if choice is None: return
        if choice in ('status','configure','jail','ban','unban') and not prepare_dependencies(ui,{'kind':'fail2ban'}):continue
        if choice == 'status': ui.view('Fail2Ban', lambda: output(['fail2ban-client', 'status']))
        elif choice == 'install':
            if version:ui.view('Fail2Ban',lambda: output(['fail2ban-client','status']))
            else:do(ui, {'kind':'install-security','package':'fail2ban'})
        elif choice == 'configure':
            if not prepare_dependencies(ui,{'kind':'fail2ban'}):continue
            jails = security.available_jails()
            if not jails: ui.error('Install Fail2Ban first. No available filter files detected.'); continue
            print('\nAvailable filters: ' + ', '.join(key for key, _ in jails))
            print('Only select application jails whose real logs exist. Other configured jails remain unchanged.')
            source = system.ssh_connection().split()
            request = {'kind': 'fail2ban',
                'jails': ui.prompt('Jails, space-separated', 'Jails με κενά', 'sshd').split(),
                'ignore': ui.prompt('Trusted IPs/networks, space-separated', 'Έμπιστες IP/δίκτυα', source[0] if source else ''),
                'retries': ui.prompt('Max retries', 'Μέγιστες αποτυχίες', '6'),
                'window': ui.prompt('Find time, seconds', 'Χρονικό παράθυρο, δευτερόλεπτα', '600'),
                'duration': ui.prompt('Ban time, seconds', 'Διάρκεια αποκλεισμού, δευτερόλεπτα', '900'),
                'port': ui.prompt('Actual SSH port', 'Πραγματική θύρα SSH', source[3] if len(source) == 4 else '22')}
            do(ui, request)
        elif choice in ('jail', 'ban', 'unban'):
            jail = ui.prompt('Jail name', 'Όνομα jail', 'sshd')
            if choice == 'jail':
                try: security.jail_name(jail); ui.view(jail, lambda: output(['fail2ban-client', 'status', jail]))
                except Exception as error: ui.error(error)
            else: do(ui, {'kind': choice, 'jail': jail, 'ip': ui.prompt('IP address', 'Διεύθυνση IP')})


@console.cancellable_menu
def firewall_menu(ui):
    while True:
        version=system.installed('ufw')
        choice = ui.choose('Firewall Manager', [('status', 'Status / existing rules', 'Inspect UFW and nftables before changing anything.'),
            ('install', installed_label('Install UFW',version), 'Install host firewall tools; this action does not explicitly enable UFW.'),
            ('allow', 'Allow source to port', 'Add one scoped rule; timed rollback protects the operation.'),
            ('enable', 'Enable UFW with SSH access', 'Preserves existing rules/policies. Confirm actual SSH port and source. Docker ports need separate review.')])
        if choice is None: return
        if choice == 'status':
            ui.view('Firewall', lambda: '\n'.join(system.command(cmd)[1] or system.command(cmd)[2] for cmd in
                    [['ufw', 'status', 'verbose'], ['ufw', 'status', 'numbered'], ['nft', 'list', 'ruleset']]))
        elif choice == 'install':
            if version:ui.view('UFW',lambda: output(['ufw','status','verbose']))
            else:do(ui, {'kind':'install-security','package':'ufw'})
        elif choice in ('allow', 'enable'):
            source = system.ssh_connection().split()
            do(ui, {'kind': 'ufw', 'mode': choice,
                'source': ui.prompt('Trusted source IP/network', 'Έμπιστη IP/δίκτυο', source[0] if source else '127.0.0.1/32'),
                'port': ui.prompt('SSH port' if choice == 'enable' else 'Destination port', 'Θύρα προορισμού', source[3] if len(source) == 4 else '22'),
                'protocol': 'tcp' if choice == 'enable' else ui.prompt('Protocol tcp/udp', 'Πρωτόκολλο tcp/udp', 'tcp')})


@console.cancellable_menu
def hardening_menu(ui):
    while True:
        installed=catalog.package_versions()
        choice = ui.choose(ui.t('Security & Hardening', 'Ασφάλεια & Hardening'), [
            ('fail2ban-manager','Fail2Ban Manager','Install/configure Fail2Ban, inspect jails and ban/unban events.'),
            ('firewall-manager','Firewall Manager','Inspect firewall rules and apply protected UFW changes.'),
            ('lynis-controls', 'Lynis recommendations / controls', 'Review findings and choose individual remediations with backup/undo.'),
            ('audit', 'Security overview', 'Read-only inventory of security configuration; no compliance score is invented.'),
            ('lynis', 'Run Lynis audit', 'Optional upstream auditor. Reports findings; does not automatically remediate them.'),
            ('root-password', 'SSH: block root password login', 'Keep public-key root login available. Preview effective settings and timed rollback.'),
            ('keys-only', 'SSH: public keys only', 'Requires a verified working key login for your selected account.'),
            ('limits', 'SSH: authentication limits', 'MaxAuthTries=3 and LoginGraceTime=30; separately selectable.'),
            ('sysctl', 'Kernel/filesystem baseline', 'Four scoped kernel/filesystem settings; routing and Docker forwarding untouched.'),
            ('apparmor-status', 'AppArmor status / profiles', 'Show kernel enforcement state and loaded profiles.'),
            ('apparmor-install', installed_label('Install AppArmor utilities','ready' if all(installed.get(p) for p in ('apparmor','apparmor-utils','apparmor-profiles')) else None), 'Install profiles and management tools through APT.'),
            ('apparmor', 'AppArmor: choose profile mode', 'Select a single profile, then complain or enforce.'),
            ('defense-portsentry', 'PortSentry', defense.information('portsentry')),
            ('defense-knockd', 'knockd', defense.information('knockd')),
            ('defense-shorewall', 'Shorewall', defense.information('shorewall')),
            ('updates', installed_label('Automatic security updates',installed.get('unattended-upgrades')), 'Install unattended-upgrades and enable periodic upgrades without automatic reboot.')])
        if choice is None: return
        if choice=='fail2ban-manager':fail2ban_menu(ui)
        elif choice=='firewall-manager':firewall_menu(ui)
        elif choice and choice.startswith('defense-'): defense_menu(ui,choice[8:])
        elif choice == 'lynis-controls': lynis_menu(ui)
        elif choice == 'audit': ui.view('Security overview', lambda: table(['Check', 'State', 'Details'], system.audit()))
        elif choice == 'lynis': do(ui, {'kind': 'lynis'})
        elif choice in ('root-password', 'keys-only', 'limits'):
            source = system.ssh_connection().split()
            request = {'kind': 'ssh', 'mode': choice,
                       'user': ui.prompt('Management account', 'Λογαριασμός διαχείρισης', original_user()),
                       'source': ui.prompt('Management client IP', 'IP πελάτη διαχείρισης', source[0] if source else '127.0.0.1')}
            if choice == 'keys-only':
                request['keys_verified'] = console.confirm('Have you verified key login from a NEW independent SSH session?')
            do(ui, request)
        elif choice == 'apparmor-status': do(ui, {'kind': 'apparmor-status'})
        elif choice == 'sysctl': do(ui, {'kind': 'sysctl'})
        elif choice in ('apparmor-install', 'updates'):
            do(ui, {'kind': 'install-security', 'package': 'apparmor' if choice.startswith('apparmor') else 'updates'})
        elif choice == 'apparmor':
            if not prepare_dependencies(ui,{'kind':'apparmor','mode':'enforce'}):continue
            profiles = [p for p in Path('/etc/apparmor.d').glob('*') if p.is_file() and not p.is_symlink() and not p.name.startswith('.')]
            selected = ui.choose('AppArmor profiles', [(str(p), p.name, 'Change this profile only.') for p in profiles]) if profiles else None
            if selected and selected != '__refresh__':
                mode = ui.prompt('Mode: complain/enforce', 'Λειτουργία complain/enforce', 'complain')
                do(ui, {'kind': 'apparmor', 'profile': selected, 'mode': mode})


@console.cancellable_menu
def defense_menu(ui,key):
    while True:
        version=system.installed(key)
        choice=ui.choose(defense.TOOLS[key][0],[('install',installed_label('Install (inactive)',version),defense.information(key)),
            ('status','Status / logs',defense.information(key)),
            ('info','Configuration / guidance',defense.information(key))])
        if choice is None:return
        if choice=='install':
            if version:do(ui,{'kind':'defense-status','tool':key})
            else:do(ui,{'kind':'defense-install','tool':key})
        elif choice=='status':do(ui,{'kind':'defense-status','tool':key})
        elif choice=='info':ui.view(defense.TOOLS[key][0],defense.information(key))


@console.cancellable_menu
def apps_menu(ui):
    while True:
        entries=[('search','Search applications','Live filtering by name, APT package, category and description.'),('all','All applications','Complete alphabetical catalog, with uCareSystem pinned first.')]
        visible=catalog.visible_apps()
        custom_categories={row['key']:row['category'] for row in appregistry.load()['custom']}
        for category,_ in categories.GROUPS:
            count=sum(custom_categories.get(row[0],categories.category(row[0]))==category for row in visible)
            entries.append((category,category+' ('+str(count)+')','Applications grouped by purpose; empty categories are placeholders for future additions.'))
        entries += [('docker-access','Docker: grant desktop user access','Explicit root-equivalent group membership.'),('freerdp','FreeRDP 3 client','Optional WinBoat desktop dependency.')]
        selected=ui.choose('App Installer — categories',entries)
        if selected is None:return
        if selected=='__refresh__':continue
        if selected=='search':
            versions=catalog.catalog_versions();candidates=catalog.package_candidates()
            rows=[(key,installed_label(name,versions.get(key)),catalog.app_information(key,versions.get(key),catalog.capability(key,candidates))) for key,name,*_ in catalog.visible_apps(candidates)]
            found=appsearch.run(ui,rows)
            if found and found!='__refresh__':app_actions(ui,found)
        elif selected=='docker-access':do(ui,{'kind':'docker-access','user':ui.prompt('Desktop user','Χρήστης desktop',original_user())})
        elif selected=='freerdp':do(ui,{'kind':'install-security','package':'freerdp'})
        else:app_category(ui,selected)


@console.cancellable_menu
def app_category(ui,group):
    while True:
        versions=catalog.catalog_versions();candidates=catalog.package_candidates()
        rows=[row for row in catalog.visible_apps(candidates) if group=='all' or catalog.category_for(row[0])==group]
        if not rows:ui.view(group,'No catalog applications in this category yet. / Δεν υπάρχουν ακόμη εφαρμογές σε αυτή την κατηγορία.');return
        entries=[]
        for key,name,*_ in rows:
            availability=catalog.capability(key,candidates)
            marker=' [Installed]' if versions.get(key) else (' [Source build]' if availability[0]=='source' else ' [Guide only]' if availability[0]=='guide' else ' [Unavailable]' if availability[0]=='unavailable' else '')
            entries.append((key,name+marker,catalog.app_information(key,versions.get(key),availability)))
        entries.append(('apt-refresh','Refresh APT metadata','Recheck suite package availability after an explicit apt-get update.'))
        choice=ui.choose('App Installer' if group=='all' else group,entries)
        if choice is None:return
        if choice=='__refresh__':continue
        if choice=='apt-refresh':do(ui,{'kind':'maintenance','mode':'refresh'})
        else:app_actions(ui,choice)


@console.cancellable_menu
def app_actions(ui,key):
    """Installed applications offer Open/Details rather than a failed reinstall."""
    while True:
        version=catalog.app_version(key)
        name=next(row[1] for row in catalog.all_apps() if row[0]==key)
        availability=catalog.capability(key,catalog.package_candidates())
        info=catalog.app_information(key,version,availability)
        entries=[]
        if version:
            entries.append(('open','Open / usage instructions',info))
            entries.append(('uninstall','Uninstall (keep data/config)',info+'\nRemoval is reviewed and backed up; package Undo depends on exact old versions.'))
        elif availability[0] not in ('guide','unavailable'):
            entries.append(('install','Build / install from source' if availability[0]=='source' else 'Install application',info))
        else:
            entries.append(('apt-refresh','Refresh APT metadata and recheck',info))
        entries += [('details','Why unavailable / instructions' if availability[0] in ('guide','unavailable') and not version else 'Application details',info),('refresh','Refresh installed status',info)]
        choice=ui.choose(name+(' [Installed]' if version else ' [Not installed]'),entries)
        if choice is None:return
        if choice=='install':
            user=ui.prompt('Desktop user','Χρήστης desktop',original_user()) if key=='winboat' else original_user()
            do(ui,{'kind':'app','app':key,'user':user})
        elif choice=='apt-refresh':do(ui,{'kind':'maintenance','mode':'refresh'})
        elif choice=='uninstall':do(ui,{'kind':'uninstall-app','app':key,'user':original_user()})
        elif choice=='open':
            if key=='nmtui':do(ui,{'kind':'nmtui'});continue
            if key in launch.GUIDES:ui.view(name,launch.GUIDES[key]);continue
            detail=''
            if key in ('iftop','tcptrack','tcpdump'):
                selected=ui.choose('Capture interface',[(iface,iface,'Open the selected tool on this interface.') for _,iface in system.socket.if_nameindex() if iface!='lo'])
                if not selected or selected=='__refresh__':continue
                detail=selected
            elif key in ('apachetop','termshark'):
                detail=ui.prompt('Log file' if key=='apachetop' else 'PCAP file','Αρχείο log / PCAP','/var/log/apache2/access.log' if key=='apachetop' else '')
            elif key=='hddtemp':detail=ui.prompt('Disk device','Συσκευή δίσκου','/dev/sda')
            do(ui,{'kind':'open-app','app':key,'detail':detail,'user':original_user()})
        elif choice=='details':ui.view(name,info)


def installed_label(label,version):
    return label+(' [Installed]' if version else '')


@console.cancellable_menu
def help_menu(ui):
    """The packaged READMEs are the single source of the in-app help."""
    while True:
        name='README.el.md' if ui.language=='el' else 'README.md'
        path=ENTRY.parent/name
        try:text=path.read_text()
        except OSError:ui.error('README is unavailable. Keep the complete source folder or rerun the standalone installer.');return
        # Web badges are omitted in terminal Help; all guide sections remain available.
        text=re.sub(r'(?ms)^<!-- aegis:badges -->\n.*?^<!-- /aegis:badges -->\n?', '', text)
        sections=re.split(r'(?m)^## ',text)
        entries=[('all',ui.t('Complete user guide','Πλήρης οδηγός χρήσης'),ui.t('Full documentation. Page Up/Down to scroll; q to return.','Πλήρης τεκμηρίωση. Page Up/Down για κύλιση, q για επιστροφή.'))]
        entries += [(str(i),section.splitlines()[0],section.splitlines()[0]) for i,section in enumerate(sections[1:],1)]
        choice=ui.choose('Help',entries)
        if choice is None:return
        if choice=='all':ui.view(ui.t('Help — User guide','Βοήθεια — Οδηγός χρήσης'),text)
        elif choice.isdigit() and 0<int(choice)<len(sections):ui.view(sections[int(choice)].splitlines()[0],'## '+sections[int(choice)])


@console.cancellable_menu
def alerts_menu(ui):
    while True:
        choice = ui.choose('Linux Telegram Alerts', [('install', installed_label('Install / reconfigure','present' if Path('/usr/local/sbin/linux-telegram-alerts').exists() else None), 'Existing token, destination and queue are preserved. Uses the existing timer identity.'),
            ('status', 'Status', 'Show enabled categories and pending queue.'), ('test', 'Send test', 'Send a test through the queue.'),
            ('logs', 'Worker logs', 'Inspect recent collection and delivery logs.'),
            ('uninstall', 'Uninstall alerts', 'Separate confirmation. Keeps configuration, token and queue for recovery.')])
        if choice is None: return
        if choice == 'logs': ui.view('Alerts logs', lambda: output(['journalctl', '-u', 'linux-telegram-alerts.service', '-n', '50', '--no-pager']))
        elif choice != '__refresh__': do(ui, {'kind': 'alerts', 'op': choice})


@console.cancellable_menu
def maintenance_menu(ui):
    while True:
        choice = ui.choose('Maintenance', [('available', 'Available updates', 'Read local APT metadata. No automatic refresh.'),
            ('refresh', 'Refresh APT metadata', 'Explicit apt-get update.'), ('upgrade', 'Upgrade system packages', 'APT confirms dependencies. No automatic reboot.'),
            ('clean', 'Clean APT package cache', 'Removes downloaded cache files; not reversible.'),
            ('ucare', 'Run uCareSystem Core', 'Runs upstream maintenance only after explicit confirmation.'),
            ('repair-policy', 'Repair stale package startup guard', 'Only after an interrupted Aegis install; never removes an unrelated administrator policy.')])
        if choice is None: return
        if choice == 'repair-policy': do(ui, {'kind': 'repair-policy'})
        elif choice == 'available': ui.view('Available updates (local metadata)', lambda: output(['apt', 'list', '--upgradable']))
        elif choice != '__refresh__': do(ui, {'kind': 'maintenance', 'mode': choice})


@console.cancellable_menu
def settings_menu(ui):
    choice = ui.choose('Settings', [('language', 'Language / Γλώσσα', 'English or Greek for Aegis menus. Alerts retain their independently selected language.'),
                                  ('theme', 'Theme', 'Slate, Blue, Nord, Dracula, Gruvbox, Solarized, Forest, Amber, Light and Plain.'),
                                  ('catalog', 'Manage App Installer list', 'Add APT applications, hide/remove entries and restore supported built-ins; backups and Undo.'),
                                  ('remove', 'Uninstall Aegis', 'Remove the program only; preserve existing alerts and recovery data.'),
                                  ('update', 'Check / install update', 'Fetch release metadata and a verified installer from karanik.gr; explicit approval and program backup.'),
                                  ('about', 'About / update', 'Version, documentation and installation/update command.')])
    if choice == 'language':
        ui.language = 'el' if ui.prompt('1 English / 2 Ελληνικά', '1 English / 2 Ελληνικά', '1') == '2' else 'en'
        save_preferences(ui)
    elif choice == 'theme':
        value=ui.prompt('Theme','Χρωματικό θέμα',ui.theme,choices=list(themes.PALETTES))
        if value in themes.PALETTES:ui.theme=value;console.THEME=value;save_preferences(ui)
    elif choice == 'catalog':do(ui,{'kind':'catalog-manager'})
    elif choice == 'update':
        try:
            if call_root({'kind':'self-update','language':ui.language,'theme':ui.theme}):raise SystemExit(0)
            console.pause()
        except (console.Cancelled,KeyboardInterrupt):pass
        except Exception as error:ui.error(error)
    elif choice == 'remove': do(ui, {'kind': 'uninstall'}); raise SystemExit(0)
    elif choice == 'about': ui.view(TITLE, TAGLINE + '\nVersion: ' + VERSION + '\n\nStart mode: ' + ('INSTALLED' if ENTRY.parent == Path('/opt/aegis-linux-hardener') else 'PORTABLE / SOURCE') + '\nProgram path: ' + str(ENTRY.parent) + '\n\nRun install-aegis.sh --install to install/update, or --portable to run without a launcher.\n'
            'Update source: https://karanik.gr/scripts/linux/aegis-linux-hardener/install-aegis.sh\n'
            'Use Settings > Check / install update. Hosting also requires release.json and optionally update-aegis.sh.\nRead README.md / README.el.md in the release.')


@console.cancellable_menu
def network_menu(ui):
    while True:
        ui.refresh_context()
        nmtui_version=catalog.app_version('nmtui')
        helpers_installed=all(system.installed(x) for x in ('iproute2','python3-yaml'))
        choice = ui.choose('Network Settings', [
            ('hostname','Change hostname','Change static/transient machine name, optionally update local hosts mapping; includes Undo.'),
            ('configure', 'Configure interface: static / DHCP', 'Select a simple link. Persistent manager configuration, private backup and independent activation with rollback.'),
            ('status', 'Addresses / routes / DNS', 'Read-only current network information.'),
            ('nmtui', installed_label('Open nmtui (NetworkManager)',nmtui_version), 'Native text UI; needs active NetworkManager. Native 150s checkpoint + configuration backup. No automatic backend migration.'),
            ('nmtui-install', installed_label('Install nmtui',nmtui_version), catalog.app_information('nmtui',nmtui_version)),
            ('dns','DNS Settings','Edit DNS independently of IP/gateway, using the current manager with protected rollback.'),
            ('hosts','Edit /etc/hosts','Add/edit/delete validated host mappings with backup; core localhost entries are protected.'),
            ('helpers', installed_label('Install network helpers','ready' if helpers_installed else None), 'Install iproute2 and python3-yaml through APT if required by this host.')])
        if choice is None: return
        if choice=='hostname':
            value=ui.prompt('New hostname / FQDN','Νέο hostname / FQDN',system.socket.gethostname())
            update=console.confirm('Update the local /etc/hosts hostname mapping too?')
            do(ui,{'kind':'hostname','hostname':value,'update_hosts':update})
        elif choice=='dns':do(ui,{'kind':'dns-browser','user':original_user()})
        elif choice=='hosts':do(ui,{'kind':'hosts-browser'})
        elif choice == 'nmtui':do(ui,{'kind':'nmtui'})
        elif choice == 'nmtui-install':app_actions(ui,'nmtui')
        elif choice == 'helpers':
            if helpers_installed:ui.view('Network helpers','iproute2 and python3-yaml are installed.')
            else:do(ui, {'kind':'network-helper'})
        elif choice == 'status': ui.view('Network', lambda: output(['ip','-br','address']) + '\n\n' + output(['ip','route']) + '\n\n' + system.read('/etc/resolv.conf'))
        elif choice == 'configure':
            if not prepare_dependencies(ui,{'kind':'network-configure'}):continue
            try: links = networking.interfaces()
            except Exception as error: ui.error(error); continue
            iface = ui.choose('Select network interface', [(x['name'], x['name'] + ' | ' + x['state'], 'Addresses: ' + ', '.join(x['addresses']) + ' | MAC: ' + x['mac']) for x in links])
            if not iface or iface == '__refresh__': continue
            selected = next(x for x in links if x['name'] == iface)
            mode = ui.choose('IPv4 mode', [('static','Static IPv4','Enter CIDR, gateway and optionally DNS. IPv6 addressing is retained.'),
                                          ('dhcp','DHCP / automatic','Use a DHCP lease for IPv4. Reconnect using the assigned address and confirm.')])
            if mode not in ('static','dhcp'): continue
            console.section('Network configuration — ' + iface)
            print('Current: ' + ', '.join(selected['addresses']))
            request = {'kind':'network', 'iface':iface, 'mode':mode}
            if mode == 'static':
                current = next((x for x in selected['addresses'] if ':' not in x), '')
                route = system.command(['ip','-j','route','show','default','dev',iface])[1]
                try: gateway = next((x.get('gateway','') for x in json.loads(route or '[]')), '')
                except ValueError: gateway = ''
                request['address'] = ui.prompt('IPv4 address / prefix (CIDR)', 'IPv4 / πρόθεμα (CIDR)', current)
                request['gateway'] = ui.prompt('Gateway (- means none)', 'Gateway (- για κανένα)', gateway or '-')
                request['dns'] = ui.prompt('DNS servers, comma/space separated (- keeps current)', 'DNS με κόμμα/κενό (- διατήρηση)', '-')
            print('\nThe SSH session may disconnect. Activation continues independently.\nA 180-second rollback timer restores the previous configuration unless confirmed from a new connection.')
            do(ui, request)


def inspect_security(request):
    check = request['check']
    if check == 'repos': print('\n'.join(lynis.repository_audit())); return
    if check == 'hashing':
        print('PAM password module (no password hashes):\n' + '\n'.join(line for line in system.read('/etc/pam.d/common-password').splitlines() if line and not line.lstrip().startswith('#')))
        print('\nlogin.defs algorithm/defaults:\n' + '\n'.join(line for line in system.read('/etc/login.defs').splitlines() if re.match(r'^(ENCRYPT_METHOD|YESCRYPT|SHA_CRYPT|PASS_|UMASK)',line)))
        return
    commands = {'needrestart':['needrestart','-r','l'], 'debsums':['debsums','-s'],
                'deleted':['lsof','+L1'], 'audit':['auditctl','-l'], 'versions':['apt-show-versions'],
                'aide':['aide.wrapper','--check'] if shutil.which('aide.wrapper') else ['aide','--check','--config=/var/lib/aide/aide.conf.autogenerated']}
    if check == 'service':
        unit = request['unit']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9@_.:-]*\.service',unit): raise ValueError('Invalid service name')
        commands[check] = ['systemd-analyze','security',unit,'--no-pager']
    if check == 'vulnerabilities':
        base = system.os_release()
        suite = base.get('VERSION_CODENAME','')
        if base.get('ID') != 'debian' or suite not in ('bookworm','trixie'):
            print('Use your distribution security tracker. This debsecan helper is limited to known Debian suites.'); return
        commands[check] = ['debsecan','--suite',suite,'--format','packages']
    if check not in commands: raise ValueError('Unknown inspection')
    security.require(commands[check][0])
    print('Read-only inspection. Findings may return a nonzero exit code without implying a program failure.\n')
    subprocess.run(commands[check])


@console.cancellable_menu
def lynis_menu(ui):
    while True:
        choice = ui.choose('Lynis recommendations / controls', [
            ('findings','Read latest Lynis findings','Read /var/log/lynis-report.dat and show mapped Aegis actions.'),
            ('matrix','Coverage / manual recommendations','Every control from the supplied scan is mapped to an action, inspection or manual review.'),
            ('packages','Security tools / packages','Choose one profile: needrestart, integrity tools, accounting, audit, PAM helpers or scanners.'),
            ('inspect','Diagnostics / security checks','Vulnerable packages, repository mismatch, deleted-open files, integrity and service exposure.'),
            ('ssh-extra','Additional SSH controls','Individual controls. Disabling TCP forwarding breaks SSH tunnels; not selected automatically.'),
            ('core-dumps','Core-dump storage','Restrict new sessions and systemd-coredump storage.'),
            ('login-defaults','Password age / umask defaults','New accounts only; existing users are handled separately.'),
            ('password-quality','Password quality','Configure future password checks after installing libpam-pwquality.'),
            ('account-aging','Aging for one account','Select a normal user. Previous aging values are retained for undo.'),
            ('banners','Login notices','Backup and set /etc/issue and /etc/issue.net.'),
            ('permissions','Sensitive path permissions','Select paths; only mode/owner metadata is backed up, not whole home directories.'),
            ('home-mode','Home directory permissions','One selected /home/USER, non-recursive 0750. Review web roots/shares first.'),
            ('modules','Optional module restrictions','Select protocols/storage individually. Does not unload running modules.'),
            ('sysctl-extra','Optional sysctl controls','Reversible options only. Never locks kernel modules or uses irreversible BPF settings.'),
            ('service','Sandbox one application service','NoNewPrivileges/PrivateTmp; no generic sandbox changes to core SSH/network services.'),
            ('remote-logging','Remote logging','TCP/TLS rsyslog destination with validation and original local logging retained.'),
            ('accounting','Enable process accounting','Install acct first; explicitly enable accounting.'),
            ('sysstat','Enable historical statistics','Install sysstat first, then enable collection.'),
            ('audit-watches','Audit identity / SSH changes','Install auditd first. Adds narrow file watches; no immutable lock.'),
            ('aide-init','Initialize AIDE baseline','Install AIDE first. Trust the host before accepting a baseline. Old database is backed up.'),
            ('locate-update','Build locate database','Install plocate first. Existing database is backed up.'),
            ('apache-waf','Apache ModSecurity / CRS','Existing Apache only. Prepare DetectionOnly, not immediate WAF blocking.'),
            ('apache-evasive','Apache mod_evasive','Existing Apache only. Review proxy/whitelist and vendor thresholds.')])
        if choice is None: return
        if choice == '__refresh__': continue
        if choice == 'findings': do(ui, {'kind':'lynis-report'}); continue
        if choice == 'matrix':
            ui.view('Control coverage', table(['Control','Topic','Support'],[(x[0],x[1],x[2]) for x in lynis.CONTROLS]) + '\n\n' + '\n\n'.join(x[0]+': '+x[3] for x in lynis.CONTROLS)); continue
        if choice == 'packages':
            installed=catalog.package_versions()
            selected = ui.choose('Security package profiles', [(key,installed_label(key,'ready' if all(installed.get(p) for p in packages) else None),', '.join(packages)) for key,packages in lynis.INSTALLS.items()])
            if selected and selected != '__refresh__':
                if all(installed.get(p) for p in lynis.INSTALLS[selected]):ui.view(selected,'All packages in this profile are installed.')
                else:do(ui,{'kind':'hardening-install','profile':selected})
            continue
        if choice == 'inspect':
            options = [('vulnerabilities','Debian vulnerable packages','Requires debsecan; no automatic upgrade/removal.'),
                       ('repos','Repository compatibility','Detect obvious Ubuntu/PPA sources on Debian; do not delete automatically.'),
                       ('needrestart','Old libraries / restart needs','List-only mode.'),('debsums','Package checksums','Differences are not automatic proof of malware.'),
                       ('deleted','Deleted files still open','Requires lsof.'),('hashing','PAM / hashing configuration','Metadata/settings only; never displays hashes.'),
                       ('service','systemd service exposure','Select a unit to inspect.'),('audit','Current audit rules','Requires auditd tools.'),('aide','Check AIDE baseline','Requires an initialized trusted baseline.'),
                       ('versions','Package versions','Requires apt-show-versions.')]
            selected = ui.choose('Security inspections',options)
            if selected and selected != '__refresh__':
                request = {'kind':'security-inspect','check':selected}
                if selected == 'service': request['unit']=ui.prompt('Service unit','Μονάδα υπηρεσίας','apache2.service')
                do(ui,request)
            continue
        if choice == 'ssh-extra':
            selected = ui.choose('Additional SSH controls',[(key,label,desc) for key,label,desc in [
                ('compression','Disable SSH compression','Optional; affects transfer performance.'),('verbose','Verbose authentication logging','Logs more connection/key metadata.'),
                ('sessions','Limit MaxSessions to 2','May affect connection multiplexing.'),('keepalive','Connection liveness settings','300-second interval, count 2; TCPKeepAlive=no.'),
                ('agent-forwarding','Disable agent forwarding','May affect jump-host workflows.'),('tcp-forwarding','Disable TCP forwarding','BREAKS local Webmin/Cockpit tunnels. Not applied by any default profile.'),
                ('banner','Enable SSH login banner','Uses /etc/issue.net; configure notice separately.'),('port','Change SSH port','Allow the new port on all firewalls FIRST. Socket-activated SSH needs manual handling.')]])
            if selected and selected!='__refresh__':
                source=system.ssh_connection().split()
                request={'kind':'ssh','mode':selected,'user':ui.prompt('Management account','Λογαριασμός διαχείρισης',original_user()),
                         'source':ui.prompt('Management client IP','IP διαχείρισης',source[0] if source else '127.0.0.1')}
                if selected=='port':request['value']=ui.prompt('New SSH port','Νέα θύρα SSH','2222')
                do(ui,request)
            continue
        request={'kind':'lynis-control','control':choice}
        if not prepare_dependencies(ui,request):continue
        if choice in ('login-defaults','account-aging'):
            request['min_days']=ui.prompt('Minimum password age, days','Ελάχιστη ηλικία κωδικού','1')
            request['max_days']=ui.prompt('Maximum password age, days','Μέγιστη ηλικία κωδικού','365')
        if choice in ('account-aging','home-mode'):request['user']=ui.prompt('Account','Λογαριασμός',original_user())
        if choice=='password-quality': request['prompt_minlen']=True
        if choice=='permissions':request['paths']=ui.prompt('Targets, space-separated: crontab ssh/sshd_config sudoers.d cron.d cron.daily cron.hourly cron.weekly cron.monthly','Στόχοι με κενά','crontab ssh/sshd_config sudoers.d').split()
        if choice=='modules':request['modules']=ui.prompt('Modules: usb-storage firewire-core dccp sctp rds tipc','Modules με κενά','dccp rds tipc').split()
        if choice=='sysctl-extra':
            ui.view('Optional sysctl controls','\n\n'.join(key+' → '+value+'\n'+desc for key,(value,desc) in lynis.EXTRA_SYSCTL.items()))
            request['keys']=ui.prompt('Keys, space-separated','Κλειδιά με κενά','fs.protected_fifos kernel.core_uses_pid').split()
        if choice=='service':
            request['unit']=ui.prompt('Application service unit','Μονάδα υπηρεσίας εφαρμογής','apache2.service')
            request['options']=ui.prompt('Options: NoNewPrivileges PrivateTmp','Επιλογές με κενά','NoNewPrivileges').split()
        if choice=='remote-logging':
            request['host']=ui.prompt('Logging server DNS name / IP','Logging server DNS / IP')
            request['port']=ui.prompt('Port','Θύρα','6514')
            request['tls']=console.confirm('Use TLS with certificate/name verification?')
        do(ui,request)


def menu(ui):
    overview=panels.LiveDashboard()
    while True:
        ui.refresh_context()
        option = ui.choose(ui.t('Main menu', 'Κεντρικό μενού'), [
            ('dashboard', 'Dashboard', ui.t('OS, kernel, CPU, RAM, disks, network and security status.', 'Λειτουργικό, kernel, CPU, RAM, δίσκοι, δίκτυο και ασφάλεια.')),
            ('users','User Management','Local users/groups, membership/sudo access, passwords, SSH public keys and scoped permissions/ACL.'),
            ('shares','Share Management','Samba install, shares, users, connected clients, service controls and Unix permissions/ACL.'),
            ('monitor', 'System Monitor', ui.t('Current CPU/RAM process tables, ports, services and containers.', 'Διεργασίες CPU/RAM, θύρες, υπηρεσίες και containers.')),
            ('security', 'Security & Hardening', ui.t('Audit first, then preview and approve individual changes.', 'Έλεγχος, προεπισκόπηση και επιλεκτική εφαρμογή αλλαγών.')),
            ('alerts', 'Linux Telegram Alerts', 'Existing 22 notification categories and persistent queue.'),
            ('apps', 'App Installer', 'uCareSystem, btop, ncdu, Lynis, Docker, Caddy, Webmin, WinBoat, Cockpit.'),
            ('maintenance', 'Maintenance', 'Updates, cache cleanup and optional uCareSystem execution.'),
            ('network', 'Network Settings', 'Choose interface, static IPv4/DHCP, gateway and DNS. Protected activation/rollback.'),
            ('logs', 'Logs', 'Categorized journal/files/container logs, ccze -A color, private export and reviewed Telegram attachments.'),
            ('reports', 'Reports & History', 'Export system information, review applied changes and restore managed files.'),
            ('settings', 'Settings', 'Language, appearance, version and documentation.'),
            ('help','Help','Complete README and step-by-step documentation; last menu entry.')], panels={'dashboard':overview.rows})
        if option is None: return
        try:
            if option == 'dashboard': ui.view('Dashboard', dashboard)
            elif option == 'monitor': monitors(ui)
            elif option=='users':do(ui,{'kind':'users-browser','user':original_user()})
            elif option=='shares':do(ui,{'kind':'shares-browser','user':original_user()})
            elif option == 'security': hardening_menu(ui)
            elif option == 'logs':do(ui,{'kind':'logs-browser','user':original_user()})
            elif option == 'help':help_menu(ui)
            elif option == 'alerts': alerts_menu(ui)
            elif option == 'apps': apps_menu(ui)
            elif option == 'maintenance': maintenance_menu(ui)
            elif option == 'settings': settings_menu(ui)
            elif option == 'network': network_menu(ui)
            elif option == 'reports':
                selected = ui.choose('Reports & History', [('undo', 'Undo actions / backups', 'Select a recorded change instead of typing its ID.'), ('export', 'Export system report', 'JSON inventory only; no credentials or raw command lines.'),
                    ('history', 'Change history / backups', 'Requires root to read private records.'),
                    ('restore', 'Restore a change', 'Restore managed settings; package undo depends on retained versions.')])
                if selected == 'undo': do(ui, {'kind': 'undo-picker'})
                elif selected == 'export':
                    name = ui.prompt('Report path', 'Διαδρομή αναφοράς', str(Path.home() / ('aegis-report-' + datetime.date.today().isoformat() + '.json')))
                    path = Path(name).expanduser()
                    if path.exists() and not console.confirm('Overwrite existing report file?'): continue
                    if os.geteuid()==0:
                        do(ui, {'kind':'report-export','path':str(path.resolve())})
                    else:
                        if path.exists():shutil.copy2(path,path.with_name(path.name+'.bak-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')))
                        actions.write_file(path,json.dumps(system.snapshot(),ensure_ascii=False,indent=2)+'\n',0o600)
                    ui.view('Report destination', str(path))
                elif selected == 'history': do(ui, {'kind': 'history'})
                elif selected == 'restore': do(ui, {'kind': 'rollback', 'id': ui.prompt('Change ID', 'ID αλλαγής')})
        except Exception as error: ui.error(error)


def main():
    parser = argparse.ArgumentParser(description=TITLE + ' — ' + TAGLINE)
    parser.add_argument('command', nargs='?', default='menu', choices=['menu', 'info', 'monitor', 'audit', 'confirm', 'rollback', 'uninstall', 'activate'])
    parser.add_argument('change_id', nargs='?')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--basic', action='store_true')
    parser.add_argument('--sort', choices=['ram', 'cpu'], default='ram')
    parser.add_argument('--language', choices=['en', 'el'])
    parser.add_argument('--hostname-runtime', help=argparse.SUPPRESS)
    parser.add_argument('--build-netscanner', help=argparse.SUPPRESS)
    parser.add_argument('--dns-reload', help=argparse.SUPPRESS)
    parser.add_argument('--python-tool', help=argparse.SUPPRESS)
    parser.add_argument('--restore-service-state', help=argparse.SUPPRESS)
    parser.add_argument('--alerts-runtime', choices=['stop'], help=argparse.SUPPRESS)
    parser.add_argument('--network-reload', help=argparse.SUPPRESS)
    parser.add_argument('--action', help=argparse.SUPPRESS)
    parser.add_argument('--origin', default=None, help=argparse.SUPPRESS)
    parser.add_argument('--automatic', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.version_info < (3, 9): raise RuntimeError('Python 3.9+ required')
    if args.hostname_runtime:
        if os.geteuid()!=0:raise RuntimeError('Root required')
        nameconfig.restore_runtime_hostname(args.hostname_runtime);return
    if args.build_netscanner:
        if os.geteuid()!=0:raise RuntimeError('Root required')
        sourcebuild.install(json.loads(args.build_netscanner));return
    if args.dns_reload:
        if os.geteuid()!=0:raise RuntimeError('Root required')
        nameconfig.reload_dns(json.loads(args.dns_reload));return
    if args.python_tool:
        if os.geteuid()!=0:raise RuntimeError('Root required')
        toolinstall.install_python(json.loads(args.python_tool));return
    if args.restore_service_state:
        if os.geteuid()!=0:raise RuntimeError('Root required')
        system.restore_service_state(json.loads(args.restore_service_state))
        return
    if args.alerts_runtime:
        if os.geteuid()!=0: raise RuntimeError('Root required')
        for command in (['systemctl','disable','--now','linux-telegram-alerts.timer'], ['systemctl','stop','linux-telegram-alerts.service']):
            system.command(command)
        return
    if args.network_reload:
        if os.geteuid() != 0: raise RuntimeError('Root required for network activation')
        data = json.loads(args.network_reload)
        networking.reload_backend(data['backend'], data['iface'], data.get('uuid',''))
        return
    if args.action:
        if os.geteuid() != 0: raise RuntimeError('Root required at the action boundary')
        if dispatch(json.loads(args.action), args.origin or '') is False:raise SystemExit(20)
        return
    if args.command in ('confirm', 'rollback', 'activate'):
        if not args.change_id: parser.error('A change ID is required')
        call_root({'kind': args.command, 'id': args.change_id, 'automatic': args.automatic})
    elif args.command == 'uninstall': call_root({'kind': 'uninstall'})
    elif args.command == 'info': print(json.dumps(system.snapshot(), ensure_ascii=False, indent=2) if args.json else dashboard())
    elif args.command == 'monitor': print(process_table(args.sort))
    elif args.command == 'audit': print(table(['Check', 'State', 'Details'], system.audit()))
    else:
        if not sys.stdin.isatty(): raise RuntimeError('Interactive terminal required. Use aegis info --json for scripts.')
        prefs = preferences()
        ui = UI(args.language or prefs['language'], prefs['theme'], args.basic)
        if not Path('/etc/aegis-linux-hardener/ui.json').exists() and not (Path.home() / '.config/aegis-linux-hardener/ui.json').exists():
            ui.language = 'el' if ui.prompt('Language: 1 English / 2 Ελληνικά', 'Language: 1 English / 2 Ελληνικά', '1') == '2' else 'en'
            save_preferences(ui)
        console.LANGUAGE = ui.language
        menu(ui)


if __name__ == '__main__':
    try: main()
    except console.Cancelled:print('\nCancelled / Ακυρώθηκε.');sys.exit(20)
    except KeyboardInterrupt: print('\nCancelled / Ακυρώθηκε.'); sys.exit(130)
    except ValueError as error:print('Aegis: '+str(error),file=sys.stderr);sys.exit(21)
    except Exception as error:
        print('Aegis: ' + str(error), file=sys.stderr)
        sys.exit(1)
