"""Explicit security plans / Επιλεκτικό hardening με έλεγχο και επαναφορά."""
import ipaddress
import os
from pathlib import Path
import pwd
import re
import shutil
import json
import sys
from .actions import Plan, ENTRY
from . import system


def require(command):
    if not shutil.which(command): raise ValueError(command + ' is unavailable. This action requires its package.')


def number(value, minimum=1, maximum=86400):
    value = int(value)
    if not minimum <= value <= maximum: raise ValueError('Number outside allowed range')
    return value


def network(value):
    return str(ipaddress.ip_network(value, strict=False))


def jail_name(value):
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', value): raise ValueError('Invalid jail name')
    return value


def ssh_unit():
    for name in ('ssh.service', 'sshd.service'):
        if system.command(['systemctl', 'show', name, '-p', 'LoadState', '--value'])[1] == 'loaded':
            return name
    raise ValueError('No OpenSSH system service detected')


def ssh_plan(mode, user, source_ip, value=None):
    extra = {
        'compression': {'Compression': 'no'}, 'verbose': {'LogLevel': 'VERBOSE'},
        'sessions': {'MaxSessions': '2'}, 'keepalive': {'ClientAliveInterval': '300', 'ClientAliveCountMax': '2', 'TCPKeepAlive': 'no'},
        'agent-forwarding': {'AllowAgentForwarding': 'no'}, 'tcp-forwarding': {'AllowTcpForwarding': 'no'},
        'banner': {'Banner': '/etc/issue.net'}, 'port': {'Port': str(number(value, 1, 65535))} if mode == 'port' else {},
    }
    if mode not in ('root-password', 'keys-only', 'limits') and mode not in extra: raise ValueError('Unknown SSH option')
    if mode == 'port' and system.service('ssh.socket') == 'active':
        raise ValueError('SSH socket activation is active; manage its socket/listener explicitly before changing the port')
    account = pwd.getpwnam(user)
    address = str(ipaddress.ip_address(source_ip))
    require('sshd')
    main = Path('/etc/ssh/sshd_config')
    content = main.read_text()
    if system.command(['sshd', '-t'])[0]: raise ValueError('Existing SSH configuration fails validation')
    unit = ssh_unit()
    settings = {'PermitRootLogin': 'prohibit-password'} if mode == 'root-password' else (
        {'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no', 'PubkeyAuthentication': 'yes'}
        if mode == 'keys-only' else ({'MaxAuthTries': '3', 'LoginGraceTime': '30'} if mode == 'limits' else extra[mode]))
    if mode == 'keys-only':
        # A valid local authorized key is necessary, but real login must ALSO be tested.
        key = Path(account.pw_dir) / '.ssh/authorized_keys'
        if not key.is_file() or system.command(['ssh-keygen', '-l', '-f', str(key)])[0]:
            raise ValueError('No valid standard authorized_keys file for the selected account')
    path = '/etc/ssh/sshd_config.d/00-aegis-hardening.conf'
    existing = system.read(path)
    merged = {}
    for line in existing.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in ('PermitRootLogin', 'PasswordAuthentication',
                'KbdInteractiveAuthentication', 'PubkeyAuthentication', 'MaxAuthTries', 'LoginGraceTime',
                'Compression', 'LogLevel', 'MaxSessions', 'ClientAliveInterval', 'ClientAliveCountMax', 'TCPKeepAlive',
                'AllowAgentForwarding', 'AllowTcpForwarding', 'Banner', 'Port'):
            merged[parts[0]] = parts[1]
    merged.update(settings)
    writes = {path: '# Managed by Aegis Linux Hardener\n' + ''.join(k + ' ' + v + '\n' for k, v in merged.items())}
    include = 'Include /etc/ssh/sshd_config.d/*.conf'
    if not any(line.strip() == include for line in content.splitlines()):
        writes[str(main)] = include + '\n' + content
    def verify():
        code, text, _ = system.command(['sshd', '-T', '-C', 'user=' + user + ',addr=' + address + ',host=localhost'])
        if code: raise RuntimeError('Cannot inspect effective SSH settings')
        effective = dict(line.split(None, 1) for line in text.splitlines() if ' ' in line)
        if mode == 'keys-only' and effective.get('authenticationmethods', 'any') not in ('any', 'publickey'):
            raise RuntimeError('Existing AuthenticationMethods/MFA requires manual review before keys-only mode')
        for key, value in settings.items():
            actual = effective.get(key.lower())
            allowed = (value.lower(), 'without-password') if value == 'prohibit-password' else (value.lower(),)
            actual = actual.lower() if actual is not None else actual
            if actual not in allowed:
                raise RuntimeError('Existing SSH config/Match rules override ' + key + '; files will be restored')
    return Plan('SSH hardening: ' + mode,
        details=['Target account: ' + user, 'Management source: ' + address,
                 'Existing settings and Match blocks are checked, not blindly overwritten.',
                 'TCP forwarding is NOT disabled unless selected. Disabling it breaks SSH tunnels used for local-only Webmin/Cockpit.',
                 'Port changes require allowing the new management port in every relevant firewall BEFORE applying.',
                 'For keys-only: verify key login from a SECOND connection BEFORE applying. Keyboard-interactive login is disabled.'],
        writes=writes, validate=[['sshd', '-t']], verify=verify,
        commands=[['systemctl', 'reload', unit]], rollback_commands=[['systemctl', 'reload', unit]], critical=True)


def available_jails():
    rows = []
    candidates = [('sshd', 'SSH authentication'), ('apache-auth', 'Apache HTTP authentication'),
                  ('nginx-http-auth', 'Nginx HTTP authentication'), ('postfix', 'Postfix SMTP'),
                  ('dovecot', 'Dovecot IMAP/POP'), ('vsftpd', 'vsftpd FTP'), ('recidive', 'Repeat offenders')]
    for key, description in candidates:
        if Path('/etc/fail2ban/filter.d/' + key + '.conf').exists(): rows.append((key, description))
    return rows


def fail2ban_plan(jails, ignore, retries, window, duration, ssh_port):
    require('fail2ban-client')
    valid = {x[0] for x in available_jails()}
    if not jails or not set(jails) <= valid: raise ValueError('Select at least one available jail')
    networks = [network(x) for x in ignore.split()]
    port = number(ssh_port, 1, 65535)
    text = '# Managed by Aegis. Other files/actions are preserved.\n[DEFAULT]\n'
    text += 'ignoreip = 127.0.0.1/8 ::1 ' + ' '.join(networks) + '\n'
    text += 'maxretry = {}\nfindtime = {}\nbantime = {}\n'.format(number(retries, 1, 100), number(window), number(duration, 1, 2592000))
    for jail in jails:
        text += '\n[' + jail_name(jail) + ']\nenabled = true\n'
        if jail == 'sshd': text += 'backend = systemd\nport = ' + str(port) + '\n'
    active = system.service('fail2ban') == 'active'
    return Plan('Configure Fail2Ban jails', details=[
        'Selected: ' + ', '.join(jails), 'Existing ban actions are inherited from the current configuration.',
        'Unselected jails configured elsewhere are NOT disabled.',
        'Application jails need real matching logs. fail2ban-client -t must pass before restart.'],
        writes={'/etc/fail2ban/jail.d/90-aegis.local': text},
        validate=[['fail2ban-client', '-t']], commands=[['systemctl', 'enable', '--now', 'fail2ban'], ['systemctl', 'restart', 'fail2ban']],
        rollback_commands=[[sys.executable,str(ENTRY),'--restore-service-state',json.dumps(system.service_state('fail2ban'))]])


def ufw_plan(mode, source, port, protocol='tcp'):
    require('ufw')
    if mode not in ('allow', 'enable'): raise ValueError('Unsupported firewall operation')
    source = network(source)
    port = number(port, 1, 65535)
    if protocol not in ('tcp', 'udp'): raise ValueError('Invalid protocol')
    # Never layer UFW over an active firewalld service.
    if system.service('shorewall') == 'active': raise ValueError('Active Shorewall detected; manage its reviewed policy separately')
    if system.service('firewalld') == 'active': raise ValueError('Active firewalld detected; inspect and manage it separately')
    active = 'Status: active' in system.command(['ufw', 'status'])[1]
    if mode == 'enable' and not active:
        # Refuse to replace an independent nftables ruleset. Existing UFW only is supported.
        nft = system.command(['nft', 'list', 'ruleset'])[1]
        if nft and 'ufw-' not in nft and not shutil.which('docker'):
            raise ValueError('Existing nftables rules detected. Review them before enabling UFW.')
    args = ['ufw', 'allow', 'proto', protocol, 'from', source, 'to', 'any', 'port', str(port)]
    commands = [args]
    if mode == 'enable': commands.append(['ufw', '--force', 'enable'])
    return Plan('UFW: ' + mode,
        details=['Source: ' + source, 'Port/protocol: {}/{}'.format(port, protocol),
                 'When enabling, this must be your REAL SSH management port/source.',
                 'Docker published ports may bypass host UFW rules; container filtering is not configured.',
                 'Existing UFW policies/rules are preserved. No reset and no automatic public ports.'],
        backup_paths=['/etc/ufw'], commands=commands,
        rollback_commands=[['ufw', 'reload']] if active else [['ufw', '--force', 'disable']], critical=True)


def sysctl_plan():
    values = {'kernel.kptr_restrict': '2', 'kernel.dmesg_restrict': '1',
              'fs.protected_hardlinks': '1', 'fs.protected_symlinks': '1'}
    undo = []
    for key in values:
        code, value, _ = system.command(['sysctl', '-n', key])
        if code: raise ValueError('Unsupported sysctl: ' + key)
        undo.append(['sysctl', '-w', key + '=' + value])
    path = '/etc/sysctl.d/60-aegis-hardening.conf'
    return Plan('Kernel/filesystem baseline', details=[
        'Restricts kernel address/log exposure and unsafe hard/symbolic link behavior.',
        'No changes to routing, IPv4/IPv6 forwarding, Docker networking, or swap.'],
        writes={path: '# Managed by Aegis\n' + ''.join(k + ' = ' + v + '\n' for k, v in values.items())},
        commands=[['sysctl', '-p', path]], rollback_commands=undo)


def apparmor_plan(profile, mode):
    if mode not in ('complain', 'enforce'): raise ValueError('Invalid AppArmor mode')
    require('aa-' + mode)
    path = Path(profile)
    if path.parent != Path('/etc/apparmor.d') or path.is_symlink() or not path.is_file():
        raise ValueError('Select a regular profile file directly under /etc/apparmor.d')
    if system.command(['apparmor_parser', '-Q', '-p', str(path)])[0]:
        raise ValueError('Selected file is not a valid AppArmor profile')
    return Plan('AppArmor profile: ' + mode,
        details=[str(path), 'Only the selected profile is changed. Test application behavior after enforcement.'],
        backup_paths=[str(path), '/etc/apparmor.d/force-complain', '/etc/apparmor.d/disable'],
        commands=[['aa-' + mode, str(path)]], rollback_commands=[['apparmor_parser', '-r', str(path)]])


def authentication_plan(jail, ip, ban=False):
    require('fail2ban-client')
    return Plan('Fail2Ban: ' + ('ban' if ban else 'unban'),
                details=['Jail: ' + jail_name(jail), 'IP: ' + str(ipaddress.ip_address(ip)),
                         'This live action is recorded but has no managed-file rollback.'],
                commands=[['fail2ban-client', 'set', jail, 'banip' if ban else 'unbanip', str(ipaddress.ip_address(ip))]])
