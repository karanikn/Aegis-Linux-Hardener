"""Lynis findings → explicit, reversible controls / Όχι τυφλό auto-fix για score."""
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys
from . import system, catalog, security
from .actions import Plan, ENTRY

ETC = Path('/etc')
CONTROLS = [
 ('PKGS-7392', 'Vulnerable packages', 'inspect', 'List update candidates and Debian debsecan findings; apply reviewed upgrades from Maintenance.'),
 ('DEB-0280', 'PAM temporary directories', 'pam-tmpdir', 'Install libpam-tmpdir; package may update PAM session configuration.'),
 ('DEB-0810', 'Critical APT bug notices', 'apt-listbugs', 'Install apt-listbugs before future package operations.'),
 ('DEB-0831', 'Services using old libraries', 'needrestart', 'Install needrestart; inspect in list-only mode, not automatic service restart.'),
 ('DEB-0880', 'Fail2Ban configuration preservation', 'existing', 'Keep Aegis jail.d/*.local. This historical Lynis control is marked invalid upstream; do not copy the full jail.conf.'),
 ('BOOT-5122', 'GRUB authentication', 'manual', 'Requires local console, recovery planning and a personally chosen boot policy; no automatic boot-loader changes.'),
 ('BOOT-5264', 'systemd service sandboxing', 'service', 'Inspect systemd-analyze security, then scope sandbox options to a selected application service.'),
 ('KRNL-5820', 'Core dumps', 'core-dumps', 'Set new-session limits and systemd-coredump storage policy; existing sessions are not forcibly changed.'),
 ('AUTH-9229', 'Password hashing method', 'inspect', 'Inspect current PAM/hash settings; keep modern distribution hashing rather than forcing obsolete rounds settings.'),
 ('AUTH-9230', 'Hash cost/rounds', 'inspect', 'Algorithm-aware manual review. Do not override yescrypt with blind SHA512 settings.'),
 ('AUTH-9262', 'Password quality', 'password-quality', 'Install libpam-pwquality separately, then configure quality for future password changes.'),
 ('AUTH-9282', 'Per-account password aging', 'account-aging', 'Apply to a selected normal account only, with prior aging values retained for undo.'),
 ('AUTH-9286', 'Password age defaults', 'login-defaults', 'Adjust defaults for new accounts; existing accounts use a separate action.'),
 ('AUTH-9328', 'Default umask', 'login-defaults', 'Set UMASK 027 in login.defs; service/PAM overrides still need inspection.'),
 ('FILE-6310', 'Separate /home /tmp /var', 'manual', 'Requires storage planning; no automatic repartitioning or filesystem migration.'),
 ('FILE-6410', 'Locate database', 'locate', 'Install plocate; optionally rebuild its database with a retained database backup.'),
 ('USB-1000', 'USB storage policy', 'modules', 'Optional persistent module block, without forcibly unloading currently used modules.'),
 ('STRG-1846', 'FireWire storage policy', 'modules', 'Optional persistent module block; desktop/external storage may need this functionality.'),
 ('PKGS-7370', 'Package file integrity', 'debsums', 'Install debsums; read-only check of installed files against package checksums.'),
 ('PKGS-7394', 'Package version visibility', 'apt-show-versions', 'Install apt-show-versions from configured repositories.'),
 ('NETW-3200', 'Unused network protocols', 'modules', 'Select dccp/sctp/rds/tipc individually; loaded modules remain until a later restart.'),
 ('FIRE-4513', 'Firewall rules review', 'existing', 'Inspect existing UFW/nftables rules. No automatic rule pruning.'),
 ('HTTP-6640', 'Apache mod_evasive', 'apache-evasive', 'Install/tune only on an existing Apache server. Vendor defaults require application testing.'),
 ('HTTP-6643', 'Apache WAF', 'apache-waf', 'Prepare ModSecurity/CRS in DetectionOnly mode, not immediate blocking.'),
 ('SSH-7408', 'SSH options', 'ssh', 'Individually select compression/logging/limits/agent/TCP forwarding and port; forwarding remains enabled unless explicitly changed.'),
 ('LOGG-2154', 'External logging', 'remote-logging', 'Add a validated TCP/TLS rsyslog destination; keep existing local outputs.'),
 ('LOGG-2190', 'Deleted files still open', 'inspect', 'Inspect lsof +L1. Do not blindly restart database/web services.'),
 ('BANN-7126', 'Local login notice', 'banners', 'Managed notice in /etc/issue, with original contents backed up.'),
 ('BANN-7130', 'Remote login notice', 'banners', 'Managed /etc/issue.net text; enabling SSH Banner is a separate SSH option.'),
 ('ACCT-9622', 'Process accounting', 'accounting', 'Install acct and explicitly enable the service.'),
 ('ACCT-9626', 'Historical resource statistics', 'sysstat', 'Install sysstat and explicitly enable collection.'),
 ('ACCT-9628', 'Kernel audit events', 'auditd', 'Install auditd; optionally add limited identity/SSH/sudo file watches. No immutable audit lock.'),
 ('FINT-4350', 'File integrity baseline', 'aide', 'Install AIDE; explicitly initialize only on a trusted host. Backup the old database first.'),
 ('TOOL-5002', 'Automation tooling', 'inspect', 'Inventory only; installing software purely to satisfy this hint is not a security guarantee.'),
 ('FILE-7524', 'Sensitive file permissions', 'permissions', 'Change selected root-owned cron/SSH/sudo paths; keep original mode/owner metadata for undo.'),
 ('HOME-9304', 'Home permissions', 'home-mode', 'Change one selected home to 0750, after reviewing web roots/shares.'),
 ('KRNL-6000', 'Additional sysctl options', 'sysctl-extra', 'Reversible per-key choices. Never set modules_disabled=1 or irreversible BPF/ptrace lock values.'),
 ('HRDN-7230', 'Malware detection', 'clamav', 'Optional ClamAV/rkhunter/chkrootkit installation; checks do not prove a host is clean.'),
 ('LYNIS', 'Lynis version', 'inspect', 'Review distribution/vendor versions without automatically replacing trusted repositories.'),
]
INSTALLS = {
 'pam-tmpdir': ['libpam-tmpdir'], 'apt-listbugs': ['apt-listbugs'], 'needrestart': ['needrestart'],
 'debsums': ['debsums'], 'apt-show-versions': ['apt-show-versions'], 'locate': ['plocate'],
 'pwquality': ['libpam-pwquality'], 'auditd': ['auditd'], 'sysstat': ['sysstat'],
 'accounting': ['acct'], 'aide': ['aide', 'aide-common'], 'clamav': ['clamav'],
 'rkhunter': ['rkhunter'], 'chkrootkit': ['chkrootkit'], 'lsof': ['lsof'],
 'debsecan': ['debsecan'], 'rsyslog-tls': ['rsyslog', 'rsyslog-gnutls'],
}
EXTRA_SYSCTL = {
 'dev.tty.ldisc_autoload': ('0', 'Disable automatic line-discipline loading; review PPP/serial use.'),
 'fs.protected_fifos': ('2', 'Restrict unsafe FIFO opens in writable sticky directories.'),
 'kernel.core_uses_pid': ('1', 'Include process ID in compatible core dump names.'),
 'kernel.sysrq': ('0', 'Disable SysRq shortcuts; changes emergency console behavior.'),
 'kernel.unprivileged_bpf_disabled': ('2', 'Reversible unprivileged BPF restriction; never use irreversible value 1.'),
 'kernel.yama.ptrace_scope': ('1', 'Restrict ptrace; may affect debugging tools.'),
 'net.core.bpf_jit_harden': ('2', 'BPF JIT hardening; can affect performance.'),
 'net.ipv4.conf.all.log_martians': ('1', 'Log suspicious IPv4 routing input; may increase log volume.'),
 'net.ipv4.conf.default.log_martians': ('1', 'Same default for new interfaces.'),
 'net.ipv4.conf.all.rp_filter': ('2', 'Loose reverse-path filtering; preferable to blind strict filtering on multihomed/VPN hosts.'),
 'net.ipv4.conf.all.send_redirects': ('0', 'Disable sending IPv4 ICMP redirects; review router roles.'),
 'net.ipv4.conf.default.send_redirects': ('0', 'Disable redirect sending for new interfaces.'),
 'net.ipv4.conf.default.accept_source_route': ('0', 'Disable accepting source-routed IPv4 packets by default.'),
}


def findings(path='/var/log/lynis-report.dat'):
    result = []
    for line in system.read(path).splitlines():
        if not line.startswith(('warning[]=', 'suggestion[]=')): continue
        kind, value = line.split('=', 1)
        fields = value.split('|')
        test = fields[0].strip()
        if not re.fullmatch(r'[A-Z0-9-]+', test): continue
        match = next((x for x in CONTROLS if x[0] == test), None)
        result.append({'kind': kind[:-2], 'id': test, 'description': fields[1] if len(fields)>1 else '',
                       'coverage': match[2] if match else 'manual', 'guidance': match[3] if match else 'Manual review; no automatic remediation registered.'})
    return result


def repository_audit():
    info = system.os_release()
    rows = []
    paths = [ETC / 'apt/sources.list'] + list((ETC / 'apt/sources.list.d').glob('*.list')) + list((ETC / 'apt/sources.list.d').glob('*.sources'))
    for path in paths:
        text = system.read(path)
        if info.get('ID') == 'debian' and re.search(r'ppa\.launchpad|ubuntu\.com|\b(jammy|noble|resolute)\b', text, re.I):
            rows.append(str(path) + ': Ubuntu/PPA source detected on Debian; review compatibility. No automatic deletion.')
    return rows or ['No obvious Ubuntu-on-Debian repository mismatch detected by this limited check.']


def replace_values(text, values, separator=' '):
    for key, value in values.items():
        pattern = r'^\s*' + re.escape(key) + r'\s*(?:=\s*|\s+).*$'
        line = key + separator + str(value)
        if re.search(pattern, text, re.M): text = re.sub(pattern, lambda _: line, text, flags=re.M)
        else: text += ('\n' if text and not text.endswith('\n') else '') + line + '\n'
    return text


def install_profile(key):
    if key not in INSTALLS: raise ValueError('Unknown hardening package profile')
    plan = catalog.package_plan(INSTALLS[key], 'Install security tools: ' + key)
    if key in ('pam-tmpdir', 'pwquality'):
        plan.backup_paths += ['/etc/pam.d', '/etc/security/pwquality.conf', '/etc/security/pwquality.conf.d']
        plan.details += ['PAM package hooks may affect future login/password sessions. Keep console access available.']
    return plan


def plan(kind, request):
    if kind == 'core-dumps':
        return Plan('Disable stored core dumps for new sessions',
            writes={'/etc/security/limits.d/60-aegis-core.conf': '* soft core 0\n* hard core 0\nroot soft core 0\nroot hard core 0\n',
                    '/etc/systemd/coredump.conf.d/60-aegis.conf': '[Coredump]\nStorage=none\nProcessSizeMax=0\n'},
            details=['New sessions/processes use the new limits. Existing processes are not forcibly restarted.'])
    if kind == 'login-defaults':
        maximum = security.number(request['max_days'], 1, 99999)
        minimum = security.number(request['min_days'], 0, maximum)
        path = str(ETC / 'login.defs')
        return Plan('New-account password/umask defaults',
            writes={path: replace_values(Path(path).read_text(), {'PASS_MAX_DAYS': maximum, 'PASS_MIN_DAYS': minimum, 'PASS_WARN_AGE': '14', 'UMASK': '027'})},
            details=['Applies defaults for future accounts; does not expire existing users or change password hashing.',
                     'PAM/service settings can override login.defs.'])
    if kind == 'password-quality':
        if not system.installed('libpam-pwquality'): raise ValueError('Install the pwquality profile first')
        pam = system.read(ETC / 'pam.d/common-password')
        module_lines = [line for line in pam.splitlines() if 'pam_pwquality.so' in line and not line.lstrip().startswith('#')]
        if not module_lines: raise ValueError('pam_pwquality is not active; install/enable its distro PAM profile separately')
        if any(re.search(r'\b(minlen|minclass|difok|dcredit|ucredit|lcredit|ocredit)=', line) for line in module_lines):
            raise ValueError('PAM module arguments override quality settings; review them manually')
        path = str(ETC / 'security/pwquality.conf')
        values = {'minlen': security.number(request.get('minlen', 14), 8, 128), 'minclass': 3, 'difok': 4,
                  'dcredit': 0, 'ucredit': 0, 'lcredit': 0, 'ocredit': 0}
        return Plan('Password quality for future changes', writes={path: replace_values(system.read(path), values, ' = ')},
                    details=['Does not reset existing passwords or force account expiry. Root/PAM behavior still follows the current PAM policy.'])
    if kind == 'account-aging':
        user = request['user']; account = pwd.getpwnam(user)
        if account.pw_uid < 1000 or account.pw_shell.endswith(('nologin', '/false')): raise ValueError('Select a normal login account')
        code, shadow, _ = system.command(['getent', 'shadow', user])
        fields = shadow.split(':')
        if code or len(fields) < 8: raise ValueError('Cannot retain current aging values')
        minimum = security.number(request['min_days'], 0, 365)
        maximum = security.number(request['max_days'], max(1, minimum), 99999)
        old = ['chage', '-m', fields[3] or '0', '-M', fields[4] or '-1', '-W', fields[5] or '7', user]
        return Plan('Account aging: ' + user, commands=[['chage', '-m', str(minimum), '-M', str(maximum), '-W', '14', user]],
                    rollback_commands=[old], details=['Only this account is affected. Old aging values are retained; password hashes are never displayed.'])
    if kind == 'banners':
        notice = 'Authorized access only. Activity may be monitored.\n'
        return Plan('Login notices', writes={str(ETC/'issue'): notice, str(ETC/'issue.net'): notice},
                    details=['SSH Banner activation is a separate protected SSH option.'])
    if kind == 'permissions':
        modes = {'crontab': 0o600, 'ssh/sshd_config': 0o600, 'sudoers.d': 0o750,
                 'cron.d': 0o700, 'cron.daily': 0o700, 'cron.hourly': 0o700, 'cron.weekly': 0o700, 'cron.monthly': 0o700}
        selected = request['paths']
        if not selected or not set(selected) <= modes.keys(): raise ValueError('Select known permission targets')
        changed = {}
        for relative in selected:
            path = ETC / relative
            if not path.exists() or path.is_symlink() or path.stat().st_uid != 0:
                raise ValueError('Target must exist, be root-owned and not be a symlink: ' + str(path))
            changed[str(path)] = modes[relative]
        return Plan('Sensitive path permissions', metadata=changed,
                    validate=[['visudo', '-c']] if 'sudoers.d' in selected else [],
                    details=['Only metadata is changed/backed up; directories are not recursively chmodded or copied.'])
    if kind == 'home-mode':
        user = request['user']; account = pwd.getpwnam(user); path = Path(account.pw_dir)
        if account.pw_uid < 1000 or path.parent != Path('/home') or path.is_symlink() or path.stat().st_uid != account.pw_uid:
            raise ValueError('Select a normal owned /home/USER directory')
        return Plan('Home permissions: ' + user, metadata={str(path): 0o750},
                    details=['Review websites/shared files under this home before restricting access. Contents are not recursively changed.'])
    if kind == 'modules':
        allowed = {'usb-storage', 'firewire-core', 'dccp', 'sctp', 'rds', 'tipc'}
        selected = request['modules']
        if not selected or not set(selected) <= allowed: raise ValueError('Invalid module selection')
        text = '# Managed by Aegis; no forced unload of running modules\n'
        text += ''.join('install ' + name + ' /bin/false\nblacklist ' + name + '\n' for name in selected)
        return Plan('Optional module autoload restrictions', writes={'/etc/modprobe.d/60-aegis-optional.conf': text},
                    details=['Storage/network/debugging features may need these modules. Already-loaded modules remain loaded.',
                             'No irreversible kernel.modules_disabled lock is applied.'])
    if kind == 'sysctl-extra':
        keys = request['keys']
        if not keys or not set(keys) <= EXTRA_SYSCTL.keys(): raise ValueError('Invalid sysctl selection')
        path = '/etc/sysctl.d/61-aegis-optional.conf'
        text = system.read(path) or '# Aegis optional reversible controls\n'
        undo = []
        for key in keys:
            code, value, _ = system.command(['sysctl', '-n', key])
            if code: raise ValueError('Kernel does not expose ' + key)
            if key == 'kernel.unprivileged_bpf_disabled' and value == '1':
                raise ValueError('BPF is already irreversibly locked for this boot; do not attempt to change it')
            undo.append(['sysctl', '-w', key + '=' + value])
            text = replace_values(text, {key: EXTRA_SYSCTL[key][0]}, ' = ')
        return Plan('Optional reversible sysctl controls', writes={path: text}, commands=[['sysctl','-w',key+'='+EXTRA_SYSCTL[key][0]] for key in keys],
                    rollback_commands=undo, details=[EXTRA_SYSCTL[key][1] for key in keys])
    if kind == 'service':
        unit = request['unit']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9@_.:-]*\.service', unit): raise ValueError('Select a service unit')
        if unit.startswith(('ssh.', 'sshd.', 'NetworkManager.', 'systemd-', 'dbus.', 'user@', 'getty@')):
            raise ValueError('Core login/network/system services require application-specific hardening')
        if system.command(['systemctl', 'show', unit, '-p', 'LoadState', '--value'])[1] != 'loaded': raise ValueError('Service not loaded')
        options = request.get('options', ['NoNewPrivileges'])
        if not options or not set(options) <= {'NoNewPrivileges', 'PrivateTmp'}: raise ValueError('Invalid sandbox choice')
        active = system.service(unit) == 'active'
        return Plan('Service sandbox: ' + unit,
            writes={'/etc/systemd/system/' + unit + '.d/50-aegis-sandbox.conf': '[Service]\n' + ''.join(key + '=true\n' for key in options)},
            validate=[['systemd-analyze', 'verify', unit]],
            commands=[['systemctl', 'daemon-reload']] + ([['systemctl', 'restart', unit]] if active else []),
            rollback_commands=[['systemctl', 'daemon-reload']] + ([['systemctl', 'restart', unit]] if active else []),
            details=['Application behavior must be tested; PrivateTmp changes shared temporary-file visibility.'])
    if kind == 'remote-logging':
        security.require('rsyslogd')
        host = request['host']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}', host): raise ValueError('Invalid logging host')
        port = security.number(request.get('port', 6514), 1, 65535)
        tls = request.get('tls', True)
        text = '# Managed by Aegis; existing local logging stays configured\n'
        if tls: text += 'global(DefaultNetstreamDriverCAFile="/etc/ssl/certs/ca-certificates.crt")\n'
        text += '*.* action(type="omfwd" target="' + host + '" port="' + str(port) + '" protocol="tcp" '
        if tls: text += 'StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="' + host + '" '
        text += 'action.resumeRetryCount="-1" queue.type="LinkedList" queue.filename="aegis-forward" queue.saveOnShutdown="on")\n'
        return Plan('Remote logging', writes={'/etc/rsyslog.d/60-aegis-forward.conf': text},
                    validate=[['rsyslogd', '-N1']], commands=[['systemctl', 'restart', 'rsyslog']],
                    rollback_commands=[['systemctl', 'restart', 'rsyslog']],
                    details=['TLS requires rsyslog-gnutls and a trusted certificate matching the selected server.',
                             'Selected system logs will be sent to ' + host + ':' + str(port)])
    if kind in ('accounting', 'sysstat'):
        security.require('accton' if kind == 'accounting' else 'sar')
        unit = 'acct' if kind == 'accounting' else 'sysstat'
        active = system.service(unit) == 'active'
        writes = {}
        if kind == 'sysstat': writes['/etc/default/sysstat'] = replace_values(system.read('/etc/default/sysstat'), {'ENABLED': '"true"'}, '=')
        return Plan('Enable ' + unit, writes=writes,
            commands=[['systemctl', 'enable', '--now', unit]], rollback_commands=[[sys.executable,str(ENTRY),'--restore-service-state',json.dumps(system.service_state(unit))]],
            details=['Collection creates historical usage/accounting data. Previously generated history is retained on undo.'])
    if kind == 'audit-watches':
        security.require('auditctl')
        status = system.command(['auditctl', '-s'])[1]
        if re.search(r'^enabled\s+2', status, re.M): raise ValueError('Audit rules are immutable until reboot; manual review required')
        path = '/etc/audit/rules.d/60-aegis-identity.rules'
        if Path(path).exists(): raise ValueError('Aegis watch file already exists; inspect current rules instead of duplicating them')
        files = [str(ETC / key) for key in ('passwd','group','shadow','sudoers','ssh/sshd_config') if (ETC/key).exists()]
        return Plan('Audit identity/SSH file watches', writes={path: ''.join('-w ' + name + ' -p wa -k aegis_identity\n' for name in files)},
                    backup_paths=['/etc/audit/audit.rules'], commands=[['augenrules'], ['auditctl', '-R', path]],
                    rollback_commands=[['auditctl', '-W', name, '-p', 'wa', '-k', 'aegis_identity'] for name in files],
                    details=['Adds only these file watches. No delete-all, immutable lock or broad syscall policy.'])
    if kind == 'aide-init':
        security.require('aideinit')
        return Plan('Initialize AIDE baseline', backup_paths=['/var/lib/aide'], commands=[['aideinit', '--yes']],
                    details=['Initialize only after establishing that this machine is trusted. An infected baseline does not clean the host.',
                             'An existing AIDE database is backed up before initialization; scanning may take time.'])
    if kind == 'locate-update':
        security.require('updatedb')
        return Plan('Build locate database', backup_paths=['/var/lib/plocate', '/var/lib/mlocate'], commands=[['updatedb']],
                    details=['Index file names using the distribution configuration. Existing index data is backed up.'])
    if kind in ('apache-waf', 'apache-evasive'):
        security.require('apache2ctl')
        if not system.installed('apache2'): raise ValueError('An existing Apache server is required; this action does not install a web server')
        packages = ['libapache2-mod-security2', 'modsecurity-crs'] if kind == 'apache-waf' else ['libapache2-mod-evasive']
        result = catalog.package_plan(packages, 'Prepare ' + kind)
        result.suppress_services = True
        result.backup_paths = ['/etc/apache2', '/etc/modsecurity']
        if kind == 'apache-waf':
            result.late_writes['/etc/modsecurity/zz-aegis.conf'] = 'SecRuleEngine DetectionOnly\n'
            result.commands = [['a2enmod', 'security2']]
            result.details += ['DetectionOnly logs rule matches. Blocking is not enabled; review CRS/app behavior first.']
        else: result.details += ['Vendor mod_evasive defaults may block clients; review its configuration and whitelist trusted proxies.']
        result.commands += [['apache2ctl', 'configtest']] + ([['systemctl', 'restart', 'apache2']] if system.service('apache2')=='active' else [])
        result.rollback_commands = [['systemctl', 'daemon-reload']] + ([['systemctl', 'reload', 'apache2']] if system.service('apache2')=='active' else [])
        return result
    raise ValueError('Unknown hardening profile')
