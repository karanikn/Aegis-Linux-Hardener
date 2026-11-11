"""Read-only collectors / Συλλογή πληροφοριών χωρίς αλλαγές συστήματος."""
import datetime
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shlex
import shutil
import socket
import subprocess
import time


def command(args, timeout=12):
    """No shell interpolation / Καμία εκτέλεση μέσω shell."""
    try:
        p = subprocess.run(args, text=True, capture_output=True, errors='replace',
                           timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, '', type(error).__name__


def read(path, default=''):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return default


def os_release(path='/etc/os-release'):
    result = {}
    for line in read(path).splitlines():
        if '=' in line and not line.startswith('#'):
            key, value = line.split('=', 1)
            try:
                parts = shlex.split(value)
                result[key] = ' '.join(parts)
            except ValueError:
                pass
    return result


def debian_based(info=None):
    info = info or os_release()
    return bool({'debian', 'ubuntu'} & set((info.get('ID', '') + ' ' + info.get('ID_LIKE', '')).split()))


def base_distribution(info=None):
    """Official repos need a known base suite, never a guessed derivative suite."""
    info = info or os_release()
    if info.get('ID') == 'debian':
        suite = info.get('VERSION_CODENAME', '')
        if suite in ('bookworm', 'trixie'):
            return 'debian', suite
    if info.get('ID') == 'ubuntu' or info.get('UBUNTU_CODENAME'):
        suite = info.get('UBUNTU_CODENAME') or info.get('VERSION_CODENAME', '')
        if suite in ('jammy', 'noble', 'resolute', 'stonking'):
            return 'ubuntu', suite
    raise ValueError('No supported official Docker base suite detected; existing Docker remains untouched.')


def memory():
    m = {x[1]: int(x[2]) for x in re.finditer(r'^(\w+):\s+(\d+)', read('/proc/meminfo'), re.M)}
    total = m.get('MemTotal', 1)
    return {'total_gib': total / 1048576, 'used_pct': 100 * (1 - m.get('MemAvailable', m.get('MemFree', 0)) / total),
            'swap_gib': m.get('SwapTotal', 0) / 1048576,
            'swap_pct': 100 * (1 - m.get('SwapFree', 0) / m['SwapTotal']) if m.get('SwapTotal') else 0}


def cpu_sample():
    values = [int(x) for x in read('/proc/stat').splitlines()[0].split()[1:]]
    # guest fields are already included in user/nice / αποφυγή διπλού υπολογισμού.
    return sum(values[:8]), values[3] + (values[4] if len(values) > 4 else 0)


def cpu_usage(delay=0.25):
    first = cpu_sample()
    time.sleep(delay)
    last = cpu_sample()
    return 100 * (1 - (last[1] - first[1]) / max(1, last[0] - first[0]))


def processes(sort='ram', limit=20, delay=0.4):
    def sample():
        items = {}
        for path in Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                raw = (path / 'stat').read_text()
                end = raw.rfind(')')
                fields = raw[end+2:].split()
                # stat field 14/15 and 24; comm may contain spaces and parentheses.
                items[int(path.name)] = {'pid': int(path.name), 'name': raw[raw.find('(')+1:end],
                    'ticks': int(fields[11]) + int(fields[12]), 'start': fields[19],
                    'rss_mib': int(fields[21]) * os.sysconf('SC_PAGE_SIZE') / 1048576,
                    'uid': path.stat().st_uid}
            except (OSError, ValueError, IndexError):
                continue
        return items
    first = sample()
    begin = time.monotonic()
    time.sleep(delay)
    last = sample()
    elapsed = max(0.01, time.monotonic() - begin)
    hz = os.sysconf('SC_CLK_TCK')
    for pid, item in last.items():
        old = first.get(pid)
        item['cpu_pct'] = max(0, 100 * (item['ticks'] - old['ticks']) / hz / elapsed) if old and old['start'] == item['start'] else 0
        try:
            item['user'] = pwd.getpwuid(item['uid']).pw_name
        except KeyError:
            item['user'] = str(item['uid'])
    return sorted(last.values(), key=lambda x: x['cpu_pct'] if sort == 'cpu' else x['rss_mib'], reverse=True)[:limit]


def filesystem_rows():
    found = []
    seen = set()
    for line in read('/proc/mounts').splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[2] in ('proc', 'sysfs', 'devpts', 'cgroup2', 'cgroup', 'securityfs', 'debugfs', 'tracefs', 'squashfs'):
            continue
        mount = fields[1].replace('\\040', ' ')
        if mount in seen or mount.startswith(('/proc', '/sys', '/snap/')):
            continue
        seen.add(mount)
        try:
            v = os.statvfs(mount)
            used = v.f_blocks - v.f_bfree
            found.append({'path': mount, 'type': fields[2], 'gib': v.f_blocks * v.f_frsize / 1073741824,
                'used_pct': 100 * used / max(1, used + v.f_bavail),
                'inode_pct': 100 * (1 - v.f_ffree / v.f_files) if v.f_files else None})
        except OSError:
            pass
    return found


def desktop_present():
    return bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY') or
                list(Path('/usr/share/xsessions').glob('*.desktop')) or
                list(Path('/usr/share/wayland-sessions').glob('*.desktop')))


def installed(package):
    code, text, _ = command(['dpkg-query', '-W', '-f=${Status} ${Version}', package])
    return text.split()[-1] if code == 0 and text.startswith('install ok installed ') else None


def service(unit):
    return command(['systemctl', 'is-active', unit])[1] or 'unavailable'


def snapshot():
    info = os_release()
    mem = memory()
    cpu = next((line.split(':', 1)[1].strip() for line in read('/proc/cpuinfo').splitlines()
                if line.startswith(('model name', 'Hardware'))), platform.machine())
    net_code, network, _ = command(['ip', '-br', 'address'])
    _, route, _ = command(['ip', 'route', 'show', 'default'])
    _, virt, _ = command(['systemd-detect-virt'])
    _, ufw, _ = command(['ufw', 'status'])
    _, apparmor, _ = command(['aa-status', '--enabled'])
    return {'hostname': socket.gethostname(), 'os': info.get('PRETTY_NAME', 'Unknown Linux'),
        'kernel': platform.release(), 'architecture': platform.machine(), 'cpu': cpu,
        'cpu_threads': os.cpu_count(), 'cpu_pct': round(cpu_usage(), 1),
        'load': os.getloadavg(), 'memory': mem,
        'uptime_hours': float(read('/proc/uptime', '0').split()[0]) / 3600,
        'virtualization': virt or 'none/unknown', 'desktop_detected': desktop_present(),
        'addresses': network if net_code == 0 else 'ip command unavailable', 'default_route': route,
        'dns': '\n'.join(line for line in read('/etc/resolv.conf').splitlines() if line.startswith(('nameserver', 'search'))),
        'filesystems': filesystem_rows(), 'ssh': service('ssh'), 'fail2ban': service('fail2ban'),
        'firewall': ufw or 'not installed / root required', 'apparmor': service('apparmor'),
        'alerts': service('linux-telegram-alerts.timer'), 'reboot_required': Path('/var/run/reboot-required').exists(),
        'timestamp': datetime.datetime.now().astimezone().isoformat(timespec='seconds')}


def audit():
    """Inventory findings, not a compliance certification / όχι πιστοποίηση ασφάλειας."""
    rows = []
    rows.append(('OS family', 'OK' if debian_based() else 'UNSUPPORTED', os_release().get('PRETTY_NAME', 'unknown')))
    rows.append(('SSH service', service('ssh'), 'Review effective settings before changing authentication'))
    for package in ('fail2ban', 'ufw', 'apparmor', 'unattended-upgrades', 'lynis'):
        version = installed(package)
        rows.append((package, 'INSTALLED' if version else 'MISSING', version or 'Optional; select installation explicitly'))
    code, settings, _ = command(['/usr/sbin/sshd', '-T'])
    if code == 0:
        for line in settings.splitlines():
            if line.startswith(('permitrootlogin ', 'passwordauthentication ', 'pubkeyauthentication ', 'maxauthtries ')):
                key, value = line.split(None, 1)
                rows.append((key, 'INFO', value))
    if shutil.which('docker'):
        rows.append(('Docker firewall', 'REVIEW', 'Published container ports may bypass UFW host rules'))
    rows.append(('Open ports', 'INFO', command(['ss', '-lntup'])[1] or 'ss unavailable'))
    return rows


def ssh_connection():
    """Recover SSH identity through sudo ancestors without changing sudo/env policy."""
    import ipaddress
    def valid(value):
        parts = value.split()
        if len(parts) != 4: return ''
        try:
            ipaddress.ip_address(parts[0]); ipaddress.ip_address(parts[2])
            if not (1 <= int(parts[1]) <= 65535 and 1 <= int(parts[3]) <= 65535): return ''
        except ValueError: return ''
        return ' '.join(parts)
    value = valid(os.environ.get('SSH_CONNECTION', ''))
    if value: return value
    pid = os.getppid()
    for _ in range(12):
        if pid <= 1: break
        try:
            environment = Path('/proc/' + str(pid) + '/environ').read_bytes().split(b'\0')
            for item in environment:
                if item.startswith(b'SSH_CONNECTION='):
                    value = valid(item.split(b'=',1)[1].decode(errors='replace'))
                    if value: return value
            raw = Path('/proc/' + str(pid) + '/stat').read_text()
            pid = int(raw[raw.rfind(')')+2:].split()[1])
        except (OSError, ValueError, IndexError): break
    return ''


def service_state(unit):
    return {'unit':unit,'active':service(unit)=='active',
            'enabled':command(['systemctl','is-enabled',unit])[1]=='enabled'}


def restore_service_state(value):
    import re
    unit=value['unit']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9@_.:-]*(?:\.service|\.socket|\.timer)?',unit):
        raise ValueError('Invalid service unit')
    if command(['systemctl','show',unit,'-p','LoadState','--value'])[1]=='not-found':
        if value['active'] or value['enabled']:raise RuntimeError('Prior service is missing: '+unit)
        return
    for args in (['systemctl','enable' if value['enabled'] else 'disable',unit],
                 ['systemctl','restart' if value['active'] else 'stop',unit]):
        if command(args)[0]:raise RuntimeError('Cannot restore service state: '+unit)
