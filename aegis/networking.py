"""IPv4 wizard plans for real managers / Ρύθμιση IPv4 με διατήρηση IPv6 και backup."""
import configparser
import glob
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from . import system
from .actions import Plan, ENTRY

ETC = Path('/etc')
SYS = Path('/sys/class/net')


def interface_name(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', value) or value == 'lo':
        raise ValueError('Select a normal physical/VM interface name')
    return value


def interfaces():
    code, text, error = system.command(['ip', '-j', 'address', 'show'])
    if code: raise ValueError('iproute2 is required: install it explicitly from Network Settings')
    rows = []
    for item in json.loads(text):
        if item['ifname'] == 'lo': continue
        rows.append({'name': item['ifname'], 'state': item.get('operstate', 'unknown'),
            'addresses': [str(a['local']) + '/' + str(a['prefixlen']) for a in item.get('addr_info', [])],
            'mac': item.get('address', '')})
    return rows


def validate_values(mode, address='', gateway='', dns=''):
    if mode not in ('dhcp', 'static'): raise ValueError('Select DHCP or static')
    settings = {'mode': mode, 'address': '', 'gateway': '', 'dns': []}
    if mode == 'static':
        if '/' not in address: raise ValueError('Use CIDR, for example 192.168.5.20/24')
        value = ipaddress.ip_interface(address)
        if value.version != 4 or value.ip.is_multicast or value.ip.is_unspecified or value.ip.is_loopback:
            raise ValueError('A valid unicast IPv4 host address is required')
        if value.network.prefixlen < 31 and value.ip in (value.network.network_address, value.network.broadcast_address):
            raise ValueError('Network/broadcast address is not a host address')
        settings['address'] = str(value)
        if gateway and gateway != '-':
            gate = ipaddress.ip_address(gateway)
            if gate.version != 4 or gate not in value.network or gate == value.ip or gate.is_multicast or gate.is_unspecified:
                raise ValueError('Gateway must be a different IPv4 address in the same subnet; off-link gateways need manual configuration')
            settings['gateway'] = str(gate)
    if dns and dns != '-':
        for token in dns.replace(',', ' ').split():
            value = ipaddress.ip_address(token)
            if value.is_multicast or value.is_unspecified: raise ValueError('Invalid DNS server')
            settings['dns'].append(str(value))
    return settings


def supported_link(iface):
    interface_name(iface)
    code, text, _ = system.command(['ip', '-d', '-j', 'link', 'show', 'dev', iface])
    if code: raise ValueError('Interface does not exist')
    entries = json.loads(text)
    if not entries: raise ValueError('Interface not found')
    item = entries[0]
    if item.get('link_type') not in (None,'ether'):
        raise ValueError('This wizard handles Ethernet/VM/Wi-Fi links, not this link type')
    kind = item.get('linkinfo', {}).get('info_kind', '')
    if kind in ('bridge', 'bond', 'vlan', 'veth', 'wireguard', 'tun', 'vxlan', 'macvlan') or item.get('master'):
        raise ValueError('This first wizard supports simple Ethernet/VM/Wi-Fi links; bridge/bond/VLAN/VPN/container links need manual configuration')
    return item


def ifupdown_sources():
    """Resolve source directives without shell expansion/execution."""
    first = ETC / 'network/interfaces'
    pending, found = [first] if first.exists() else [], []
    while pending:
        path = pending.pop(0)
        if path in found: continue
        if len(found) > 100: raise ValueError('Too many ifupdown include files')
        if path.is_symlink(): raise ValueError('ifupdown symlink configuration requires manual management')
        found.append(path)
        for line in path.read_text().splitlines():
            parts = shlex.split(line, comments=True)
            if len(parts) < 2 or parts[0] not in ('source', 'source-directory'): continue
            for pattern in parts[1:]:
                if any(c in pattern for c in ('$','`')): raise ValueError('Dynamic source expressions require manual management')
                target = Path(pattern) if pattern.startswith('/') else path.parent / pattern
                for value in glob.glob(str(target)):
                    value = Path(value)
                    if parts[0] == 'source-directory':
                        pending += [p for p in sorted(value.iterdir()) if p.is_file() and re.fullmatch(r'[A-Za-z0-9_-]+', p.name)]
                    elif value.is_file(): pending.append(value)
    return found


def ifupdown_stanzas(text, iface):
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if re.match(r'^\s*(iface|auto|allow-\S+|mapping|source|source-directory|rename)\s', line)]
    ranges = []
    for index, start in enumerate(starts):
        if re.match(r'^\s*iface\s+' + re.escape(iface) + r'\s+inet\s+\S+', lines[start]):
            end = starts[index+1] if index+1 < len(starts) else len(lines)
            ranges.append((start, end))
    return lines, ranges


def nm_profile(iface):
    code, ident, _ = system.command(['nmcli', '-g', 'GENERAL.CON-UUID', 'device', 'show', iface])
    if code or not re.fullmatch(r'[a-fA-F0-9-]{36}', ident): return None
    for folder in (ETC / 'NetworkManager/system-connections', Path('/run/NetworkManager/system-connections')):
        for path in folder.glob('*'):
            if not path.is_file() or path.is_symlink(): continue
            cfg = configparser.ConfigParser(interpolation=None, strict=False)
            try: cfg.read_string(path.read_text())
            except (OSError, ValueError, configparser.Error): continue
            if cfg.get('connection', 'uuid', fallback='') == ident:
                if folder.parts[:2] == ('/', 'run'):
                    raise ValueError('Runtime/generated NetworkManager profile: manage its Netplan/cloud-init source instead')
                return path, ident, cfg
    raise ValueError('Active NetworkManager profile has no readable persistent keyfile')


def netplan_documents():
    paths = sorted((ETC / 'netplan').glob('*.yaml'))
    if not paths: return []
    try: import yaml
    except ImportError: raise ValueError('Netplan YAML helper missing. Select Install python3-yaml in Network Settings, then retry.')
    docs = []
    for path in paths:
        if path.is_symlink(): raise ValueError('Netplan symlink files require manual management')
        data = yaml.safe_load(path.read_text()) or {}
        if not isinstance(data, dict): raise ValueError('Invalid Netplan document')
        docs.append((path, data))
    return docs


def netplan_matches(iface, docs):
    matches = []
    for path, data in docs:
        network = data.get('network', {})
        for group in ('ethernets', 'wifis'):
            for ident, value in network.get(group, {}).items():
                if not isinstance(value, dict): continue
                if ident == iface or value.get('set-name') == iface or value.get('match', {}).get('name') == iface:
                    matches.append((path, data, group, ident, value))
    if len({(group, ident) for _, _, group, ident, _ in matches}) > 1:
        raise ValueError('Ambiguous Netplan match: multiple definitions control the selected interface')
    return matches


def detect_backend(iface):
    # Netplan owns generated NetworkManager/networkd profiles when it defines this link.
    docs = netplan_documents()
    matches = netplan_matches(iface, docs)
    if matches: return 'netplan', matches
    if system.service('NetworkManager') == 'active':
        profile = nm_profile(iface)
        if profile: return 'networkmanager', profile
    sources = []
    for path in ifupdown_sources():
        _, ranges = ifupdown_stanzas(path.read_text(), iface)
        if ranges: sources.append(path)
    if sources: return 'ifupdown', sources
    if system.service('systemd-networkd') == 'active':
        code, text, _ = system.command(['networkctl', 'status', '--no-pager', '--no-legend', iface])
        match = re.search(r'Network File:\s+(\S+\.network)', text)
        if match:
            path = Path(match[1])
            if path.parent != ETC / 'systemd/network' or path.is_symlink():
                raise ValueError('Generated/vendor networkd configuration requires its source manager')
            return 'networkd', path
    raise ValueError('No unambiguous supported network manager configuration found for this interface')


def helper_command(backend, iface, ident=''):
    return [sys.executable, str(ENTRY), '--network-reload', json.dumps({'backend': backend, 'iface': iface, 'uuid': ident})]


def network_plan(iface, mode, address='', gateway='', dns=''):
    supported_link(iface)
    values = validate_values(mode, address, gateway, dns)
    backend, detail = detect_backend(iface)
    plan = Plan('Network Settings: ' + iface + ' → ' + mode.upper(), critical=True, detached=True, secrets=True,
        details=['Manager: ' + backend, 'Interface: ' + iface, 'IPv4: ' + (values['address'] or 'DHCP'),
                 'Gateway: ' + (values['gateway'] or 'DHCP / no new default gateway'),
                 'DNS: ' + (', '.join(values['dns']) or 'retain current / DHCP supplied'),
                 'IPv6 addressing is not disabled. Complex bridges/bonds/VLANs and multiple IPv4 stanzas are excluded.',
                 'Activation runs as an independent systemd job. Reconnect to the NEW address and confirm within 180 seconds.'])
    ident = ''
    resolver = ETC / 'resolv.conf'
    if resolver.exists() and not resolver.is_symlink(): plan.backup_paths.append(str(resolver))
    if backend == 'networkmanager':
        path, ident, cfg = detail
        if not cfg.has_section('ipv4'): cfg.add_section('ipv4')
        if any(re.fullmatch(r'route\d+|routing-rules', key) for key in cfg['ipv4']):
            raise ValueError('Custom NetworkManager IPv4 routes need manual review')
        for key in list(cfg['ipv4']):
            if re.fullmatch(r'address\d+', key) or key in ('gateway', 'method'): cfg.remove_option('ipv4', key)
        cfg.set('ipv4', 'method', 'auto' if mode == 'dhcp' else 'manual')
        if mode == 'static': cfg.set('ipv4', 'address1', values['address'] + (',' + values['gateway'] if values['gateway'] else ''))
        if values['dns']:
            cfg.set('ipv4', 'dns', ';'.join(values['dns']) + ';'); cfg.set('ipv4', 'ignore-auto-dns', 'true')
        elif mode == 'dhcp':
            cfg.remove_option('ipv4', 'dns'); cfg.set('ipv4', 'ignore-auto-dns', 'false')
        output = io.StringIO(); cfg.write(output, space_around_delimiters=False)
        plan.writes[str(path)] = output.getvalue(); plan.modes[str(path)] = 0o600
    elif backend == 'netplan':
        import yaml
        for _, _, _, _, original in detail:
            if 'renderer' in original and original['renderer'] not in ('networkd', 'NetworkManager'):
                raise ValueError('Unknown Netplan renderer')
        group, definition = detail[0][2:4]
        overlay = ETC / 'netplan' / ('99-aegis-' + iface + '.yaml')
        overlay_doc = None
        for path, document in netplan_documents():
            changed = False
            for _, _, _, ident0, obj in netplan_matches(iface, [(path, document)]):
                if ident0 != definition: continue
                old_addresses = obj.get('addresses', [])
                # Mapping-form addresses or advanced routing require manual management.
                if any(not isinstance(a, str) for a in old_addresses): raise ValueError('Advanced Netplan address mappings require manual review')
                obj['addresses'] = [a for a in old_addresses if ipaddress.ip_interface(a).version == 6]
                obj.pop('gateway4', None)
                routes = obj.get('routes', [])
                if any(not isinstance(r, dict) for r in routes): raise ValueError('Invalid Netplan routes')
                obj['routes'] = [r for r in routes if not (r.get('to') in ('default', '0.0.0.0/0') and ':' not in str(r.get('via', '')))]
                obj['dhcp4'] = mode == 'dhcp'
                if values['dns']:
                    obj.setdefault('nameservers', {})['addresses'] = []
                elif mode == 'dhcp':
                    obj.pop('dhcp4-overrides', None)
                    if 'nameservers' in obj: obj['nameservers']['addresses'] = []
                changed = True
            if path == overlay: overlay_doc = document
            if changed and path != overlay:
                plan.writes[str(path)] = yaml.safe_dump(document, sort_keys=False)
                plan.modes[str(path)] = 0o600
        overlay_doc = overlay_doc or {'network': {'version': 2}}
        obj = overlay_doc['network'].setdefault(group, {}).setdefault(definition, {})
        obj['dhcp4'] = mode == 'dhcp'
        if mode == 'static':
            obj['addresses'] = obj.get('addresses', []) + [values['address']]
            if values['gateway']: obj.setdefault('routes', []).append({'to': 'default', 'via': values['gateway']})
        if values['dns']:
            obj.setdefault('nameservers', {})['addresses'] = values['dns']
            if mode == 'dhcp': obj['dhcp4-overrides'] = {'use-dns': False}
        plan.writes[str(overlay)] = yaml.safe_dump(overlay_doc, sort_keys=False)
        plan.modes[str(overlay)] = 0o600
        plan.validate = [['netplan', 'generate']]
        plan.details += ['Cloud-init may regenerate its files on reboot; review cloud-init ownership separately.',
                         'Only supported definitions in /etc/netplan are edited. Runtime/vendor YAML requires manual review.',
                         'netplan apply can reconfigure other links; their stored definitions are preserved.']
        for folder in ('/run/netplan', '/lib/netplan'):
            if list(Path(folder).glob('*.yaml')): raise ValueError('Runtime/vendor Netplan YAML detected; review ownership before automatic editing')
    elif backend == 'ifupdown':
        if len(detail) != 1: raise ValueError('Interface defined in multiple files; manual review required')
        path = detail[0]
        lines, ranges = ifupdown_stanzas(path.read_text(), iface)
        if len(ranges) != 1: raise ValueError('Multiple IPv4 stanzas are not handled by this simple wizard')
        start, end = ranges[0]
        kept = []
        for line in lines[start+1:end]:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'): kept.append(line); continue
            key = stripped.split()[0]
            if key in ('pre-up', 'up', 'post-up', 'down', 'pre-down', 'post-down') or key.startswith(('bridge-', 'bond-', 'vlan-', 'wpa-')):
                raise ValueError('Custom ifupdown hooks/virtual links require manual review')
            if key == 'dns-nameservers' and not values['dns'] and mode == 'static':
                kept.append(line)
            elif key not in ('address', 'netmask', 'gateway', 'broadcast', 'network', 'dns-nameservers'):
                kept.append(line)
        replacement = ['iface ' + iface + ' inet ' + ('dhcp' if mode == 'dhcp' else 'static') + '\n']
        if mode == 'static':
            replacement += ['    address ' + values['address'] + '\n']
            if values['gateway']: replacement += ['    gateway ' + values['gateway'] + '\n']
        if values['dns']:
            if shutil_which('resolvconf'):
                replacement += ['    dns-nameservers ' + ' '.join(values['dns']) + '\n']
            else:
                resolv = ETC / 'resolv.conf'
                if resolv.is_symlink(): raise ValueError('DNS is managed through a symlink. Keep DNS unchanged (-) or use its resolver manager.')
                plan.writes[str(resolv)] = '# DNS configured by Aegis\n' + ''.join('nameserver ' + x + '\n' for x in values['dns'])
        plan.writes[str(path)] = ''.join(lines[:start] + replacement + kept + lines[end:])
        plan.validate = [['ifquery', iface]]
    elif backend == 'networkd':
        path = detail
        text = path.read_text()
        if re.search(r'^\s*\[(Route|RoutingPolicyRule|Address)\]', text, re.M):
            raise ValueError('Advanced networkd sections require manual review')
        cfg = configparser.ConfigParser(interpolation=None, strict=True)
        cfg.optionxform = str
        cfg.read_string(text)
        if not cfg.has_section('Network'): cfg.add_section('Network')
        section = cfg['Network']
        for key in ('Address', 'Gateway'):
            if key in section and ':' in section[key]: raise ValueError('Mixed static IPv6 entries require manual review')
            cfg.remove_option('Network', key)
        old_dhcp = section.get('DHCP', 'no').lower()
        section['DHCP'] = 'yes' if mode == 'dhcp' and old_dhcp in ('yes', 'ipv6', 'true') else (
            'ipv4' if mode == 'dhcp' else ('ipv6' if old_dhcp in ('yes', 'ipv6', 'true') else 'no'))
        if mode == 'static':
            section['Address'] = values['address']
            if values['gateway']: section['Gateway'] = values['gateway']
        if values['dns']:
            section['DNS'] = ' '.join(values['dns'])
            uses_resolved = system.service('systemd-resolved') == 'active' and (
                (resolver.is_symlink() and 'systemd/resolve' in str(resolver.resolve())) or '127.0.0.53' in system.read(resolver))
            if not uses_resolved:
                if resolver.is_symlink(): raise ValueError('DNS symlink is managed by another provider; keep DNS (-) or use that provider')
                plan.writes[str(resolver)] = '# DNS configured by Aegis\n' + ''.join('nameserver '+server+'\n' for server in values['dns'])
        output = io.StringIO(); cfg.write(output, space_around_delimiters=False)
        plan.writes[str(path)] = output.getvalue()
        plan.details += ['DNS settings are effective through systemd-resolved when it is configured as the system resolver.']
    plan.commands = [helper_command(backend, iface, ident)]
    plan.rollback_commands = [helper_command(backend, iface, ident)]
    return plan


def shutil_which(value):
    import shutil
    return shutil.which(value)


def reload_backend(backend, iface, ident=''):
    interface_name(iface)
    if backend == 'networkmanager':
        if not re.fullmatch(r'[a-fA-F0-9-]{36}', ident): raise ValueError('Invalid connection UUID')
        commands = [['nmcli', 'connection', 'reload'], ['nmcli', '--wait', '45', 'connection', 'up', 'uuid', ident, 'ifname', iface]]
    elif backend == 'netplan': commands = [['netplan', 'generate'], ['netplan', 'apply']]
    elif backend == 'networkd': commands = [['networkctl', 'reload'], ['networkctl', 'reconfigure', iface]]
    elif backend == 'ifupdown':
        subprocess.run(['ifdown', '--force', iface], timeout=25)
        commands = [['ifup', iface]]
    else: raise ValueError('Unknown network backend')
    for args in commands:
        if subprocess.run(args, timeout=55).returncode: raise RuntimeError('Network manager activation failed: ' + args[0])
