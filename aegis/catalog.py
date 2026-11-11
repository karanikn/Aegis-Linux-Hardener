"""Curated app plans from distribution/vendor sources / Κατάλογος εφαρμογών."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import urllib.request
from . import system, appdata, categories, appregistry
from .actions import Plan

APPS = [
 ('ucaresystem-core', 'uCareSystem Core', 'Updates and maintenance; vendor package may add its repository/key.', 'https://github.com/Utappia/uCareSystem'),
 ('btop', 'btop', 'Interactive CPU/RAM/process monitor.', 'https://github.com/aristocratos/btop'),
 ('ncdu', 'ncdu', 'Explore disk space usage.', 'https://dev.yorhel.nl/ncdu'),
 ('lynis', 'Lynis', 'Security audit and hardening suggestions.', 'https://cisofy.com/lynis/'),
 ('docker', 'Docker Engine + Compose', 'Official vendor APT repo; existing runtimes are never removed automatically.', 'https://docs.docker.com/engine/install/'),
 ('caddy', 'Caddy', 'Official stable repository. A new instance binds to 127.0.0.1:8080.', 'https://caddyserver.com/docs/install'),
 ('webmin', 'Webmin', 'Official repository. A new instance binds to localhost:10000.', 'https://webmin.com/download/'),
 ('winboat', 'WinBoat', 'Desktop Windows-app integration; KVM, Docker/Podman, FreeRDP 3 required.', 'https://www.winboat.app/'),
 ('cockpit', 'Cockpit', 'Distribution package. A new socket binds to localhost:9090.', 'https://cockpit-project.org/running.html'),
]
PACKAGE_NAMES = {'docker': 'docker-ce', 'fresh':'fresh-editor', 'iptraf':'iptraf-ng', 'nmtui':'network-manager'}
DISTRO_SPECS={row[0]:row for row in appdata.DISTRO}
UPSTREAM_SPECS={row[0]:row for row in appdata.UPSTREAM}
COMMANDS={row[0]:row[3] for row in appdata.DISTRO+appdata.UPSTREAM}
for key,label,package,command,purpose,example,note in appdata.DISTRO:
    if key not in {x[0] for x in APPS}:
        APPS.append((key,label,purpose,'https://packages.debian.org/search?keywords='+package))
for key,label,repo,command,purpose,example,note in appdata.UPSTREAM:
    APPS.append((key,label,purpose,'https://github.com/'+repo))
APPS += [
 ('rovr','rovr','Stylish terminal file manager with previews and navigation.','https://github.com/NSPC911/rovr'),
 ('hwinfo-tui','hwinfo-tui','Visualize Windows HWiNFO sensor CSV logs; not Linux sensor collection.','https://github.com/JuanjoFuchs/hwinfo-tui'),
 ('psnet','psnet','Windows PowerShell network monitor; not supported on Linux.','https://github.com/psmux/psnet'),
 ('watcher','watcher','Ambiguous project name: exact upstream identity required.',''),
 ('ngrok','ngrok','Outbound tunnel client; installation starts no public endpoint.','https://ngrok.com/download/linux'),
]
# uCareSystem remains pinned first, as requested in the original catalog.
APPS=[APPS[0]]+sorted(APPS[1:],key=lambda row:row[0].casefold())


def all_apps():
    extra=[(r['key'],r['label'],r['description'],'https://packages.debian.org/search?keywords='+r['package']) for r in appregistry.load()['custom']]
    return [APPS[0]]+sorted(APPS[1:]+extra,key=lambda row:row[1].casefold())


def visible_apps(candidates=None):
    hidden=set(appregistry.load()['hidden'])|appregistry.REMOVED_GUIDES
    return [r for r in all_apps() if r[0] not in hidden and capability(r[0],candidates)[0]!='guide']


def category_for(key):
    row=appregistry.get(key) if key.startswith('custom-') else None
    return row['category'] if row else categories.category(key)


def package_for(key):
    row=appregistry.get(key) if key.startswith('custom-') else None
    if row:return row['package']
    return DISTRO_SPECS[key][2] if key in DISTRO_SPECS else PACKAGE_NAMES.get(key,key)


def package_candidate(package):
    code,text,_=system.command(['apt-cache','policy',package])
    match=re.search(r'^\s*Candidate:\s*(\S+)',text,re.M)
    return match.group(1) if code==0 and match and match.group(1)!='(none)' else None


def package_versions():
    """One dpkg query for the whole page. Never spawn dpkg per arrow key."""
    _,text,_=system.command(['dpkg-query','-W','-f=${binary:Package}\t${db:Status-Status}\t${Version}\n'])
    packages={}
    for line in text.splitlines():
        parts=line.split('\t')
        if len(parts)==3 and parts[1]=='installed':packages[parts[0].split(':')[0]]=parts[2]
    return packages


def managed_version(key):
    if key not in {row[0] for row in APPS}:return None
    path=Path('/opt/aegis-tools/receipts')/(key+'.json')
    try:
        info=json.loads(path.read_text())
        target=Path('/usr/local/bin')/COMMANDS.get(key,key)
        if info.get('target')==str(target) and target.is_file() and not target.is_symlink():return str(info['version'])
    except (OSError,ValueError,KeyError):pass
    return None


def catalog_versions():
    packages=package_versions()
    versions={}
    for key,*_ in all_apps():
        package=package_for(key)
        value=packages.get(package)
        if key=='docker':value=value or packages.get('docker.io')
        if not key.startswith('custom-') and not value and shutil.which(COMMANDS.get(key,key)):value=managed_version(key) or 'external executable'
        versions[key]=value
    return versions


def package_candidates():
    names=sorted(set([row[2] for row in appdata.DISTRO]+[PACKAGE_NAMES.get(row[0],row[0]) for row in appdata.UPSTREAM]+[r['package'] for r in appregistry.load()['custom']]))
    code,text,_=system.command(['apt-cache','policy']+names)
    result={};current=None
    for line in text.splitlines():
        match=re.fullmatch(r'([^\s:]+)(?::[A-Za-z0-9_-]+)?:',line)
        if match:current=match[1]
        candidate=re.match(r'\s*Candidate:\s*(\S+)',line)
        if candidate and current:result[current]=None if candidate[1]=='(none)' else candidate[1]
    return result


def capability(key,candidates=None):
    if key.startswith('custom-'):
        row=appregistry.get(key)
        if not row:raise ValueError('Unknown custom application')
        return ('apt','Custom APT package: '+row['package']) if candidates is None or candidates.get(row['package']) else ('unavailable','No APT candidate for '+row['package']+'. Refresh metadata to recheck.')
    if key=='psnet':return 'guide','Windows-only upstream; no Linux installer.'
    if key=='watcher':return 'guide','Exact project URL required; no unrelated package is substituted.'
    if key=='pnana' and not (candidates or {}).get(key):return 'guide','Manual source build: requires reviewed FTXUI/CMake dependencies; no automatic recipe yet.'
    package=DISTRO_SPECS[key][2] if key in DISTRO_SPECS else PACKAGE_NAMES.get(key,key)
    if candidates is not None and candidates.get(package):return 'apt','APT package: '+package
    if key=='netscanner':return 'source','Verified crates.io source build using isolated Rust; compile as regular user.'
    if key in ('rovr','hwinfo-tui'):return 'python','Isolated Python install; current upstream Python requirement checked first.'
    if key in UPSTREAM_SPECS:return 'binary','Official Linux release binary, checked for supported architecture.'
    if key in DISTRO_SPECS:
        if candidates is not None and not candidates.get(package):return 'unavailable','No current APT candidate for '+package+'. Refresh metadata to recheck; no foreign repository is added.'
        return 'apt','Distribution package availability is checked before install.'
    return 'vendor','Reviewed vendor/release installation; platform prerequisites apply.'


def app_information(key,version=None,availability=None):
    row=next(x for x in all_apps() if x[0]==key)
    _,label,description,url=row
    lines=[label.upper(),'','What it does',description,'','Installation / status',
           'Installed: '+(version or 'not detected'),'Category: '+category_for(key)]
    if key.startswith('custom-'):
        custom=appregistry.get(key)
        lines+=['APT package: '+custom['package'],'Launcher: '+(custom['command'] or 'Package contents / usage details'),
                'Custom APT entry. Open runs only a package-owned executable as your regular user. No root launcher or command arguments.']
    if availability:lines+=['Install method: '+availability[0],availability[1]]
    spec=DISTRO_SPECS.get(key) or UPSTREAM_SPECS.get(key)
    if spec:
        lines += ['APT package: '+(spec[2] if key in DISTRO_SPECS else key)+' (if available for your suite)',
                  '', 'Example',spec[5],'','Requirements / notes',spec[6]]
    if key in UPSTREAM_SPECS:lines+=['','Fallback: verified official Linux release asset when one is available.']
    extra={
     'watcher':'Several unrelated tools use this name. No OpenStack watcher package is substituted. Supply its project URL before enabling installation.',
     'psnet':'Upstream currently uses Windows APIs; Linux support is listed as future work. Use bandwhich, NetHogs or iftop on Linux.',
     'hwinfo-tui':'Python 3.10+; isolated Python environment. Reads HWiNFO64 CSV produced on Windows. Use lm-sensors for local Linux sensors.',
     'rovr':'Isolated Python environment; exact Python requirement is shown at install. Does not replace system Python.',
     'ngrok':'Requires an account/token for use. Install does not add a token, service or tunnel. Starting a tunnel can publish a local service.',
     'ucaresystem-core':'System maintenance utility: updates, upgrades and cleanup. Running maintenance is separate from install; inspect repository compatibility on Debian.',
     'docker':'Requires a running systemd host and supported vendor repository. Existing engines are preserved. No automatic docker-group membership.',
     'webmin':'Web administration UI. New managed install binds to localhost:10000; connect through an SSH tunnel.',
     'cockpit':'Browser-based server administration. New managed install binds to localhost:9090; connect through an SSH tunnel.',
     'caddy':'Web server/reverse proxy. New managed install binds to localhost:8080. No public DNS/TLS/proxy routes are configured.',
     'winboat':'Graphical desktop, KVM, container runtime, FreeRDP 3 and sufficient resources required. Does not install a Windows guest.',
     'btop':'Interactive CPU, RAM, disk and network monitor. Example: btop. No monitoring daemon is enabled.',
     'lynis':'Security audit and recommendations. Example: sudo lynis audit system. Findings are not automatically applied.',
    }
    if key in extra:lines+=['','Important',extra[key]]
    if key=='pnana':lines+=['','Source-build procedure','Follow upstream docs/DEPENDENCIES.md and build.sh; compile as a regular user. No root-executed build script is offered.']
    if key=='netscanner':lines+=['','Source-build procedure','Aegis can build the pinned crates.io release using isolated stable Rust, verified SHA256 and Cargo.lock.','Build executes as a regular user. Output is mode 0755; no SUID. Uninstall/Undo are available.']
    lines+=['','Official source',url or 'Not specified','', 'Enter: application actions (open / install / details)','Tab: focus information; PgUp/PgDn: scroll']
    return '\n'.join(lines)



def fetch(url, maximum=512 * 1024 * 1024):
    if not url.startswith('https://'): raise ValueError('HTTPS required')
    request = urllib.request.Request(url, headers={'User-Agent': 'Aegis-Linux-Hardener/0.6.0', 'Accept': 'application/json, */*'})
    with urllib.request.urlopen(request, timeout=45) as response:
        if not response.url.startswith('https://'): raise ValueError('Insecure redirect refused')
        data = response.read(maximum + 1)
    if len(data) > maximum: raise ValueError('Download exceeds allowed size')
    return data


def latest_asset(repo, pattern):
    release = json.loads(fetch('https://api.github.com/repos/' + repo + '/releases/latest', 4 * 1024 * 1024))
    matches = [x for x in release.get('assets', []) if re.fullmatch(pattern, x['name'])]
    if len(matches) != 1: raise ValueError('No unique matching upstream .deb asset; inspect official releases manually')
    item = matches[0]
    url = item['browser_download_url']
    if not url.startswith('https://github.com/' + repo + '/releases/download/'):
        raise ValueError('Release URL did not match the expected repository')
    data = fetch(url)
    digest = hashlib.sha256(data).hexdigest()
    expected = item.get('digest')
    if expected and expected != 'sha256:' + digest: raise ValueError('Upstream SHA256 verification failed')
    return release.get('tag_name', ''), item['name'], data, digest, bool(expected)


def package_plan(packages, title=None):
    if not system.debian_based(): raise ValueError('Requires a Debian-based APT system')
    return Plan(title or 'Install ' + ', '.join(packages),
        details=['Source: repositories already configured for this system.',
                 'APT will show its dependency changes and ask for confirmation.'],
        before=[['apt-get', 'update'], ['apt-get', 'install'] + packages], package_change=True)


def winboat_requirements(user):
    missing = []
    if not system.desktop_present(): missing.append('Linux graphical desktop not detected')
    if system.command(['dpkg', '--print-architecture'])[1] != 'amd64': missing.append('This installer currently selects only the upstream amd64 .deb')
    if not Path('/dev/kvm').exists(): missing.append('/dev/kvm is unavailable')
    mem = system.memory()
    if mem['total_gib'] < 3.8: missing.append('At least 4 GiB RAM required')
    if (os.cpu_count() or 1) < 2: missing.append('At least 2 CPU threads required')
    try:
        account = pwd.getpwnam(user)
        if shutil.disk_usage(account.pw_dir).free < 32 * 1073741824: missing.append('At least 32 GiB free in user home required by this preflight')
    except (KeyError, OSError): missing.append('A valid desktop user account is required')
    docker_ok = system.command(['docker', 'info'])[0] == 0 and system.command(['docker', 'compose', 'version'])[0] == 0
    podman_ok = shutil.which('podman') and shutil.which('podman-compose')
    if not docker_ok and not podman_ok: missing.append('Running Docker Engine + Compose v2, or Podman + Compose required')
    if docker_ok and 'docker' not in system.command(['id', '-nG', user])[1].split():
        missing.append('Desktop user needs Docker access; group membership is NOT added automatically')
    rdp = shutil.which('xfreerdp3') or shutil.which('xfreerdp')
    if not rdp or not re.search(r'\b3\.\d', system.command([rdp, '/version'])[1] + system.command([rdp, '/version'])[2]):
        missing.append('FreeRDP 3.x with sound support is required; runtime build features must be checked separately')
    return missing


def app_version(key):
    if key.startswith('custom-'):
        row=appregistry.get(key)
        return system.installed(row['package']) if row else None
    if key == 'docker':
        return system.installed('docker-ce') or system.installed('docker.io') or ('external runtime' if shutil.which('docker') else None)
    package=DISTRO_SPECS[key][2] if key in DISTRO_SPECS else PACKAGE_NAMES.get(key,key)
    return system.installed(package) or ((managed_version(key) or 'external executable') if shutil.which(COMMANDS.get(key,key)) else None)


def app_plan(key, user):
    if key not in {x[0] for x in all_apps()}: raise ValueError('Unknown catalog application')
    if app_version(key): raise ValueError('Already installed. Existing applications are left untouched; use Maintenance for updates.')
    if key.startswith('custom-'):
        row=appregistry.get(key)
        if not package_candidate(row['package']):raise ValueError('No APT candidate for '+row['package']+'; refresh metadata first.')
        plan=package_plan([row['package']],'Install '+row['label']);plan.suppress_services=True
        plan.details+=['Custom entry: automatic service starts are suppressed during installation. Existing configured repositories are used.']
        return plan
    if key=='samba':
        from . import shares
        return shares.install_plan()
    if key in ('watcher','psnet'):
        raise ValueError(app_information(key))
    if key in ('rovr','hwinfo-tui'):
        from .toolinstall import python_plan
        return python_plan(key,user)
    if key=='ngrok':
        from .toolinstall import binary_plan
        return binary_plan(key)
    if key in UPSTREAM_SPECS:
        package=PACKAGE_NAMES.get(key,key)
        if package_candidate(package):return package_plan([package])
        if key=='netscanner':
            from .sourcebuild import source_plan
            return source_plan(user)
        from .toolinstall import BINARY_REPOS,binary_plan
        if key in BINARY_REPOS:return binary_plan(key)
        raise ValueError('No APT candidate or verified prebuilt release for this suite.\n'+app_information(key))
    if key in DISTRO_SPECS and key!='ncdu':
        package=DISTRO_SPECS[key][2]
        if not package_candidate(package):raise ValueError('No APT candidate for '+package+'. Refresh metadata in Maintenance. No obsolete/foreign repository is added.\n'+app_information(key))
        plan=package_plan([package])
        plan.details += [DISTRO_SPECS[key][6]]
        plan.suppress_services=True
        if key=='nmtui':
            plan.backup_paths += ['/etc/NetworkManager']
            plan.commands=[['systemctl','disable','NetworkManager.service','NetworkManager-wait-online.service']]
            plan.details+=['New NetworkManager daemon is not started/enabled. Existing network backend is not migrated.']
        if key in ('collectl','incron','vnstat'):
            from .actions import ENTRY
            import sys
            value={'unit':key+'.service','active':False,'enabled':False}
            plan.commands.append([sys.executable,str(ENTRY),'--restore-service-state',json.dumps(value)])
        if key=='termshark':plan.before[-1].append('tshark')
        return plan
    if key in ('btop', 'ncdu', 'lynis'):
        return package_plan([key])
    if key == 'cockpit':
        plan = package_plan(['cockpit'], 'Install Cockpit (localhost only)')
        plan.suppress_services = True
        plan.writes['/etc/systemd/system/cockpit.socket.d/90-aegis-localhost.conf'] = '[Socket]\nListenStream=\nListenStream=127.0.0.1:9090\n'
        plan.commands = [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', 'cockpit.socket']]
        plan.rollback_commands = [['systemctl', 'disable', '--now', 'cockpit.socket'], ['systemctl', 'daemon-reload']]
        plan.details += ['Access using an SSH tunnel: ssh -L 9090:127.0.0.1:9090 USER@SERVER',
                         'Then open https://127.0.0.1:9090. No firewall allow-rule is added.']
        return plan
    if key in ('ucaresystem-core', 'winboat'):
        if key == 'winboat':
            missing = winboat_requirements(user)
            if missing: raise ValueError('WinBoat preflight:\n- ' + '\n- '.join(missing))
            repo, pattern = 'winboat-org/winboat', r'winboat.*(?:amd64|x64).*\.deb'
        else:
            repo, pattern = 'Utappia/uCareSystem', r'ucaresystem-core_.*\.deb'
        tag, name, data, digest, verified = latest_asset(repo, pattern)
        target = '/var/cache/aegis-linux-hardener/' + name
        plan = Plan('Install ' + key + ' ' + tag,
            details=['Source: https://github.com/' + repo, 'Asset: ' + name, 'SHA256: ' + digest,
                     'Upstream digest verified.' if verified else 'No upstream asset digest provided; HTTPS origin and displayed hash are used.',
                     'Vendor package scripts/dependencies are executed by APT.',
                     'uCareSystem installation may add the Utappia repository/key; Debian support is described as partial upstream.'
                     if key == 'ucaresystem-core' else 'Installs the desktop client only; no Windows guest is installed/launched.'],
            writes={target: data}, package_change=True, suppress_services=True,
            commands=[['apt-get', 'update'], ['apt-get', 'install', target]])
        # Suppression must span dpkg package hooks too; execute local install in the before-writes phase is impossible.
        # The engine's dedicated install stage below runs while service-start suppression remains active.
        plan.before = []
        plan.validate = plan.commands
        plan.commands = []
        return plan
    plan = Plan('Install ' + key, package_change=True, suppress_services=True,
                details=['Adds the selected official vendor signing key and APT source.',
                         'New services are held stopped until local configuration has been written.'])
    plan.before = [['apt-get', 'update'], ['apt-get', 'install', 'ca-certificates']]
    if key == 'docker':
        distro, suite = system.base_distribution()
        conflicts = [p for p in ('docker.io', 'docker-compose', 'docker-compose-v2', 'podman-docker', 'containerd', 'runc') if system.installed(p)]
        if conflicts: raise ValueError('Conflicting existing runtime packages are NOT removed: ' + ', '.join(conflicts))
        arch = system.command(['dpkg', '--print-architecture'])[1]
        if not re.fullmatch(r'[a-z0-9]+', arch): raise ValueError('Invalid architecture')
        plan.writes['/etc/apt/keyrings/aegis-docker.asc'] = fetch('https://download.docker.com/linux/' + distro + '/gpg', 1024 * 1024)
        plan.writes['/etc/apt/sources.list.d/aegis-docker.sources'] = (
            'Types: deb\nURIs: https://download.docker.com/linux/' + distro + '\nSuites: ' + suite +
            '\nComponents: stable\nArchitectures: ' + arch + '\nSigned-By: /etc/apt/keyrings/aegis-docker.asc\n')
        plan.validate = [['apt-get', 'update'], ['apt-get', 'install', 'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-buildx-plugin', 'docker-compose-plugin']]
        plan.commands = [['systemctl', 'enable', '--now', 'docker']]
        plan.details += ['Docker can modify host forwarding/firewall rules. Published ports can bypass UFW.',
                         'No user is automatically added to the root-equivalent docker group.']
    elif key == 'caddy':
        plan.writes['/etc/apt/keyrings/aegis-caddy.asc'] = fetch('https://dl.cloudsmith.io/public/caddy/stable/gpg.key', 1024 * 1024)
        plan.writes['/etc/apt/sources.list.d/aegis-caddy.list'] = 'deb [signed-by=/etc/apt/keyrings/aegis-caddy.asc] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main\n'
        plan.validate = [['apt-get', 'update'], ['apt-get', 'install', 'caddy']]
        plan.late_writes['/etc/caddy/Caddyfile'] = 'http://127.0.0.1:8080 {\n    respond "Caddy installed by Aegis Linux Hardener"\n}\n'
        plan.post_validate = [['caddy', 'validate', '--config', '/etc/caddy/Caddyfile']]
        plan.commands = [['systemctl', 'enable', '--now', 'caddy']]
        plan.rollback_commands = [['systemctl', 'disable', '--now', 'caddy']]
        # Installed AFTER the vendor package so dpkg cannot overwrite this managed default.
        plan.details += ['A new Caddyfile will serve only http://127.0.0.1:8080.',
                         'Existing /etc/caddy/Caddyfile must not be present for this fresh-install path.']
        if Path('/etc/caddy/Caddyfile').exists(): raise ValueError('Existing Caddyfile detected; configure existing Caddy manually')
    elif key == 'webmin':
        plan.writes['/etc/apt/keyrings/aegis-webmin.asc'] = fetch('https://download.webmin.com/developers-key.asc', 1024 * 1024)
        plan.writes['/etc/apt/sources.list.d/aegis-webmin.list'] = 'deb [signed-by=/etc/apt/keyrings/aegis-webmin.asc] https://download.webmin.com/download/newkey/repository stable contrib\n'
        plan.validate = [['apt-get', 'update'], ['apt-get', 'install', '--install-recommends', 'webmin']]
        def local_webmin(text):
            if not text.strip(): raise RuntimeError('Webmin did not create miniserv.conf')
            lines = [line for line in text.splitlines() if not line.startswith(('bind=', 'allow=', 'ipv6='))]
            return '\n'.join(lines) + '\nbind=127.0.0.1\nallow=127.0.0.1\nipv6=0\n'
        plan.late_writes['/etc/webmin/miniserv.conf'] = local_webmin
        plan.modes['/etc/webmin/miniserv.conf'] = 0o600
        plan.commands = [['systemctl', 'enable', '--now', 'webmin']]
        plan.rollback_commands = [['systemctl', 'disable', '--now', 'webmin']]
        plan.details += ['A new Webmin binds to 127.0.0.1:10000.',
                         'Access with: ssh -L 10000:127.0.0.1:10000 USER@SERVER',
                         'Then open https://127.0.0.1:10000.']
        if Path('/etc/webmin/miniserv.conf').exists(): raise ValueError('Existing Webmin configuration detected; use its management tools')
    for path, value in plan.writes.items():
        if path.endswith('.asc'):
            if not value.lstrip().startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'):
                raise ValueError('Vendor did not return an ASCII-armored signing key')
            plan.details.append('Signing key SHA256 (' + path + '): ' + hashlib.sha256(value).hexdigest())
    return plan
