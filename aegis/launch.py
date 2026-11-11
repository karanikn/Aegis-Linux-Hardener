"""Explicit external-tool launch / Άνοιγμα εφαρμογών με σταθερά argv, χωρίς shell."""
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
from . import catalog,console,system,appregistry

# fixed defaults; no tunnel, daemon, scanner target or service activation is implicit.
DEFAULTS={
 'btop':('btop',[]),'htop':('htop',[]),'mc':('mc',[]),'ncdu':('ncdu',['-r','/']),
 'lf':('lf',[]),'rovr':('rovr',[]),'glances':('glances',[]),'nmon':('nmon',[]),
 'bmon':('bmon',[]),'nload':('nload',[]),'pydf':('pydf',[]),'lm-sensors':('sensors',[]),
 'tmux':('tmux',[]),'tmate':('tmate',['--help']),'ngrok':('ngrok',['help']),
 'aria2':('aria2c',['--help']),'curl':('curl',['--version']),'unrar-free':('unrar-free',['--help']),
 'ccze':('ccze',['--help']),'netdiag':('dpkg',['-L','netdiag']),
 'lynis':('lynis',['show','help']),'docker':('docker',['ps','-a']),
 'docker-dash':('docker-dash',[]),'dockmate':('dockmate',[]),'dtop':('dtop',[]),'lazydocker':('lazydocker',[]),
 'fresh':('fresh',[]),'lazyide':('lazyide',[]),'microneo':('microneo',[]),'pnana':('pnana',[]),
 'hwinfo-tui':('hwinfo-tui',['--help']),'vnstat':('vnstat',[]),'collectl':('collectl',[]),
 'incron':('incrontab',['-l']),'nmap':('nmap',['--help']),'rtop':('rtop',['-h']),
 'logwatch':('logwatch',['--output','stdout','--range','today']),
 'iotop':('iotop',['-o']),'nethogs':('nethogs',[]),'bandwhich':('bandwhich',[]),
 'iptraf':('iptraf-ng',[]),'netscanner':('netscanner',[]),'chkservice':('chkservice',[]),'rcconf':('rcconf',[]),
}
ROOT_TOOLS={'apachetop','logwatch','iotop','nethogs','bandwhich','iptraf','netscanner','chkservice','rcconf','iftop','tcptrack','tcpdump','hddtemp'}
GUIDES={
 'samba':'Open Share Management for shares, connected clients, Samba accounts and service controls.',
 'ucaresystem-core':'Open Maintenance → Run uCareSystem Core. That action includes a reviewed change plan and package/configuration backups.',
 'webmin':'Webmin: ssh -L 10000:127.0.0.1:10000 USER@SERVER\nThen open https://127.0.0.1:10000 on your workstation. Use the configured address if this is an older installation.',
 'cockpit':'Cockpit: ssh -L 9090:127.0.0.1:9090 USER@SERVER\nThen open https://127.0.0.1:9090 on your workstation.',
 'caddy':'Inspect service: systemctl status caddy\nNew Aegis install uses http://127.0.0.1:8080. Existing Caddy may use your own ports/configuration.',
 'winboat':'Launch WinBoat from your graphical desktop application menu as your desktop user. An SSH server session cannot open its local graphical window reliably.',
 'nmtui':'Open Network Settings → Open nmtui. That path adds a configuration backup and native NetworkManager checkpoint.',
 'watcher':'Exact upstream URL is required before installation or launch.',
 'psnet':'Windows-only upstream. Use the Linux network monitors in the catalog.',
}


def launch_args(key,detail=''):
    if key not in {x[0] for x in catalog.all_apps()}:raise ValueError('Unknown catalog application')
    custom=appregistry.get(key) if key.startswith('custom-') else None
    if custom:
        if not custom['command']:return None
        code,contents,_=system.command(['dpkg-query','-L',custom['package']])
        owned=set(contents.splitlines()) if code==0 else set()
        for directory in ('/usr/bin','/bin'):
            path=Path(directory)/custom['command']
            if str(path) in owned and path.is_file() and os.access(path,os.X_OK):return [str(path)]
        raise ValueError('The configured executable is not owned by this installed package in /usr/bin or /bin. Edit/remove the entry or review package contents.')
    if key in GUIDES:return None
    if key in ('iftop','tcptrack','tcpdump'):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}',detail):raise ValueError('Choose a valid interface')
        if detail not in {x[1] for x in system.socket.if_nameindex()}:raise ValueError('Interface does not exist')
        args={'iftop':['iftop','-i',detail],'tcptrack':['tcptrack','-i',detail],
              'tcpdump':['tcpdump','-nn','-i',detail,'-c','100']}[key]
    elif key in ('apachetop','termshark'):
        if not detail or detail.startswith('-') or '\x00' in detail:raise ValueError('Provide a file path')
        path=Path(detail).expanduser().resolve(strict=True)
        if not path.is_file():raise ValueError('Choose a regular file')
        if key=='apachetop' and Path('/var/log') not in path.parents:raise ValueError('Select an Apache log inside /var/log')
        args=['apachetop','-f',str(path)] if key=='apachetop' else ['termshark','-r',str(path)]
    elif key=='hddtemp':
        if not re.fullmatch(r'/dev/(?:sd[a-z]+|nvme\d+n\d+|hd[a-z]+)',detail):raise ValueError('Choose a supported disk device path')
        args=['hddtemp',detail]
    elif key in DEFAULTS:
        command,flags=DEFAULTS[key];args=[command]+list(flags)
    else:raise ValueError('This catalog entry has no supported launcher; review its official usage instructions.')
    command=shutil.which(args[0])
    if not command:raise ValueError(args[0]+' executable is unavailable. Refresh installed status or inspect the package contents.')
    args[0]=command
    return args


def open_app(key,user,detail=''):
    if key in GUIDES:
        print(GUIDES[key]);return
    if not catalog.app_version(key):raise ValueError('Application is not installed; install it first.')
    args=launch_args(key,detail)
    if args is None:
        custom=appregistry.get(key)
        print('Package contents / usage details: '+custom['package'])
        print(system.command(['dpkg-query','-L',custom['package']])[1]);return
    account=pwd.getpwnam(user)
    if os.geteuid()==0 and key not in ROOT_TOOLS:
        if account.pw_uid==0:raise ValueError('Open this user-facing tool from a regular account with sudo, so it runs under your own user profile.')
        args=['runuser','-u',user,'--','env','HOME='+account.pw_dir]+args
    elif os.geteuid()!=0 and key in ROOT_TOOLS:raise ValueError('Use the Aegis privileged launcher for this tool')
    print('Opening '+key+'. Exit with its own q/Ctrl+C command to return to Aegis.')
    print('Actions performed inside external tools use their own behavior/history; Aegis installation undo covers installation changes.')
    try:subprocess.run(args,check=False)
    except KeyboardInterrupt:print('\nReturned to Aegis.')
