"""Categorized bounded log snapshots, ANSI color and reviewed export/Telegram send.
EL: Το ίδιο στιγμιότυπο εμφανίζεται, εξάγεται και αποστέλλεται· όχι κρυφή νέα συλλογή.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import urllib.error
import urllib.request
import uuid
from . import actions,alerts,catalog,console,system

MAX_BYTES=2*1024*1024
PERIODS={'boot':['-b'],'hour':['--since','1 hour ago'],'today':['--since','today'],'day':['--since','24 hours ago'],'week':['--since','7 days ago']}
CATEGORIES=[
 ('system','System / journal','Recent systemd journal events.'),
 ('auth','Authentication / SSH / sudo','SSH, sudo and authentication journal events.'),
 ('kernel','Kernel / hardware','Kernel, device and driver messages.'),
 ('fail2ban','Fail2Ban','Ban/unban events and daemon errors.'),
 ('firewall','Firewall / UFW','Kernel firewall messages (UFW/netfilter/nftables).'),
 ('apt','APT / dpkg','Package manager log tails; file sources use line limits, not journal time filtering.'),
 ('apache','Apache','Service journal and Apache error/access file tails.'),
 ('nginx','Nginx','Service journal and Nginx error/access file tails.'),
 ('caddy','Caddy','Caddy systemd service journal.'),
 ('docker','Docker engine','Docker daemon journal; container stdout is available separately.'),
 ('container','Docker container','Recent stdout/stderr from a selected container; no shell enters the container.'),
 ('telegram','Telegram alerts','Collector/timer journal; token patterns are masked.'),
 ('security','Security daemons','AppArmor/auditd/PortSentry/knockd/Shorewall journal.'),
 ('service','Selected systemd service','Enter a service unit such as ssh.service.'),
 ('file','Selected /var/log file','Read a regular file within /var/log; no arbitrary root file access.'),
]
UNITS={'fail2ban':['fail2ban.service'],'apache':['apache2.service'],'nginx':['nginx.service'],
       'caddy':['caddy.service'],'docker':['docker.service'],
       'telegram':['linux-telegram-alerts.service','linux-telegram-alerts.timer'],
       'security':['apparmor.service','auditd.service','portsentry.service','knockd.service','shorewall.service']}
FILES={'apt':['/var/log/apt/history.log','/var/log/apt/term.log','/var/log/dpkg.log'],
       'apache':['/var/log/apache2/error.log','/var/log/apache2/access.log'],
       'nginx':['/var/log/nginx/error.log','/var/log/nginx/access.log']}
ANSI=re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-_]')


def clean(text,redact=True):
    text=ANSI.sub('',str(text))
    text=''.join(ch for ch in text if ch in '\n\t' or ord(ch)>=32 and not 127<=ord(ch)<=159)
    if redact:
        text=re.sub(r'\b\d{5,16}:[A-Za-z0-9_-]{20,}\b','[REDACTED_BOT_TOKEN]',text)
        text=re.sub(r'(?i)(authorization\s*[:=]\s*)(?:bearer|basic)\s+[^\s,;]+',r'\1[REDACTED]',text)
        text=re.sub(r'(?i)(["\']?(?:password|passwd|api[_-]?key|access[_-]?token|secret|token)["\']?\s*[:=]\s*)("[^"\n]*"|\x27[^\x27\n]*\x27|[^\s,;&]+)',r'\1[REDACTED]',text)
        text=re.sub(r'(https?://)[^/\s:@]+:[^/\s@]+@',r'\1[REDACTED]@',text)
    return text


def tail_file(name,count):
    path=Path(name)
    # Resolve before containment check: /var/log/symlink -> /etc/shadow is refused.
    resolved=path.resolve(strict=True)
    if Path('/var/log') not in resolved.parents or not resolved.is_file():raise ValueError('Choose a regular file within /var/log')
    fd=os.open(resolved,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd);raise ValueError('Not a regular log file')
    with os.fdopen(fd,'rb') as stream:
        stream.seek(0,2);size=stream.tell();start=max(0,size-MAX_BYTES);stream.seek(start);data=stream.read(MAX_BYTES)
    if start and b'\n' in data:data=data.split(b'\n',1)[1]
    return b'\n'.join(data.splitlines()[-count:]).decode('utf-8','replace')


def collect(category,period='today',count=500,detail=''):
    if category not in {x[0] for x in CATEGORIES}:raise ValueError('Invalid log category')
    if period not in PERIODS or count not in (100,200,500,1000,5000):raise ValueError('Invalid period / line limit')
    base=['journalctl','--no-pager','--no-hostname','--output=short-iso','-n',str(count)]+PERIODS[period]
    commands=[];files=list(FILES.get(category,[]))
    if category=='system':commands=[base]
    elif category=='auth':commands=[base+['_COMM=sshd','+','SYSLOG_IDENTIFIER=sshd','+','_COMM=sudo','+','SYSLOG_IDENTIFIER=sudo']]
    elif category=='kernel':commands=[base+['-k']]
    elif category=='firewall':commands=[base+['-k','--grep','UFW|IN=.*OUT=|nftables|iptables']]
    elif category=='service':
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9@_.:-]*\.(?:service|socket|timer)',detail):raise ValueError('Enter a valid systemd service/socket/timer name')
        commands=[base+['-u',detail]]
    elif category=='container':
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',detail):raise ValueError('Invalid container name/ID')
        since={'boot':'24h','hour':'1h','today':'24h','day':'24h','week':'168h'}[period]
        commands=[['docker','logs','--timestamps','--tail',str(count),'--since',since,detail]]
    elif category=='file':files=[detail]
    elif category in UNITS:
        args=[]
        for unit in UNITS[category]:args+=['-u',unit]
        commands=[base+args]
    chunks=[]
    for command in commands:
        code,out,err=system.command(command,timeout=20)
        if code:chunks.append('Source unavailable: '+command[0]+' (exit '+str(code)+')')
        elif command[0]=='docker':chunks.append(out+'\n'+err) # docker sends container stderr to its own stderr.
        else:chunks.append(out or 'No matching events.')
    for name in files:
        try:chunks.append('FILE '+name+' (last '+str(count)+' lines; no time filter)\n'+tail_file(name,count))
        except (OSError,ValueError) as error:chunks.append('File unavailable: '+name+' ('+type(error).__name__+')')
    label=next(x[1] for x in CATEGORIES if x[0]==category)
    now=datetime.datetime.now().astimezone().isoformat(timespec='seconds')
    text=clean('\n\n'.join(chunks))
    limited=len(text.encode())>MAX_BYTES
    text=text.encode()[-MAX_BYTES:].decode('utf-8','replace')
    header='Aegis logs | '+socket.gethostname()+' | '+label+'\nCollected: '+now+' | Period: '+period+' | Max lines per source: '+str(count)+'\nSensitive-value masking: best effort; review before sharing.\n'
    if category=='container':header+='Container time window uses relative hours (today/boot = last 24h).\n'
    if limited:header+='Content truncated to the final 2 MiB.\n'
    return {'category':category,'label':label,'period':period,'count':count,'detail':detail,'text':header+'\n'+text+'\n',
            'filename':'aegis-'+category+'-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.log'}


def colorize(text):
    if not shutil.which('ccze'):return text
    # -A is raw ANSI (Latin A); disable DNS/service lookups for responsive viewing.
    try:
        result=subprocess.run(['ccze','-A','-o','nolookups'],input=text,text=True,capture_output=True,timeout=15)
        return result.stdout if result.returncode==0 else text
    except (OSError,subprocess.TimeoutExpired):return text


def view(snapshot):
    text=colorize(snapshot['text'])
    if os.isatty(1) and shutil.which('less'):
        subprocess.run(['less','-R','-S','--'],input=text,text=True,
                       env={**os.environ,'LESSSECURE':'1','LESSHISTFILE':'/dev/null','LESS':''})
    else:print(text)


def export_plan(snapshot,path,user):
    account=pwd.getpwnam(user);target=Path(account.pw_dir)/path[2:] if path.startswith('~/') else Path(path).expanduser()
    if not target.is_absolute():raise ValueError('Use an absolute export path')
    resolved=target.resolve()
    home=Path(account.pw_dir).resolve();exports=(actions.STATE/'exports').resolve()
    if not any(base in resolved.parents for base in (home,exports)):raise ValueError('Export into the selected user home or Aegis exports directory')
    if target.is_symlink():raise ValueError('Refusing symlink export destination')
    plan=actions.Plan('Export log snapshot: '+snapshot['label'],writes={str(target):snapshot['text']},modes={str(target):0o600},
        details=['Plain UTF-8 snapshot (no ANSI codes). Existing destination is backed up.',
                 'Masking is best effort; inspect before sharing.'])
    if home in resolved.parents:plan.commands=[['chown','--',str(account.pw_uid)+':'+str(account.pw_gid),str(target)]]
    return plan


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def telegram_destination():
    config=alerts.config()
    token=(alerts.CONF/'telegram.token').read_text().strip()
    if not re.fullmatch(r'\d{5,16}:[A-Za-z0-9_-]{20,}',token):raise ValueError('Telegram token is missing/invalid; configure Linux Telegram Alerts first')
    if not config.get('chat_id'):raise ValueError('Telegram destination is missing')
    return config,token


def multipart(snapshot,config):
    boundary='Aegis'+uuid.uuid4().hex
    fields={'chat_id':str(config['chat_id']),'caption':'📜 '+socket.gethostname()+' | '+snapshot['label']}
    if config.get('thread_id'):fields['message_thread_id']=str(config['thread_id'])
    body=bytearray()
    for key,value in fields.items():
        body.extend(('--'+boundary+'\r\nContent-Disposition: form-data; name="'+key+'"\r\n\r\n'+value+'\r\n').encode())
    filename=snapshot['filename']
    if not re.fullmatch(r'aegis-[a-z]+-\d{8}-\d{6}\.log',filename):raise ValueError('Invalid attachment name')
    body.extend(('--'+boundary+'\r\nContent-Disposition: form-data; name="document"; filename="'+filename+'"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n').encode())
    body.extend(snapshot['text'].encode());body.extend(('\r\n--'+boundary+'--\r\n').encode())
    return boundary,bytes(body)


def send(snapshot,config,token):
    boundary,body=multipart(snapshot,config)
    req=urllib.request.Request('https://api.telegram.org/bot'+token+'/sendDocument',data=body,
        headers={'Content-Type':'multipart/form-data; boundary='+boundary})
    try:
        with urllib.request.build_opener(NoRedirect()).open(req,timeout=25) as response:
            result=json.loads(response.read(65536))
    except urllib.error.HTTPError as error:raise RuntimeError('Telegram upload rejected (HTTP '+str(error.code)+'). Nothing is retried automatically.') from None
    except (OSError,ValueError,urllib.error.URLError):raise RuntimeError('Telegram delivery is unconfirmed. Check the destination before retrying; no automatic retry is performed.') from None
    if not result.get('ok'):raise RuntimeError('Telegram API rejected the attachment (code '+str(result.get('error_code',0))+').')
    actions.event('telegram-log-sent',hashlib.sha256(snapshot['text'].encode()).hexdigest()[:16],snapshot['label'])
    return result.get('result',{}).get('message_id')


def menu(language,user):
    from .ui import UI
    ui=UI(language);period='today';count=500
    while True:
        installed=catalog.app_version('ccze')
        choice=ui.choose('Logs',CATEGORIES+[
            ('settings','Time window / line limit','Current: '+period+' | '+str(count)+' lines per source.'),
            ('ccze','ccze'+(' [Installed]' if installed else ' — Install colorizer'),'Color with ccze -A; plain-text fallback when absent.')])
        if choice is None:return
        if choice=='__refresh__':continue
        try:
            if choice=='ccze':
                if installed:ui.view('ccze','Installed: '+installed+'\nLog views automatically use ccze -A -o nolookups. Export/Telegram remain plain text.')
                else:actions.apply(catalog.app_plan('ccze',user))
                continue
            if choice=='settings':
                selected=ui.choose('Journal time window',[(key,key,'Select '+key) for key in PERIODS])
                if selected in PERIODS:period=selected
                count=int(ui.prompt('Lines per source: 100/200/500/1000/5000','Γραμμές ανά πηγή: 100/200/500/1000/5000',str(count)))
                if count not in (100,200,500,1000,5000):count=500
                continue
            detail=''
            if choice=='service':detail=ui.prompt('Systemd unit','Μονάδα systemd','ssh.service')
            if choice=='file':detail=ui.prompt('File within /var/log','Αρχείο μέσα στο /var/log','/var/log/syslog')
            if choice=='container':
                _,text,_=system.command(['docker','ps','-a','--format','{{.Names}}'])
                selected=ui.choose('Container logs',[(name,name,'Read recent container stdout/stderr') for name in text.splitlines() if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',name)])
                if not selected or selected=='__refresh__':continue
                detail=selected
            snapshot=collect(choice,period,count,detail)
            while True:
                op=ui.choose(snapshot['label'],[
                    ('view','View logs (ccze -A)','q exits pager; arrows/Page Up/Down scroll. Snapshot is masked with best-effort rules.'),
                    ('export','Export snapshot','Plain .log file. Exported file is private; overwritten files retain undo backup.'),
                    ('send','Send snapshot to Telegram','Preview the exact snapshot, then explicitly confirm the configured chat/topic. Sends a .log attachment.'),
                    ('refresh','Refresh snapshot','Read new events using the selected category/time window.')])
                if op is None:break
                if op=='view':view(snapshot)
                elif op=='refresh':snapshot=collect(choice,period,count,detail)
                elif op=='export':
                    default=str(Path(pwd.getpwnam(user).pw_dir)/snapshot['filename'])
                    path=ui.prompt('Export path','Διαδρομή εξαγωγής',default)
                    if Path(path).exists() and not console.confirm('Overwrite the existing export?'):continue
                    if actions.apply(export_plan(snapshot,path,user)):print('Exported: '+path);console.pause()
                elif op=='send':
                    config,token=telegram_destination()
                    view(snapshot)
                    print('Destination: '+str(config['chat_id'])+' | Topic: '+str(config.get('thread_id') or 0))
                    print('The exact previewed snapshot will be sent. Masking cannot detect every secret. A sent attachment is not undone by Aegis.')
                    if console.confirm('Send this log attachment to the displayed Telegram destination?',default=False):
                        ident=send(snapshot,config,token);print('Telegram attachment delivered. Message ID: '+str(ident));console.pause()
        except (console.Cancelled,KeyboardInterrupt):continue
        except Exception as error:ui.error(str(error))
