#!/usr/bin/env python3
"""Scoped GeoIP SSH runtime; stdlib only / Αυτόνομο runtime, δύο sets, πέντε κανόνες."""
import argparse
import concurrent.futures
import contextlib
import datetime
import fcntl
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

TABLE='aegis_geoip_ssh'
MARKER='Managed by Aegis GeoIP SSH'
ROOT=Path('/var/lib/aegis-linux-hardener/geoip')
CONFIG=Path('/etc/aegis-linux-hardener/geoip-ssh.json')
CACHE=ROOT/'lists.json'
RULES=Path('/etc/aegis-linux-hardener/geoip-ssh.nft')
UNIT='aegis-geoip-ssh.service'
UPDATE_UNIT='aegis-geoip-update.service'
UPDATE_TIMER='aegis-geoip-update.timer'
RUNTIME=ROOT/'engine.py'
RIRS={
 'RIPE NCC':'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest',
 'ARIN':'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest',
 'APNIC':'https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest',
 'AFRINIC':'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest',
 'LACNIC':'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest'}
GR_API='https://stat.ripe.net/data/country-resource-list/data.json?resource=GR'
GR_EXTRA='https://www.nirsoft.net/countryip/gr.html'
MAX_PREFIXES=1500000


def command(args,input=None,timeout=90):
    result=subprocess.run(args,input=input,text=True,capture_output=True,timeout=timeout,env={**os.environ,'LC_ALL':'C'})
    if result.returncode:raise RuntimeError(args[0]+': '+(result.stderr or result.stdout).strip()[:1000])
    return result.stdout


def read_json(path,default=None):
    if path.is_symlink():raise ValueError('Refusing symlink: '+str(path))
    if not path.exists():return default
    if not path.is_file() or path.stat().st_size>128*1024*1024:raise ValueError('Invalid/oversized state file')
    return json.loads(path.read_text())


def write_json(path,value):
    write_text(path,json.dumps(value))


def write_text(path,value):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,name=tempfile.mkstemp(dir=path.parent,prefix='.geoip-')
    try:
        with os.fdopen(fd,'w') as handle:
            os.fchmod(handle.fileno(),0o600);handle.write(value);handle.flush();os.fsync(handle.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)


def safe_network(value,family=None,trusted=False):
    if not isinstance(value,str) or '%' in value:raise ValueError('Invalid network value')
    network=ipaddress.ip_network(value,strict=True)
    if family and network.version!=family:raise ValueError('Wrong address family')
    if not network.prefixlen:raise ValueError('Default routes are not accepted as IP lists')
    if not trusted and (not network.is_global or network.is_multicast or network.is_reserved or network.prefixlen<(8 if network.version==4 else 12)):
        raise ValueError('Non-public or overly broad country network: '+value)
    return network


def collapse(values,family,trusted=False):
    if len(values)>MAX_PREFIXES:raise ValueError('Too many prefixes')
    networks=[safe_network(v,family,trusted) for v in values]
    result=[]
    for network in ipaddress.collapse_addresses(networks):
        # Cache normalization must remain valid on its next read. Adjacent /8s or
        # /12s can merge beyond the accepted feed boundary; retain that boundary.
        minimum=8 if family==4 else 12
        if not trusted and network.prefixlen<minimum:
            result.extend(str(n) for n in network.subnets(new_prefix=minimum))
        else:
            result.append(str(network))
    return result


def config(value):
    if not isinstance(value,dict) or value.get('schema')!=1:raise ValueError('Invalid GeoIP configuration')
    result=dict(value)
    for key,pattern,maximum in [('countries',r'[A-Z]{2}',250),('continents',r'(?:eu|as|af|na|sa|oc|an)',7),('expanded',r'[A-Z]{2}',250)]:
        items=result.get(key,[])
        if not isinstance(items,list) or len(items)>maximum or any(not isinstance(v,str) or not re.fullmatch(pattern,v) for v in items):raise ValueError('Invalid '+key)
        result[key]=sorted(set(items))
    ports=result.get('ports')
    if not isinstance(ports,list) or not ports or len(ports)>32 or any(type(p)!=int or not 1<=p<=65535 for p in ports):raise ValueError('Invalid SSH ports')
    result['ports']=sorted(set(ports))
    if type(result.get('enabled'))!=bool:raise ValueError('Invalid enabled flag')
    if result.get('update_schedule','') not in ('','hourly','daily','weekly'):raise ValueError('Invalid update schedule')
    trusted=result.get('trusted',[])
    if not isinstance(trusted,list) or len(trusted)>100:raise ValueError('At most 100 trusted CIDRs')
    result['trusted']=[str(safe_network(v,trusted=True)) for v in trusted]
    if result.get('source') not in ('rir','zone-feed'):raise ValueError('Unknown list source')
    if result['source']=='zone-feed':result['base_url']=base_url(result.get('base_url',''))
    if result['enabled'] and not result['expanded']:raise ValueError('Select at least one country or continent')
    return result


def base_url(value):
    parsed=urllib.parse.urlsplit(value)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Use an HTTP(S) feed base URL without credentials, query or fragment')
    try:parsed.port
    except ValueError:raise ValueError('Invalid feed port') from None
    return value.rstrip('/')


def download(url,limit=64*1024*1024):
    request=urllib.request.Request(url,headers={'User-Agent':'Aegis-GeoIP/0.9.1 (+https://karanik.gr)'})
    with urllib.request.urlopen(request,timeout=35) as response:
        target=urllib.parse.urlsplit(response.geturl());original=urllib.parse.urlsplit(url)
        if target.hostname!=original.hostname or target.scheme!=original.scheme:raise ValueError('Cross-host/protocol feed redirect refused')
        data=response.read(limit+1)
    if len(data)>limit:raise ValueError('Feed exceeds download limit')
    return data


def parse_rir(raw,known):
    """RIR delegated allocations, including non-power-of-two IPv4 ranges."""
    result={};count=0
    for line in raw.decode('ascii').splitlines():
        fields=line.split('|')
        if len(fields)<7 or fields[2] not in ('ipv4','ipv6') or fields[6] not in ('allocated','assigned') or fields[1] not in known:continue
        country=fields[1];family=4 if fields[2]=='ipv4' else 6
        if family==4:
            start=ipaddress.IPv4Address(fields[3]);amount=int(fields[4])
            if amount<=0 or int(start)+amount>2**32:raise ValueError('Invalid delegated IPv4 range')
            networks=list(ipaddress.summarize_address_range(start,ipaddress.IPv4Address(int(start)+amount-1)))
        else:networks=[ipaddress.IPv6Network(fields[3]+'/'+fields[4],strict=True)]
        for network in networks:
            try:safe_network(str(network),family)
            except ValueError:continue
            result.setdefault(country,{'4':[],'6':[]})[str(family)].append(str(network));count+=1
        if count>MAX_PREFIXES:raise ValueError('RIR feed exceeds prefix limit')
    if not count:raise ValueError('No valid allocated networks in RIR feed')
    return result


def parse_gr_api(raw):
    data=json.loads(raw)['data']['resources'];result={'4':[],'6':[]}
    for family,key in [(4,'ipv4'),(6,'ipv6')]:
        for value in data.get(key,[]):
            if '-' in value:
                left,right=value.split('-',1);networks=ipaddress.summarize_address_range(ipaddress.ip_address(left.strip()),ipaddress.ip_address(right.strip()))
            else:networks=[ipaddress.ip_network(value,strict=False)]
            for network in networks:result[str(family)].append(str(safe_network(str(network),family)))
    if not result['4']:raise ValueError('Empty Greece RIPEstat data')
    return result


def parse_nirsoft(raw):
    text=html.unescape(re.sub(r'<[^>]+>',' ',raw.decode('utf-8',errors='replace')))
    ips=re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',text);networks=[]
    for i in range(0,len(ips)-1,2):
        start,end=ipaddress.IPv4Address(ips[i]),ipaddress.IPv4Address(ips[i+1])
        if int(end)<int(start):continue
        for network in ipaddress.summarize_address_range(start,end):
            try:networks.append(str(safe_network(str(network),4)))
            except ValueError:continue
    if len(networks)<10:raise ValueError('Too few validated NirSoft networks')
    return networks


def collect_rir(known):
    countries={code:{'4':[],'6':[]} for code in known};sources=[];warnings=[]
    def task(item):
        name,url=item;raw=download(url);return name,url,raw,parse_rir(raw,known)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        for name,url,raw,parsed in pool.map(task,RIRS.items()):
            for code,rows in parsed.items():
                for family in ('4','6'):countries[code][family]+=rows[family]
            sources.append({'name':name,'url':url,'sha256':hashlib.sha256(raw).hexdigest()})
    # Greece follows the existing feed's RIR + RIPEstat enrichment. NirSoft is supplementary.
    raw=download(GR_API,8*1024*1024);gr=parse_gr_api(raw)
    for family in ('4','6'):countries['GR'][family]+=gr[family]
    sources.append({'name':'RIPEstat GR','url':GR_API,'sha256':hashlib.sha256(raw).hexdigest()})
    try:
        raw=download(GR_EXTRA,8*1024*1024);countries['GR']['4']+=parse_nirsoft(raw)
        sources.append({'name':'NirSoft GR','url':GR_EXTRA,'sha256':hashlib.sha256(raw).hexdigest()})
    except Exception as error:warnings.append('Optional NirSoft GR enrichment unavailable: '+str(error)[:200])
    for rows in countries.values():
        for family in ('4','6'):rows[family]=collapse(rows[family],int(family))
    return {'schema':1,'updated':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'rir','countries':countries,'sources':sources,'warnings':warnings}


def collect_feed(settings):
    base=base_url(settings['base_url']);countries={};sources=[]
    for code in settings['expanded']:
        rows={}
        for family,suffix in [('4',''),('6','-v6')]:
            url=base+'/feeds/'+code.lower()+suffix+'.zone';raw=download(url,16*1024*1024)
            values=[line.strip() for line in raw.decode('ascii').splitlines() if line.strip() and not line.lstrip().startswith('#')]
            rows[family]=collapse(values,int(family));sources.append({'url':url,'sha256':hashlib.sha256(raw).hexdigest()})
        countries[code]=rows
    return {'schema':1,'updated':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':'zone-feed','base_url':base,'countries':countries,'sources':sources,'warnings':[]}


def selected_networks(settings,cache):
    settings=config(settings)
    if not isinstance(cache,dict) or cache.get('schema')!=1 or cache.get('source')!=settings['source']:raise ValueError('Refresh lists for the selected source first')
    if settings['source']=='zone-feed' and cache.get('base_url')!=settings.get('base_url'):raise ValueError('Refresh the configured feed source first')
    result={'4':[],'6':[]}
    for code in settings['expanded']:
        rows=cache.get('countries',{}).get(code)
        if not isinstance(rows,dict):raise ValueError('Missing country data for '+code+'; refresh lists')
        for family in ('4','6'):
            values=rows.get(family)
            if not isinstance(values,list):raise ValueError('Invalid cached family')
            result[family]+=values
    for family in ('4','6'):result[family]=collapse(result[family],int(family))
    if not result['4'] and not result['6']:raise ValueError('No allocated prefixes for this selection; choose other countries or refresh lists')
    return result


def render(settings,cache):
    settings=config(settings);networks=selected_networks(settings,cache)
    for value in settings['trusted']:
        network=safe_network(value,trusted=True);networks[str(network.version)].append(str(network))
    for family in ('4','6'):networks[family]=collapse(networks[family],int(family),trusted=True)
    lines=['table inet '+TABLE+' {','    comment "'+MARKER+'";']
    for family,kind in [('4','ipv4_addr'),('6','ipv6_addr')]:
        lines+=['    set allowed_v'+family+' {','        type '+kind+'; flags interval; auto-merge;']
        if networks[family]:lines+=['        elements = { '+', '.join(networks[family])+' };']
        lines+=['    }']
    ports=', '.join(map(str,settings['ports']))
    lines+=['    chain ssh_input {','        type filter hook input priority -5; policy accept;',
            '        ct state established,related return','        iifname "lo" return',
            '        tcp dport { '+ports+' } ip saddr @allowed_v4 counter return',
            '        tcp dport { '+ports+' } ip6 saddr @allowed_v6 counter return',
            '        tcp dport { '+ports+' } counter drop','    }','}']
    return '\n'.join(lines)+'\n',networks


def live_table():
    process=subprocess.run(['nft','-j','list','table','inet',TABLE],text=True,capture_output=True)
    if process.returncode:
        if 'No such file or directory' in process.stderr:return None
        raise RuntimeError('Cannot inspect GeoIP nftables table: '+process.stderr[:500])
    data=json.loads(process.stdout)
    table=next((row['table'] for row in data.get('nftables',[]) if 'table' in row),{})
    text=command(['nft','-s','list','table','inet',TABLE])
    # Some nft versions omit table comments from JSON but retain them in text.
    if table.get('comment')!=MARKER and not re.search(r'^\s*comment\s+"'+re.escape(MARKER)+r'"\s*;?\s*$',text,re.M):
        raise ValueError('Unmanaged table with the same name; refusing to replace it')
    return text


def replace_table(text):
    before=live_table()
    batch=('delete table inet '+TABLE+'\n' if before is not None else '')+(text or '')
    if not batch:return
    command(['nft','-c','-f','-'],batch);command(['nft','-f','-'],batch)


def validate_table(text):
    before=live_table()
    batch=('delete table inet '+TABLE+'\n' if before is not None else '')+(text or '')
    if batch:command(['nft','-c','-f','-'],batch)


def apply_current():
    settings=config(read_json(CONFIG))
    if not settings['enabled']:replace_table(None);return
    text,_=render(settings,read_json(CACHE));replace_table(text)


def unit_state():
    def ok(args):return subprocess.run(args,capture_output=True).returncode==0
    return {'enabled':ok(['systemctl','is-enabled','--quiet',UNIT]),'active':ok(['systemctl','is-active','--quiet',UNIT])}


def snapshot_path(token):
    if not re.fullmatch(r'[a-f0-9]{32}',token):raise ValueError('Invalid GeoIP snapshot ID')
    return ROOT/'snapshots'/(token+'.json')


def capture(token):
    path=snapshot_path(token)
    if path.exists():raise ValueError('GeoIP snapshot already exists')
    write_json(path,{'schema':1,'table':live_table(),'unit':unit_state()})


def restore(token):
    path=snapshot_path(token);value=read_json(path)
    if not value:return # No runtime mutation can precede capture in the plan.
    if value.get('schema')!=1:raise ValueError('Invalid runtime snapshot')
    # Stop first. The unit intentionally has no ExecStop firewall command.
    subprocess.run(['systemctl','stop',UNIT],capture_output=True)
    command(['systemctl','daemon-reload'])
    old=value['unit'];result=subprocess.run(['systemctl','enable' if old['enabled'] else 'disable',UNIT],capture_output=True,text=True)
    if result.returncode and old['enabled']:raise RuntimeError('Cannot restore GeoIP boot state')
    if old['active']:command(['systemctl','start',UNIT])
    with runtime_lock():replace_table(value['table']) # Exact prior table, after service load.


@contextlib.contextmanager
def runtime_lock():
    ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
    with (ROOT/'engine.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);yield


def run(op,token=''):
    if os.geteuid()!=0:raise RuntimeError('Root required')
    # Service start in restore invokes apply in another process; never hold its lock here.
    if op=='restore':restore(token);return
    if op=='schedule-stop':stop_schedule();return
    if op=='schedule-restore':restore_schedule(json.loads(token));return
    if op=='update':
        def terminate(signum,frame):raise RuntimeError('Scheduled update interrupted; retaining previous data')
        signal.signal(signal.SIGTERM,terminate)
        scheduled_update();return
    with runtime_lock():
        if op=='apply':apply_current()
        elif op=='check':
            settings=config(read_json(CONFIG));text,_=render(settings,read_json(CACHE));validate_table(text)
        elif op=='disable':replace_table(None)
        elif op=='capture':capture(token)
        else:raise ValueError('Unknown GeoIP runtime operation')


def stop_schedule():
    for unit in (UPDATE_TIMER,UPDATE_UNIT):
        result=subprocess.run(['systemctl','stop',unit],capture_output=True,text=True,env={**os.environ,'LC_ALL':'C'})
        if result.returncode and not any(message in result.stderr for message in ('not loaded','not found','does not exist')):
            raise RuntimeError('Cannot stop '+unit+': '+result.stderr[:300])


def restore_schedule(state):
    command(['systemctl','daemon-reload'])
    result=subprocess.run(['systemctl','enable' if state['enabled'] else 'disable',UPDATE_TIMER],capture_output=True,text=True)
    if result.returncode and state['enabled']:raise RuntimeError('Cannot restore update timer enable state')
    if state['active']:command(['systemctl','start',UPDATE_TIMER])


def scheduled_update():
    """Persistent reviewed schedule; last-good data survive failed publication.
    Προγραμματισμένη ενημέρωση με snapshot και επαναφορά μόνο αν αποτύχει.
    """
    ROOT.parent.mkdir(parents=True,exist_ok=True)
    with (ROOT.parent/'change.lock').open('a') as change:
        fcntl.flock(change,fcntl.LOCK_EX)
        with runtime_lock():
            settings=config(read_json(CONFIG));old=read_json(CACHE)
            if not settings.get('update_schedule'):raise ValueError('Scheduled updates are disabled')
            for path in (ROOT.parent/'backups').glob('*/manifest.json'):
                if read_json(path,{}).get('status') in ('armed','applying','awaiting-activation','activating','awaiting-confirmation'):
                    raise ValueError('Another change awaits confirmation; keeping previous lists')
            if settings['source']=='rir':
                if not old or len(old.get('countries',{}))!=250:raise ValueError('Download the full country cache before scheduling updates')
                new=collect_rir(old['countries'])
            else:new=collect_feed(settings)
            selected_networks(settings,new)
            if old:
                before=selected_networks(settings,old);after=selected_networks(settings,new)
                for family in ('4','6'):
                    count=lambda values:sum(ipaddress.ip_network(n).num_addresses for n in values)
                    if count(before[family]) and count(after[family])<count(before[family])*0.5:
                        raise ValueError('Address coverage fell by more than 50%; review a manual refresh. Previous lists retained.')
            text,_=render(settings,new) if settings['enabled'] else ('',{})
            if settings['enabled']:validate_table(text)
            prior=live_table() if settings['enabled'] else None
            stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
            folder=ROOT/'scheduled-backups';snapshot=folder/(stamp+'.json')
            previous_rules=RULES.read_text() if RULES.exists() else None
            write_json(snapshot,{'cache':old,'rules':previous_rules,'table':prior})
            changed=False
            try:
                if settings['enabled']:replace_table(text);changed=True
                write_json(CACHE,new)
                if settings['enabled']:write_text(RULES,text)
            except BaseException:
                if old is not None:write_json(CACHE,old)
                else:CACHE.unlink(missing_ok=True)
                if previous_rules is not None:write_text(RULES,previous_rules)
                else:RULES.unlink(missing_ok=True)
                if changed:replace_table(prior)
                raise
            for path in sorted(folder.glob('*.json'))[:-7]:path.unlink()
            print('GeoIP lists updated: '+new['updated']+'; policy '+('active' if settings['enabled'] else 'disabled')+'; backup '+str(snapshot),flush=True)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('op',choices=['apply','check','capture','restore','disable','update','schedule-stop','schedule-restore']);parser.add_argument('snapshot',nargs='?')
    args=parser.parse_args()
    run(args.op,args.snapshot or '')


if __name__=='__main__':main()
