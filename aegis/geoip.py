"""GeoIP country lists and explicitly reviewed SSH policy / Λίστες και πολιτική SSH."""
import dataclasses
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import sys
import uuid
from . import actions,catalog,console,system
from . import geoip_engine as engine
from .geodata import COUNTRIES,CONTINENTS
from .selection import checklist

UNIT_PATH=Path('/etc/systemd/system')/engine.UNIT


def defaults():
    return {'schema':1,'enabled':False,'source':'rir','base_url':'','countries':['GR'],'continents':[],
            'expanded':['GR'],'trusted':[],'ports':[22]}


def settings():
    value=engine.config(engine.read_json(engine.CONFIG,defaults()))
    expanded=expand(value['countries'],value['continents'])
    if value['expanded']!=expanded:raise ValueError('Country/continent expansion does not match saved policy')
    return value


def expand(countries,continents):
    if set(countries)-set(COUNTRIES) or set(continents)-set(CONTINENTS):raise ValueError('Unknown country or continent')
    result=set(countries)
    for code in continents:result.update(CONTINENTS[code]['countries'])
    return sorted(result)


def ports_detected():
    command=shutil.which('sshd') or '/usr/sbin/sshd'
    code,text,_=system.command([command,'-T']);ports={int(m) for m in re.findall(r'^port (\d+)$',text,re.M)} if code==0 else set()
    _,sockets,_=system.command(['systemctl','show','ssh.socket','-p','Listen','--value'])
    ports.update(int(m) for m in re.findall(r':(\d+)\s+\(Stream\)',sockets))
    connection=system.ssh_connection().split()
    if len(connection)==4 and connection[3].isdigit():ports.add(int(connection[3]))
    return sorted(p for p in ports if 1<=p<=65535)


def parse_ports(value):
    fields=re.split(r'[ ,]+',value.strip())
    if not fields or any(not re.fullmatch(r'\d{1,5}',v) or not 1<=int(v)<=65535 for v in fields):raise ValueError('Use TCP port numbers 1–65535, separated by spaces or commas')
    return sorted(set(map(int,fields)))


def fingerprint(path):
    if path.is_symlink():raise ValueError('Managed GeoIP path is a symlink: '+str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def coverage(networks):
    return {family:sum(ipaddress.ip_network(n).num_addresses for n in rows) for family,rows in networks.items()}


def shrink_warnings(old,new,policy):
    if not old:return []
    before=coverage(engine.selected_networks(policy,old));after=coverage(engine.selected_networks(policy,new))
    return [str(family)+': allocated address coverage fell by more than 50%' for family in ('4','6') if before[family] and after[family]<before[family]*0.5]


def policy_plan(value,cache=None):
    value=engine.config(value)
    if value['expanded']!=expand(value['countries'],value['continents']):raise ValueError('Invalid selected-country expansion')
    old_files={p:fingerprint(p) for p in (engine.CONFIG,engine.CACHE,engine.RULES,engine.RUNTIME,UNIT_PATH)}
    enabled=value['enabled'];data=cache if cache is not None else engine.read_json(engine.CACHE)
    text='';networks={'4':[],'6':[]}
    if enabled:
        detected=set(ports_detected())
        if detected-set(value['ports']):raise ValueError('Include all detected SSH ports: '+', '.join(map(str,sorted(detected))))
        if not detected:raise ValueError('No SSH listener configuration detected; verify sshd/socket setup first')
        if not shutil.which('nft'):raise ValueError('Install the nftables command first from this menu')
        text,networks=engine.render(value,data)
        empty=[code for code in value['expanded'] if not any(data['countries'][code].get(f) for f in ('4','6'))]
        connection=system.ssh_connection().split()
        if connection:
            address=ipaddress.ip_address(connection[0]);family=str(address.version)
            if not any(address in ipaddress.ip_network(n) for n in networks[family]):raise ValueError('Current SSH client would be excluded. Add its IP/VPN network to trusted exceptions.')
    live=engine.live_table();live_hash=hashlib.sha256((live or '').encode()).hexdigest()
    token=uuid.uuid4().hex;entry=str(actions.ENTRY)
    before=[[sys.executable,entry,'--geoip-runtime','capture','--geoip-snapshot',token]]
    writes={str(engine.CONFIG):json.dumps(value,indent=2)+'\n'}
    summaries={str(engine.CONFIG):'Validated selections, SSH ports and trusted exceptions shown in the plan summary.'}
    if cache is not None:
        writes[str(engine.CACHE)]=json.dumps(data,separators=(',',':'))+'\n'
        summaries[str(engine.CACHE)]='Validated country CIDR cache; '+str(len(data['countries']))+' countries; updated '+data['updated']
    if enabled:
        unit='''[Unit]
Description=Aegis GeoIP SSH allowlist
After=local-fs.target nftables.service ufw.service firewalld.service
Before=ssh.service sshd.service ssh.socket

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 '''+str(engine.RUNTIME)+''' apply
ExecReload=/usr/bin/python3 '''+str(engine.RUNTIME)+''' apply
TimeoutStartSec=90

[Install]
WantedBy=multi-user.target
'''
        writes.update({str(engine.RULES):text,str(engine.RUNTIME):Path(engine.__file__).read_text(),str(UNIT_PATH):unit})
        summaries[str(engine.RUNTIME)]='Standalone trusted loader; SHA256 '+hashlib.sha256(writes[str(engine.RUNTIME)].encode()).hexdigest()
        summaries[str(engine.RULES)]='inet '+engine.TABLE+': 2 interval sets ('+str(len(networks['4']))+' IPv4 / '+str(len(networks['6']))+' IPv6 CIDRs), 5 fixed rules; no per-prefix rules.'
        commands=[['systemctl','daemon-reload'],['systemctl','enable',engine.UNIT],['systemctl','restart',engine.UNIT]]
        validate=[[sys.executable,entry,'--geoip-runtime','check']]
    else:
        commands=[['systemctl','disable','--now',engine.UNIT]] if UNIT_PATH.exists() else []
        commands.append([sys.executable,entry,'--geoip-runtime','disable']);validate=[]
    def guard():
        if any(fingerprint(path)!=digest for path,digest in old_files.items()):raise ValueError('GeoIP files changed; refresh the action')
        if hashlib.sha256((engine.live_table() or '').encode()).hexdigest()!=live_hash:raise ValueError('GeoIP table changed; refresh before applying')
        if enabled:engine.validate_table(text)
    return actions.Plan('GeoIP SSH: '+('enable/update policy' if enabled else 'disable policy'),writes=writes,write_summaries=summaries,
        modes={path:0o600 for path in writes},before=before,validate=validate,commands=commands,critical=True,persist_runner=True,guard=guard,
        rollback_commands=[['systemctl','daemon-reload'],[sys.executable,entry,'--geoip-runtime','restore','--geoip-snapshot',token]],
        details=['Countries: '+', '.join(value['countries']),'Continents: '+', '.join(value['continents']),
                 'Expanded country count: '+str(len(value['expanded'])),'TCP SSH ports: '+', '.join(map(str,value['ports'])),
                 'Trusted exceptions: '+(', '.join(value['trusted']) or '(none)'),
                 'Two nftables sets, five fixed input rules. Other firewall tables/rules remain intact.',
                 'Existing sessions and loopback are preserved. IPv4 and IPv6 are filtered; no empty IPv6 bypass.',
                 'An allowed country does not override another firewall drop or Fail2Ban ban.',
                 'IP allocation country is approximate. VPNs/proxies appear as their observed source address.',
                 'Boot persistence uses a private standalone runtime. Manual list updates require approval and SSH confirmation.']+
                (['Selected territories with no allocations: '+', '.join(empty)] if enabled and empty else []))


def cache_plan(cache):
    old=fingerprint(engine.CACHE)
    def guard():
        if fingerprint(engine.CACHE)!=old:raise ValueError('Country cache changed; refresh first')
    content=json.dumps(cache,separators=(',',':'))+'\n'
    return actions.Plan('Update GeoIP country lists',writes={str(engine.CACHE):content},modes={str(engine.CACHE):0o600},guard=guard,
        write_summaries={str(engine.CACHE):str(len(cache['countries']))+' countries; updated '+cache['updated']},
        details=['Cache update only: no enabled GeoIP SSH policy. Invalid/failed downloads keep the previous cache intact.',
                 'Sources: '+', '.join(s.get('name',s.get('url','')) for s in cache['sources'])]+cache.get('warnings',[]))


def refresh(ui,value):
    if not console.confirm('Download and validate IP lists from '+('RIR registries / RIPEstat' if value['source']=='rir' else value['base_url'])+'?'):return None
    print('Downloading country allocations; the current policy remains active until validation and approval.',flush=True)
    cache=engine.collect_rir(COUNTRIES) if value['source']=='rir' else engine.collect_feed(value)
    old=engine.read_json(engine.CACHE)
    if value['enabled']:
        warnings=shrink_warnings(old,cache,value)
        if warnings and not console.confirm('; '.join(warnings)+'. Publish this large list change?',default=False):return None
        plan=policy_plan(value,cache)
    else:plan=cache_plan(cache)
    actions.apply(plan,system.ssh_connection());console.pause();return cache


def status_text():
    value=settings();data=engine.read_json(engine.CACHE)
    lines=['GeoIP SSH: '+('configured enabled' if value['enabled'] else 'disabled'),
           'Source: '+value['source'],'Countries: '+', '.join(value['countries']),'Continents: '+', '.join(value['continents']),
           'Ports: '+', '.join(map(str,value['ports'])),'Trusted: '+(', '.join(value['trusted']) or '(none)'),
           'List timestamp: '+(data.get('updated','unknown') if data else 'not downloaded'),'','Two interval sets, five rules; country allocations are not exact physical geolocation.']
    uncovered=set(ports_detected())-set(value['ports'])
    if value['enabled'] and uncovered:lines+=['WARNING: detected SSH ports outside the policy: '+', '.join(map(str,sorted(uncovered)))]
    if shutil.which('nft'):
        try:lines+=['','Runtime table:','absent' if engine.live_table() is None else 'present / owned by Aegis']
        except Exception as error:lines+=['Runtime error: '+str(error)]
    else:lines+=['nftables command is missing; list downloads remain available.']
    return '\n'.join(lines)


@console.cancellable_menu
def menu(language,theme):
    from .ui import UI,table
    ui=UI(language,theme)
    while True:
        value=settings()
        choice=ui.choose('GeoIP SSH / Zone Feed',[
            ('status','Status / policy','Current source, selections, list age, exceptions and active table.'),
            ('configure','Select countries / continents','Space toggles checkboxes; search, paging and cancellation. All changes use timed rollback.'),
            ('update','Update IP lists now','Validate and publish a complete refresh. If active, update both sets atomically after approval.'),
            ('inventory','Country / continent lists','Counts per country; allocation-country data, IPv4 and IPv6.'),
            ('inspect','View country CIDRs','Inspect downloaded IPv4/IPv6 lists without applying rules.'),
            ('source','List source','Direct RIR collection or an existing compatible Karanik Zone Feed server.'),
            ('install','Install nftables command','Install tools without starting/enabling the distribution firewall service.'),
            ('disable','Disable GeoIP SSH policy','Remove only the Aegis GeoIP table; preserve Fail2Ban and other firewall rules.'),
            ('rules','Inspect runtime rules / counters','Read only: table sets, five rules and counters.'),
            ('logs','Service logs','Boot/runtime apply logs.')])
        if choice is None:return
        try:
            if choice=='configure' and not shutil.which('nft'):
                plan=catalog.package_plan(['nftables'],'Install required nftables command');plan.suppress_services=True
                plan.details+=['The distribution nftables service is not enabled or started.']
                if not actions.apply(plan,system.ssh_connection()) or not shutil.which('nft'):continue
            if choice=='status':ui.view('GeoIP SSH',status_text)
            elif choice=='update':refresh(ui,value)
            elif choice=='inventory':
                data=engine.read_json(engine.CACHE,{'countries':{}})
                rows=[(code,name,len(data['countries'].get(code,{}).get('4',[])),len(data['countries'].get(code,{}).get('6',[]))) for code,name in sorted(COUNTRIES.items(),key=lambda r:r[1])]
                groups=[(code,row['name'],len(row['countries']),sum(len(data['countries'].get(c,{}).get('4',[])) for c in row['countries']),sum(len(data['countries'].get(c,{}).get('6',[])) for c in row['countries'])) for code,row in CONTINENTS.items()]
                ui.view('Country / continent lists','Continent totals before cross-country merging:\n'+table(['Code','Continent','Countries','IPv4 CIDRs','IPv6 CIDRs'],groups)+'\n\n'+table(['Code','Country','IPv4 CIDRs','IPv6 CIDRs'],rows))
            elif choice=='inspect':
                data=engine.read_json(engine.CACHE,{'countries':{}})
                rows=[(code,name+' ('+code+')',str(len(values.get('4',[])))+' IPv4 / '+str(len(values.get('6',[])))+' IPv6 CIDRs') for code,name in sorted(COUNTRIES.items(),key=lambda r:r[1]) if (values:=data['countries'].get(code))]
                selected=ui.choose('Downloaded country lists',rows)
                if selected and selected!='__refresh__':
                    values=data['countries'][selected]
                    ui.view(COUNTRIES[selected]+' CIDRs','IPv4\n'+'\n'.join(values['4'])+'\n\nIPv6\n'+'\n'.join(values['6']))
            elif choice=='install':
                if shutil.which('nft'):ui.view('nftables','nft command is already installed.');continue
                plan=catalog.package_plan(['nftables'],'Install nftables command');plan.suppress_services=True
                plan.details+=['Does not enable nftables.service or load its default ruleset.']
                actions.apply(plan,system.ssh_connection());console.pause()
            elif choice=='source':
                source=ui.choose('GeoIP list source',[('rir','RIR registries + Greece enrichment','Collect all country allocations locally; no HTTP listener is installed.'),('zone-feed','Karanik Zone Feed server','Use /feeds/cc.zone and /feeds/cc-v6.zone from a trusted server.')])
                if source not in ('rir','zone-feed'):continue
                if value['enabled']:raise ValueError('Disable GeoIP policy before changing its source, then download and re-enable.')
                new={**value,'source':source}
                if source=='zone-feed':new['base_url']=engine.base_url(ui.prompt('Feed base URL (trusted HTTP/HTTPS server)','Βασικό URL έμπιστου feed server',value.get('base_url','')))
                actions.apply(actions.Plan('GeoIP list source',writes={str(engine.CONFIG):json.dumps(engine.config(new),indent=2)+'\n'},modes={str(engine.CONFIG):0o600}),system.ssh_connection());console.pause()
            elif choice=='configure':
                continents=checklist(ui,'Allowed continents',[(code,row['name'],', '.join(row['countries'])) for code,row in CONTINENTS.items()],value['continents'])
                inherited=expand([],continents)
                countries=checklist(ui,'Allowed countries',[(code,name+' ('+code+')','Included by continent where checked automatically.') for code,name in sorted(COUNTRIES.items(),key=lambda r:r[1])],value['countries'],inherited)
                expanded=expand(countries,continents)
                if not expanded:raise ValueError('Select at least one country or continent. Use Disable to remove the policy.')
                ports=parse_ports(ui.prompt('SSH TCP ports (all detected ports are required)','TCP θύρες SSH (όλες οι ανιχνευμένες)',', '.join(map(str,ports_detected() or value['ports']))))
                connection=system.ssh_connection().split();trusted=list(value['trusted'])
                if connection:
                    address=ipaddress.ip_address(connection[0]);host=str(ipaddress.ip_network(str(address)+('/32' if address.version==4 else '/128')))
                    if host not in trusted:trusted.append(host)
                raw=ui.prompt('Trusted management IPs/VPN CIDRs, comma or space separated','Έμπιστες διαχειριστικές IP/VPN CIDRs',', '.join(trusted))
                networks=[str(ipaddress.ip_network(n,strict=False)) for n in re.split(r'[ ,]+',raw.strip()) if n]
                new={**value,'enabled':True,'continents':continents,'countries':countries,'expanded':expanded,'ports':ports,'trusted':networks}
                data=engine.read_json(engine.CACHE)
                if not data or data.get('source')!=new['source'] or (new['source']=='zone-feed' and (set(expanded)-set(data.get('countries',{})) or data.get('base_url')!=new['base_url'])):
                    if not console.confirm('Download lists for the selected source before enabling?'):continue
                    data=engine.collect_rir(COUNTRIES) if new['source']=='rir' else engine.collect_feed(new)
                    actions.apply(policy_plan(new,data),system.ssh_connection())
                else:actions.apply(policy_plan(new),system.ssh_connection())
                console.pause()
            elif choice=='disable':
                if not value['enabled']:ui.view('GeoIP SSH','Policy is already disabled.');continue
                actions.apply(policy_plan({**value,'enabled':False}),system.ssh_connection());console.pause()
            elif choice=='rules':ui.view('GeoIP SSH rules',lambda: engine.live_table() or 'No active table.')
            elif choice=='logs':ui.view('GeoIP SSH logs',lambda: system.command(['journalctl','-u',engine.UNIT,'-n','100','--no-pager'])[1])
        except (console.Cancelled,KeyboardInterrupt):continue
        except Exception as error:ui.error(error)
