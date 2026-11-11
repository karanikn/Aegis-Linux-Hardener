"""DNS-only manager edits and validated hosts entries / DNS χωρίς αλλαγή IP."""
import copy
import io
import ipaddress
from pathlib import Path
import re
import sys
from . import networking,system
from .actions import Plan,ENTRY

ETC=Path('/etc')


def hostnames(value):
    names=value.replace(',',' ').split()
    for name in names:
        if len(name)>253 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name):raise ValueError('Use valid host/domain names separated by spaces.')
    return names


def hosts_plan(op,address='',names='',index=None,expected='',comment=''):
    path=ETC/'hosts'
    if path.is_symlink():raise ValueError('Hosts symlink needs manual management.')
    text=path.read_text();lines=text.splitlines()
    if op not in ('add','edit','delete'):raise ValueError('Unknown hosts operation')
    if op!='add':
        index=int(index)
        if index<0 or index>=len(lines) or lines[index]!=expected:raise ValueError('Hosts file changed; refresh before editing.')
        fields=lines[index].split('#',1)[0].split()
        if not fields:raise ValueError('Select an address entry.')
        if fields[0] in ('127.0.0.1','127.0.1.1','::1') or 'localhost' in fields[1:]:raise ValueError('Core localhost/host identity entries are protected by this wizard.')
    if op=='delete':del lines[index]
    else:
        address=str(ipaddress.ip_address(address));aliases=hostnames(names)
        if not aliases:raise ValueError('At least one hostname is required.')
        if any(c in comment for c in ('\n','\r','\x00')):raise ValueError('One-line comment required.')
        replacement=address+'\t'+' '.join(aliases)+(' # '+comment[:200] if comment else '')
        if op=='add':lines.append(replacement)
        else:lines[index]=replacement
    return Plan('Hosts file: '+op,writes={str(path):'\n'.join(lines)+'\n'},details=['Other hosts entries/comments are retained. No network service restart is needed. Existing file is backed up.'])


def section_values(text,section,values):
    lines=text.splitlines();out=[];inside=False;seen=False
    for line in lines:
        match=re.match(r'\s*\[([^]]+)\]',line)
        if match:
            if inside:out += [key+'='+value for key,value in values.items() if value is not None]
            inside=match[1]==section;seen=seen or inside
        if inside and any(re.match(r'\s*'+re.escape(key)+r'\s*=',line) for key in values):continue
        out.append(line)
    if inside:out += [key+'='+value for key,value in values.items() if value is not None]
    if not seen:out += ['','['+section+']']+[key+'='+value for key,value in values.items() if value is not None]
    return '\n'.join(out)+'\n'


def dns_plan(iface,servers,domains='-',automatic=False):
    iface=networking.interface_name(iface)
    addresses=[] if automatic else [str(ipaddress.ip_address(x)) for x in servers.replace(',',' ').split()]
    if not automatic and not addresses:raise ValueError('Enter at least one DNS IP address.')
    search=None if domains=='-' else hostnames(domains)
    try:backend,detail=networking.detect_backend(iface)
    except ValueError as error:
        if not str(error).startswith('No unambiguous supported'):raise
        resolver=ETC/'resolv.conf'
        if resolver.is_symlink() or not resolver.is_file() or automatic:raise
        text=resolver.read_text()
        if re.search(r'generated|NetworkManager|resolvconf|systemd',text,re.I):raise ValueError('Resolver file has an external owner; use its supported interface manager.')
        backend,detail='resolver-file',resolver
    plan=Plan('DNS only: '+iface,critical=True,detached=True,secrets=True,
        details=['Manager: '+backend,'DNS: '+('automatic' if automatic else ', '.join(addresses)),
                 'Existing IP addresses, gateway, routes and DHCP address mode are preserved.',
                 'Confirm from a new SSH session within 180 seconds; also test name resolution before keeping the change.'])
    ident=''
    if backend=='networkmanager':
        path,ident,cfg=detail
        for section,version in (('ipv4',4),('ipv6',6)):
            if not cfg.has_section(section):continue
            chosen=[x for x in addresses if ipaddress.ip_address(x).version==version]
            cfg.set(section,'ignore-auto-dns','false' if automatic else 'true')
            cfg.remove_option(section,'dns')
            if chosen:cfg.set(section,'dns',';'.join(chosen)+';')
            if search is not None:
                cfg.remove_option(section,'dns-search')
                if search:cfg.set(section,'dns-search',';'.join(search)+';')
        stream=io.StringIO();cfg.write(stream,space_around_delimiters=False)
        plan.writes[str(path)]=stream.getvalue();plan.modes[str(path)]=0o600
    elif backend=='netplan':
        import yaml
        # Remove nameserver address sequences in every matching layer before setting the last layer.
        docs={};effective={family:False for family in ('dhcp4','dhcp6')}
        for _,_,_,_,config in detail:
            for family in effective:
                if family in config:effective[family]=bool(config[family])
        for path,data,group,key,original in detail:
            document=docs.setdefault(path,copy.deepcopy(data));config=document['network'][group][key]
            nameserver=config.setdefault('nameservers',{});nameserver.pop('addresses',None)
            if search is not None:nameserver.pop('search',None)
            for dhcp in ('dhcp4','dhcp6'):
                if config.get(dhcp):config.setdefault(dhcp+'-overrides',{})['use-dns']=automatic
        path,data,group,key,original=detail[-1];target=docs[path]['network'][group][key]
        for family,active in effective.items():
            if active:target.setdefault(family+'-overrides',{})['use-dns']=automatic
        if automatic and not any(effective.values()):raise ValueError('Automatic DNS requires DHCP DNS on this Netplan interface.')
        if addresses:target.setdefault('nameservers',{})['addresses']=addresses
        if search:target.setdefault('nameservers',{})['search']=search
        for path,data in docs.items():plan.writes[str(path)]=yaml.safe_dump(data,sort_keys=False);plan.modes[str(path)]=path.stat().st_mode&0o777
        plan.validate=[['netplan','generate']]
        plan.details+=['netplan apply can reconfigure other links; review cloud-init/vendor regeneration separately.']
    elif backend=='ifupdown':
        if len(detail)!=1:raise ValueError('Ambiguous ifupdown definitions.')
        path=detail[0];lines,ranges=networking.ifupdown_stanzas(path.read_text(),iface)
        if len(ranges)!=1:raise ValueError('Ambiguous IPv4 stanza.')
        start,end=ranges[0];block=lines[start:end]
        has_resolvconf=bool(networking.shutil_which('resolvconf'))
        if has_resolvconf:
            filtered=[line for line in block if not re.match(r'\s*dns-nameservers\s',line) and not(search is not None and re.match(r'\s*dns-search\s',line))]
            if addresses:filtered.append('    dns-nameservers '+' '.join(addresses)+'\n')
            if search:filtered.append('    dns-search '+' '.join(search)+'\n')
            plan.writes[str(path)]=''.join(lines[:start]+filtered+lines[end:])
        elif automatic:raise ValueError('Automatic DNS needs the existing DHCP/resolver integration; it is not guessed here.')
        resolver=ETC/'resolv.conf'
        if not has_resolvconf:
            if resolver.is_symlink():raise ValueError('Resolver symlink belongs to another provider.')
            old=resolver.read_text();kept=[line for line in old.splitlines() if not line.startswith('nameserver ') and not(search is not None and line.startswith(('search ','domain ')))]
            plan.writes[str(resolver)]='\n'.join(kept+['nameserver '+x for x in addresses]+(['search '+' '.join(search)] if search else []))+'\n'
        if has_resolvconf and automatic and ' dhcp' not in block[0]:raise ValueError('Automatic DNS needs an IPv4 DHCP stanza.')
    elif backend=='networkd':
        path=detail;text=path.read_text()
        if automatic and not re.search(r'^\s*DHCP\s*=\s*(yes|true|ipv4|ipv6)\s*$',text,re.M|re.I):raise ValueError('Automatic DNS requires DHCP on this networkd interface.')
        text=section_values(text,'Network',{'DNS':' '.join(addresses) if addresses else None,**({'Domains':' '.join(search) if search else None} if search is not None else {})})
        for section in ('DHCPv4','DHCPv6'):text=section_values(text,section,{'UseDNS':'yes' if automatic else 'no'})
        if system.service('systemd-resolved')!='active':raise ValueError('This networkd DNS flow requires active systemd-resolved; no resolver migration is performed.')
        plan.writes[str(path)]=text
    elif backend=='resolver-file':
        old=detail.read_text();kept=[line for line in old.splitlines() if not line.startswith('nameserver ') and not(search is not None and line.startswith(('search ','domain ')))]
        plan.writes[str(detail)]='\n'.join(kept+['nameserver '+x for x in addresses]+(['search '+' '.join(search)] if search else []))+'\n'
    else:raise ValueError('Unsupported DNS owner')
    data={'backend':backend,'iface':iface,'uuid':ident}
    helper=[sys.executable,str(ENTRY),'--dns-reload',__import__('json').dumps(data)]
    plan.commands=[helper];plan.rollback_commands=[helper]
    return plan


def reload_dns(data):
    backend=data['backend'];iface=networking.interface_name(data['iface']);ident=data.get('uuid','')
    commands=[]
    if backend=='networkmanager':
        if not re.fullmatch(r'[a-fA-F0-9-]{36}',ident):raise ValueError('Invalid connection UUID')
        if system.command(['nmcli','-g','GENERAL.CON-UUID','device','show',iface])[1]!=ident:raise ValueError('Active NetworkManager profile changed; inspect before applying DNS.')
        commands=[['nmcli','connection','reload'],['nmcli','device','reapply',iface]]
    elif backend=='netplan':commands=[['netplan','apply']]
    elif backend=='networkd':commands=[['networkctl','reload'],['networkctl','reconfigure',iface]]
    elif backend=='ifupdown':
        # resolvconf updates DNS without bouncing the interface; direct files need no restart.
        if networking.shutil_which('resolvconf'):
            path_list=networking.ifupdown_sources();dns=[];search=[]
            for path in path_list:
                lines,ranges=networking.ifupdown_stanzas(path.read_text(),iface)
                for start,end in ranges:
                    for line in lines[start:end]:
                        parts=line.split()
                        if parts and parts[0]=='dns-nameservers':dns+=parts[1:]
                        if parts and parts[0]=='dns-search':search+=parts[1:]
            import subprocess
            if dns:
                text=''.join('nameserver '+x+'\n' for x in dns)+('search '+' '.join(search)+'\n' if search else '')
                subprocess.run(['resolvconf','-a',iface+'.inet'],input=text,text=True,check=True)
            else:subprocess.run(['resolvconf','-d',iface+'.inet'],check=True)
            commands=[['resolvconf','-u']]
    elif backend!='resolver-file':raise ValueError('Unsupported DNS manager')
    for command in commands:
        if system.command(command)[0]:raise RuntimeError('DNS activation failed: '+command[0])


def hostname_plan(value,update_hosts=True):
    value=value.strip()
    if len(value)>64 or value!=value.lower() or not value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in value.split('.')):
        raise ValueError('Use a lowercase DNS hostname/FQDN, letters/digits/hyphens, max 64 characters; labels cannot start/end with a hyphen.')
    import shutil
    if not shutil.which('hostnamectl'):raise ValueError('hostnamectl/systemd-hostnamed is required; no replacement hostname manager is installed automatically.')
    current=system.socket.gethostname();hostfile=ETC/'hostname';hostsfile=ETC/'hosts'
    if hostfile.is_symlink() or hostsfile.is_symlink():raise ValueError('Symlink hostname/hosts files need manual ownership review.')
    if current==value and system.read(hostfile).strip()==value:raise ValueError('This hostname is already configured.')
    plan=Plan('Change hostname: '+current+' → '+value,writes={str(hostfile):value+'\n'},
        commands=[['hostnamectl','--static','set-hostname',value],['hostnamectl','--transient','set-hostname',value]],
        rollback_commands=[[sys.executable,str(ENTRY),'--hostname-runtime',current],['systemctl','try-restart','systemd-hostnamed.service']],
        details=['Sets static and current transient hostname. Previous files and kernel hostname are retained for Undo.',
                 'IP/gateway/DNS servers are unchanged. External DNS, TLS certificates, monitoring identities and application configuration are not renamed.',
                 'Current SSH sessions normally remain; shells/services may display cached old names until reopened/restarted.'])
    if update_hosts:
        lines=system.read(hostsfile).splitlines();updated=[];found=False
        old_short=current.split('.')[0].lower();new_names=[value]+([value.split('.')[0]] if '.' in value else [])
        for line in lines:
            content,separator,comment=line.partition('#');parts=content.split()
            if parts and parts[0]=='127.0.1.1':
                aliases=[name for name in parts[1:] if name.lower().split('.')[0]!=old_short and name not in new_names]
                updated.append('127.0.1.1\t'+' '.join(new_names+aliases)+(' #'+comment if separator else ''));found=True
            else:updated.append(line)
        if not found:updated.append('127.0.1.1\t'+' '.join(new_names))
        plan.writes[str(hostsfile)]='\n'.join(updated)+'\n'
        plan.details+=['Updates the local 127.0.1.1 hostname mapping, preserving unrelated aliases/comments and localhost IPv4/IPv6 entries.']
    return plan


def restore_runtime_hostname(value):
    if not value or len(value.encode())>64 or any(ord(ch)<33 or ord(ch)>126 for ch in value):raise ValueError('Invalid recorded kernel hostname')
    system.socket.sethostname(value.encode('ascii'))
