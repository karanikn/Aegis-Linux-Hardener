"""Standalone Samba shares, credentials and inspection; Unix ACLs are separate."""
import configparser
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from . import actions,catalog,system,users
from .actions import Plan,ENTRY

ETC=Path('/etc')


def standalone():
    if not system.installed('samba'):raise ValueError('Install Samba first.')
    code,role,_=system.command(['testparm','-s','--parameter-name=server role'])
    if code or 'standalone' not in role.lower():raise ValueError('This manager edits standalone Samba only; AD/domain-member servers need domain-aware administration.')
    _,backend,_=system.command(['testparm','-s','--parameter-name=passdb backend'])
    if not backend.startswith('tdbsam'):raise ValueError('Only the local tdbsam credential backend is managed here.')


def install_plan():
    if system.installed('samba'):raise ValueError('Samba is installed; existing configuration is retained.')
    if system.service('smbd')=='active' or system.service('samba-ad-dc')=='active':raise ValueError('An external Samba instance is active; inspect it before installing.')
    plan=catalog.package_plan(['samba','smbclient','acl'],'Install Samba server/tools (inactive)')
    plan.suppress_services=True;plan.backup_paths=[str(ETC/'samba')]
    plan.commands=[[sys.executable,str(ENTRY),'--restore-service-state',__import__('json').dumps({'unit':unit,'enabled':False,'active':False})] for unit in ('smbd.service','nmbd.service','samba-ad-dc.service')]
    plan.details+=['New services remain stopped/disabled. Share creation and service start are separate choices.',
                   'No guest shares, SMB1 policy, firewall openings or public exposure are added.']
    return plan


def parsed(text):
    cfg=configparser.ConfigParser(interpolation=None,strict=False,inline_comment_prefixes=None)
    cfg.read_string(text or '')
    return cfg


def inventory():
    code,text,_=system.command(['testparm','-s','--suppress-prompt'])
    if code:raise ValueError('testparm could not read a valid Samba configuration.')
    cfg=parsed(text);rows=[]
    global_row=next((cfg[s] for s in cfg.sections() if s.lower()=='global'),{})
    for section in cfg.sections():
        if section.lower()=='global':continue
        row=cfg[section]
        rows.append((section,row.get('path','dynamic/special'),row.get('read only',global_row.get('read only','yes')),row.get('guest ok',global_row.get('guest ok','no')),row.get('valid users',global_row.get('valid users','default'))))
    return rows


def share_name(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,47}',value) or value.lower() in ('global','homes','printers','ipc'):
        raise ValueError('Use a regular share name, letters/digits/_/-, max 48; special Samba sections are excluded.')
    return value


def share_plan(op,request):
    standalone();name=share_name(request['name']);main=ETC/'samba/smb.conf';managed=ETC/'samba/aegis-shares.conf'
    if main.is_symlink() or managed.is_symlink():raise ValueError('Symlink Samba configuration requires manual review.')
    text=main.read_text();cfg=parsed(system.read(managed));existing={row[0].lower() for row in inventory()}
    matches=[section for section in cfg.sections() if section.lower()==name.lower()]
    if op=='create' and name.lower() in existing:raise ValueError('This share already exists. Existing external shares are shown read-only.')
    if op in ('edit','remove') and not matches:raise ValueError('Edit/remove is limited to shares created in the Aegis include file.')
    if matches:cfg.remove_section(matches[0])
    if op!='remove':
        path=users.permission_path(request['path'])
        if not path.is_dir() or '%' in str(path):raise ValueError('Select an existing directory without Samba substitution tokens.')
        subjects=request['valid_users'].split()
        if not subjects:raise ValueError('Specify at least one Linux user or @group; guest shares are not offered.')
        for subject in subjects:
            if subject.startswith('@'):users.local_group(subject[1:])
            else:users.local_user(subject)
        allowed=request.get('allow_networks','').replace(',',' ').split()
        import ipaddress
        networks=[str(ipaddress.ip_network(x,strict=False)) for x in allowed]
        if not networks:raise ValueError('Specify trusted client IPs/subnets for the share.')
        cfg.add_section(name)
        cfg[name]={'path':str(path),'browseable':'yes','read only':'yes' if request.get('readonly',True) else 'no',
                   'force directory mode':'02000','guest ok':'no','valid users':' '.join(subjects),'hosts allow':' '.join(networks),
                   'hosts deny':'ALL','create mask':'0660','directory mask':'0770'}
    output=io.StringIO();cfg.write(output,space_around_delimiters=True)
    marker='# Aegis managed share include'
    include='include = '+str(managed)
    if not re.search(r'^\s*include\s*=\s*'+re.escape(str(managed))+r'\s*$',text,re.M):
        text=text.rstrip()+'\n\n'+marker+'\n[global]\n    '+include+'\n'
    reload=[['smbcontrol','smbd','reload-config']] if system.service('smbd')=='active' else []
    return Plan('Samba share: '+op+' '+name,writes={str(main):text,str(managed):output.getvalue()},validate=[['testparm','-s',str(main)]],
        commands=reload,rollback_commands=reload,details=['Changes only Aegis-managed share entries. Existing external share definitions are not edited.',
            'Share data, Unix ownership and ACLs are preserved. Read-write SMB access also requires Unix write/traverse rights.',
            'No service is started and no firewall rule is added here. Existing client sessions may retain old settings until reconnect.'])


def credential_rows(names):
    for name in names:users.name(name)
    code,text,_=system.command(['pdbedit','-L','-w'])
    if code:raise RuntimeError('Cannot snapshot Samba credentials; no SMB account changes applied.')
    rows={line.split(':',1)[0]:line for line in text.splitlines() if line.count(':')>=6}
    return {name:rows.get(name) for name in names}


def credential_plan(op,user):
    standalone();users.local_user(user,True)
    if op not in ('password','enable','disable'):raise ValueError('Unknown SMB account operation')
    if op!='password' and credential_rows([user])[user] is None:raise ValueError('Add this Samba account/password first.')
    return Plan('Samba account: '+op+' '+user,samba_users=[user],commands=[['smbpasswd',{'password':'-a','enable':'-e','disable':'-d'}[op],user]],
        details=['Separate from the Linux password. Type the SMB password into smbpasswd, never argv.',
                 'Private recovery data includes SMB password hashes. Undo restores basic password/account flags, not all Samba metadata/domain state.'])


def restore_credentials(record):
    standalone()
    names=list(record['old']);current=credential_rows(names)
    if record.get('expected') is not None and current!=record['expected']:raise RuntimeError('Samba credentials changed later; undo newer changes first.')
    for name,old in record['old'].items():
        if old is None:
            if current[name] is not None:
                result=subprocess.run(['pdbedit','-x','-u',name],capture_output=True)
                if result.returncode:raise RuntimeError('Could not remove the newly created SMB account.')
        else:
            with tempfile.NamedTemporaryFile(mode='w',prefix='aegis-smb-',dir=actions.STATE,delete=False) as stream:
                os.chmod(stream.name,0o600);stream.write(old+'\n');path=stream.name
            try:
                result=subprocess.run(['pdbedit','-i','smbpasswd:'+path,'-u',name],capture_output=True)
                if result.returncode:raise RuntimeError('SMB credential recovery failed; inspect the protected snapshot.')
            finally:Path(path).unlink(missing_ok=True)


def service_plan(mode):
    standalone()
    if mode not in ('start','stop','enable','disable'):raise ValueError('Choose start or stop.')
    old=system.service_state('smbd.service')
    return Plan('Samba service: '+mode,validate=[['testparm','-s']],
        commands=[['systemctl',mode,'smbd.service']],rollback_commands=[[sys.executable,str(ENTRY),'--restore-service-state',__import__('json').dumps(old)]],
        details=['Start/stop affects SMB availability and client sessions. Boot enablement is preserved.',
                 'No firewall rules are changed. Confirm your current bind interfaces and network access policy before starting.'])
