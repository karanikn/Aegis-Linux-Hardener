"""Guided account, share, resolver and hosts menus / Οδηγοί διαχείρισης."""
import grp
import ipaddress
from pathlib import Path
import pwd
import stat
from . import actions,catalog,console,dependencies,nameconfig,networking,shares,system,users
from .ui import UI,table

class Back(Exception):pass


def ask(ui,en,el,default=''):
    value=ui.prompt(en+' (q=back)',el+' (q=πίσω)',default)
    if value.strip().lower()=='q':raise Back()
    return value


def apply(plan):
    result=actions.apply(plan,system.ssh_connection())
    console.pause()
    return result


def packages(values,title):
    missing=[package for package in values if not system.installed(package)]
    if not missing:return True
    plan=catalog.package_plan(missing,'Install requirements: '+title)
    plan.details+=['The selected management screen resumes after successful installation.']
    return bool(actions.apply(plan,system.ssh_connection()))


def choose_user(ui,regular=True):
    values=[(p.pw_name,p.pw_name+' | UID '+str(p.pw_uid),p.pw_dir+' | '+p.pw_shell) for p in pwd.getpwall()
            if (not regular or 1000<=p.pw_uid<60000) and p.pw_name in users.entries('passwd')]
    value=ui.choose('Select local user',values)
    if not value or value=='__refresh__':raise Back()
    return value


def choose_group(ui):
    values=[(g.gr_name,g.gr_name+' | GID '+str(g.gr_gid),'Members: '+', '.join(g.gr_mem)) for g in grp.getgrall() if g.gr_name in users.entries('group')]
    value=ui.choose('Select local group',values)
    if not value or value=='__refresh__':raise Back()
    return value


def permissions_menu(ui):
    while True:
        op=ui.choose('Permissions / POSIX ACL',[
          ('inspect','Inspect mode / owner / ACL','One existing file or directory; no recursive scan.'),
          ('mode','Change chmod mode','Nonrecursive rwx/setgid mode; preserves recovery of mode, ownership and ACL.'),
          ('owner','Change owner / group','Choose local identities; only the selected object changes.'),
          ('acl-set','Add / update ACL entry','Named user/group access or directory default ACL; inspect effective mask.'),
          ('acl-remove','Remove ACL entry','Only the selected named user/group ACL is removed.')])
        if op is None:return
        if op=='__refresh__':continue
        try:
            if not packages(['acl'],'POSIX ACL tools'):continue
            path=users.permission_path(ask(ui,'Absolute file/directory path','Απόλυτη διαδρομή',''))
            if op=='inspect':
                info=path.stat();code,text,error=system.command(['getfacl','-p','--',str(path)])
                ui.view('Permissions',str(path)+'\nMode '+oct(stat.S_IMODE(info.st_mode))+' | UID '+str(info.st_uid)+' | GID '+str(info.st_gid)+'\n\n'+text+error);continue
            request={'path':str(path)}
            if op=='mode':request['mode']=ask(ui,'Octal mode (e.g. 0750 / 2770)','Δικαιώματα (π.χ. 0750 / 2770)',format(stat.S_IMODE(path.stat().st_mode),'04o'))
            elif op=='owner':request['owner']=choose_user(ui,False);request['group']=choose_group(ui)
            elif op.startswith('acl-'):
                kind=ui.choose('ACL subject',[('user','Local user','Access for one user'),('group','Local group','Access for one group')])
                if kind not in ('user','group'):continue
                request['subject_kind']=kind;request['subject']=choose_user(ui,False) if kind=='user' else choose_group(ui)
                request['default']=path.is_dir() and console.confirm('Default ACL for NEW child files/directories?',default=False)
                if op=='acl-set':request['perms']=ask(ui,'Permissions rwx / r-x / r--','Δικαιώματα rwx / r-x / r--','r-x')
            apply(users.permissions(op,request))
        except (Back,console.Cancelled,KeyboardInterrupt):continue
        except Exception as error:ui.error(error)


@console.cancellable_menu
def ssh_keys_menu(ui):
    user=choose_user(ui,False)
    while True:
        filename=ui.choose('SSH public keys: '+user,[('authorized_keys','authorized_keys','Standard local key file'),('authorized_keys2','authorized_keys2','Legacy local key file')])
        if filename is None:return
        if filename=='__refresh__':continue
        while True:
            path,content,keys=users.ssh_keys(user,filename)
            rows=[(str(k['index']),k['type']+' '+k['fingerprint'],
                   'Line '+str(k['index']+1)+' | '+(k['comment'] or '(no comment)')+'\nRestrictions: '+str(k['restricted'])+'\nFile: '+str(path)) for k in keys]
            rows.append(('view','View entire public-key file','Read only; includes comments/options and unrecognized rows. Custom sshd key sources are not enumerated.'))
            selected=ui.choose(str(path),rows)
            if selected is None:break
            if selected=='__refresh__':continue
            if selected=='view':ui.view(str(path),content or 'No local public keys found.');continue
            key=next(k for k in keys if str(k['index'])==selected)
            action=ui.choose(key['fingerprint'],[('view','View public key',key['line']),('remove','Remove this public key','Back up the file, preserve other rows, and verify a new SSH connection.')])
            if action=='view':ui.view('SSH public key',key['line'])
            elif action=='remove':
                warning='Remove '+key['fingerprint']+'?'
                if len(keys)==1:warning+=' This is the LAST recognized key in this file.'
                if console.confirm(warning,default=False):apply(users.remove_ssh_key_plan(user,filename,key['index'],content))


def users_menu(language,operator,theme='slate'):
    ui=UI(language,theme)
    while True:
        op=ui.choose('User Management',[
          ('list','List local users','Names, UID/GID, home, shell and supplementary groups; no hashes.'),
          ('groups','List local groups','Local group names/GIDs/members.'),
          ('create','Create local user','Create a locked-password account and home; set its password separately.'),
          ('account','Manage an existing user','Password, password lock/unlock, account expiry, shell or delete without removing data.'),
          ('membership','Group membership / sudo access','Append/remove supplementary memberships; other groups are preserved.'),
          ('group-create','Create group','New local group.'),('group-delete','Delete empty group','Only non-system groups not used as a primary group.'),
          ('ssh-key','Add SSH public key','Append a validated public key; preserve existing keys.'),
          ('ssh-keys','View / remove SSH public keys','Fingerprints, comments, restrictions and backed-up removal of one selected key.'),
          ('permissions','Permissions / POSIX ACL','Inspect/edit one data path. No recursive ownership or chmod.'),
          ('sessions','Sessions / account status','Current logins and selected account status.')])
        if op is None:return
        try:
            if op=='list':ui.view('Local users',table(['User','UID','GID','Home','Shell','Groups'],users.overview()))
            elif op=='groups':ui.view('Local groups',table(['Group','GID','Members'],[(g.gr_name,g.gr_gid,','.join(g.gr_mem)) for g in grp.getgrall() if g.gr_name in users.entries('group')]))
            elif op=='create':
                request={'user':ask(ui,'New username','Νέος χρήστης')}
                shell=ui.choose('Login shell',[('/bin/bash','bash','Interactive shell'),('/bin/sh','sh','Minimal shell'),('/usr/sbin/nologin','No interactive login','For a data/service-only account')])
                if shell not in ('/bin/bash','/bin/sh','/usr/sbin/nologin'):continue
                request['shell']=shell;apply(users.plan('create',request,operator))
            elif op=='account':
                user=choose_user(ui)
                action=ui.choose(user,[(x,label,desc) for x,label,desc in [
                  ('password','Set Linux password','Interactive passwd; prior hash in private recovery data.'),
                  ('lock','Lock password','Does not revoke SSH keys or existing sessions.'),('unlock','Unlock password','Requires an existing usable password hash.'),
                  ('disable','Disable future logins (expiry)','Set account expiry; current sessions remain.'),('enable','Clear account expiry','Other PAM/SSH restrictions remain.'),
                  ('shell','Change login shell','bash, sh or nologin.'),('delete','Delete account; keep home/data','Refuses active processes and the current management account.')]])
                if not action or action=='__refresh__':continue
                request={'user':user}
                if action=='delete' and not packages(['procps'],'process checks'):continue
                if action=='shell':request['shell']=ask(ui,'Shell','Shell','/bin/bash')
                apply(users.plan(action,request,operator))
            elif op=='membership':
                user=choose_user(ui);group=choose_group(ui)
                action=ui.choose('Membership',[('group-add','Add membership','sudo/docker groups grant powerful privileges.'),('group-remove','Remove membership','Primary group is preserved.')])
                if action in ('group-add','group-remove'):apply(users.plan(action,{'user':user,'group':group},operator))
            elif op=='group-create':apply(users.plan(op,{'group':ask(ui,'New group name','Νέο group')},operator))
            elif op=='group-delete':apply(users.plan(op,{'group':choose_group(ui)},operator))
            elif op=='ssh-key':apply(users.ssh_key_plan(choose_user(ui),ask(ui,'Paste one OpenSSH PUBLIC key','Ένα OpenSSH ΔΗΜΟΣΙΟ κλειδί')))
            elif op=='ssh-keys':ssh_keys_menu(ui)
            elif op=='permissions':permissions_menu(ui)
            elif op=='sessions':
                user=choose_user(ui)
                ui.view('Sessions / status',system.command(['who'])[1]+'\n\n'+system.command(['passwd','-S',user])[1]+'\n\n'+system.command(['chage','-l',user])[1])
        except (Back,console.Cancelled,KeyboardInterrupt):continue
        except Exception as error:ui.error(error)


def hosts_menu(language,theme='slate'):
    ui=UI(language,theme)
    while True:
        op=ui.choose('Hosts file',[(x,label,desc) for x,label,desc in [('view','View /etc/hosts','All entries and comments.'),('add','Add entry','IPv4/IPv6 plus hostname/aliases.'),('edit','Edit entry','Core localhost/host identity entries are protected.'),('delete','Delete entry','A backup is kept before deletion.')]])
        if op is None:return
        try:
            if op=='view':ui.view('/etc/hosts',(nameconfig.ETC/'hosts').read_text());continue
            if op not in ('add','edit','delete'):continue
            request={}
            if op!='add':
                lines=(nameconfig.ETC/'hosts').read_text().splitlines()
                chosen=ui.choose('Select hosts entry',[(str(i),line,'Edit/delete only this row; other comments/entries remain.') for i,line in enumerate(lines) if len(line.split('#',1)[0].split())>=2])
                if chosen is None or chosen=='__refresh__':continue
                request={'index':int(chosen),'expected':lines[int(chosen)]}
            if op!='delete':
                parts=request.get('expected','').split('#',1)[0].split()
                request['address']=ask(ui,'IP address','IP',parts[0] if parts else '')
                request['names']=ask(ui,'Hostname / aliases separated by spaces','Hostname / aliases με κενά',' '.join(parts[1:]))
                request['comment']=ask(ui,'Comment (optional)','Σχόλιο (προαιρετικό)')
            apply(nameconfig.hosts_plan(op,**request))
        except (Back,console.Cancelled,KeyboardInterrupt):continue
        except Exception as error:ui.error(error)


def dns_menu(language,operator,theme='slate'):
    ui=UI(language,theme)
    while True:
        op=ui.choose('DNS Settings',[('status','Current DNS / resolver','Resolver file, resolved status and default route.'),
            ('edit','Edit DNS only','Detect current manager; preserve IP/gateway/routes. Timed rollback protects the operation.'),
            ('test','Test name resolution','Uses getent through the current Linux NSS configuration.')])
        if op is None:return
        try:
            if op=='status':ui.view('DNS',system.read('/etc/resolv.conf')+'\n\n'+system.command(['resolvectl','status'])[1]);continue
            if op=='test':
                domain=ask(ui,'Hostname to resolve','Hostname για επίλυση','debian.org');nameconfig.hostnames(domain)
                ui.view('Resolution',system.command(['getent','ahosts',domain])[1] or 'No result.');continue
            if op!='edit':continue
            if not dependencies.ensure({'kind':'network-configure','user':operator}):continue
            links=networking.interfaces();iface=ui.choose('Select interface',[(r['name'],r['name'],' | '.join(r['addresses'])) for r in links])
            if not iface or iface=='__refresh__':continue
            mode=ui.choose('DNS source',[('manual','Manual DNS IPs','IPv4/IPv6 nameservers.'),('auto','Automatic DNS','Only supported existing DHCP/resolver integration.')])
            if mode not in ('manual','auto'):continue
            servers=ask(ui,'DNS IPs, space/comma separated','DNS IP με κενά/κόμμα') if mode=='manual' else ''
            domains=ask(ui,'Search domains (- keeps existing; empty clears)','Search domains (- διατήρηση, κενό καθαρισμός)','-')
            apply(nameconfig.dns_plan(iface,servers,domains,mode=='auto'))
        except (Back,console.Cancelled,KeyboardInterrupt):continue
        except Exception as error:ui.error(error)


def shares_menu(language,operator,theme='slate'):
    ui=UI(language,theme)
    while True:
        version=catalog.app_version('samba')
        op=ui.choose('Share Management',[
          ('install','Install Samba'+(' [Installed]' if version else ''),'Standalone SMB server/tools; new services stay inactive.'),
          ('list','List configured SMB shares','Includes existing external shares (read-only inventory).'),
          ('create','Create Samba share','Existing data directory, authenticated users/@groups and trusted client subnets.'),
          ('edit','Edit Aegis share','Managed share definitions only.'),('remove','Remove Aegis share','Removes share configuration, never its data folder.'),
          ('folder','Create shared data folder','New /srv data folder with a selected group and setgid mode. Undo removes it only if empty.'),
          ('permissions','Unix permissions / POSIX ACL','Same scoped permission editor as User Management.'),
          ('smb-users','Samba accounts / passwords','Separate SMB password, enable/disable and account list.'),
          ('clients','Connected clients / open files','smbstatus views; no forced disconnect.'),
          ('service','Samba service control','Validate configuration before explicit start/stop; manage boot enablement separately.'),
          ('uninstall','Uninstall Samba (keep data/config)','Stop active services first. APT removal simulation and package recovery safeguards apply.'),
          ('cifs','SMB client / mounted shares','Inspect CIFS mounts and optionally install cifs-utils/smbclient.'),
          ('help','Share access / permission model','SMB authorization AND Unix traversal/permissions/ACL are required.')])
        if op is None:return
        try:
            if op=='install':
                if version:ui.view('Samba','Installed: '+version+'\nExisting configuration is preserved.')
                else:apply(shares.install_plan())
                continue
            if op=='uninstall':
                from . import uninstall
                apply(uninstall.plan('samba'));continue
            if op=='permissions':permissions_menu(ui);continue
            if op=='cifs':
                if packages(['cifs-utils','smbclient'],'SMB client tools'):ui.view('CIFS mounts',system.command(['findmnt','-t','cifs'])[1]+'\nUse a protected credentials file and a separately reviewed mount configuration; passwords never belong in command history.')
                continue
            if op=='help':
                ui.view('SMB permissions','1. Create a local Linux user/group.\n2. Give it suitable Unix permissions/ACL on the folder.\n3. Set its separate Samba password.\n4. Create a share with valid users and trusted LAN/VPN subnets.\n5. Validate and explicitly start Samba; review host firewall scope.\nWindows: \\\\SERVER_IP\\SHARE_NAME\nRead-write requires both SMB read only=no and Unix write/traverse access.\nNo public firewall ports are opened automatically. Existing sessions may need reconnection.');continue
            if op=='folder':
                target=Path(ask(ui,'New folder under /srv','Νέος φάκελος μέσα στο /srv','/srv/team'))
                if not target.is_absolute() or target.exists() or target.is_symlink() or Path('/srv') not in target.resolve().parents or not target.parent.is_dir():raise ValueError('Choose a NEW folder under an existing /srv directory.')
                group=users.local_group(choose_group(ui))
                plan=actions.Plan('Create shared folder '+str(target),commands=[['mkdir','--mode=2770','--',str(target)],['chown','--','0:'+str(group.gr_gid),str(target)],['chmod','2770',str(target)]],
                    rollback_commands=[['rmdir','--',str(target)]],details=['Owner root, selected group, mode 2770. Undo never recursively deletes data; nonempty directories are retained.'])
                apply(plan);continue
            if not dependencies.ensure({'kind':'open-app','app':'samba','user':operator}):continue
            if op=='list':ui.view('SMB shares',table(['Share','Path','Read only','Guest','Valid users'],shares.inventory()))
            elif op in ('create','edit','remove'):
                request={}
                if op=='create':request['name']=ask(ui,'Share name','Όνομα share')
                else:
                    cfg=shares.parsed(system.read(shares.ETC/'samba/aegis-shares.conf'))
                    chosen=ui.choose('Aegis-managed shares',[(name,name,cfg[name].get('path','')) for name in cfg.sections()])
                    if not chosen or chosen=='__refresh__':continue
                    request['name']=chosen
                if op!='remove':
                    old=shares.parsed(system.read(shares.ETC/'samba/aegis-shares.conf'));defaults=old[request['name']] if old.has_section(request['name']) else {}
                    request['path']=ask(ui,'Existing shared directory','Υπάρχων κοινόχρηστος φάκελος',defaults.get('path','/srv/team'))
                    request['valid_users']=ask(ui,'Allowed users / @groups','Επιτρεπόμενοι χρήστες / @groups',defaults.get('valid users',''))
                    source=system.ssh_connection().split();default_net=str(ipaddress.ip_network(source[0]+('/128' if ':' in source[0] else '/32'),strict=False)) if source else '127.0.0.1/32'
                    request['allow_networks']=ask(ui,'Trusted client IPs/subnets','Έμπιστα IP/subnets',defaults.get('hosts allow',default_net))
                    request['readonly']=not console.confirm('Allow SMB write access (Unix permissions must also allow it)?',default=False)
                apply(shares.share_plan(op,request))
            elif op=='smb-users':
                action=ui.choose('Samba accounts',[('list','List SMB accounts','No password hashes displayed.'),('password','Add / reset SMB password','Separate from Linux password.'),('enable','Enable SMB account','Retains existing SID/password.'),('disable','Disable SMB account','Retains account and data.')])
                if action=='list':ui.view('SMB accounts',system.command(['pdbedit','-L'])[1])
                elif action in ('password','enable','disable'):apply(shares.credential_plan(action,choose_user(ui)))
            elif op=='clients':ui.view('SMB clients / files',system.command(['smbstatus','--shares'])[1]+'\n\n'+system.command(['smbstatus','--locks'])[1])
            elif op=='service':
                choice=ui.choose('Samba service',[('start','Start smbd','Starts the configured SMB listener; no firewall rules are added.'),('stop','Stop smbd','Interrupts client availability. Boot enablement is unchanged.'),('enable','Enable at boot','Changes boot enablement only; does not start smbd now.'),('disable','Disable at boot','Changes boot enablement only; does not stop current sessions.')])
                if choice in ('start','stop','enable','disable'):apply(shares.service_plan(choice))
        except (Back,console.Cancelled,KeyboardInterrupt):continue
        except Exception as error:ui.error(error)
