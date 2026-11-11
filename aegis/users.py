"""Local account/group management and narrowly scoped recovery / Τοπικοί λογαριασμοί."""
import base64
import ctypes
import grp
import hashlib
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
from . import system
from .actions import Plan,write_file

ETC=Path('/etc')
DBS=('passwd','shadow','group','gshadow','subuid','subgid')


def name(value):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',value):raise ValueError('Use a local account/group name: lowercase letters, digits, _ or -, max 32 characters.')
    return value


def entries(file):
    return {line.split(':',1)[0]:line for line in system.read(ETC/file).splitlines() if line and not line.startswith('#') and ':' in line}


def capture(users,groups):
    for required in ('passwd','shadow','group','gshadow'):
        path=ETC/required
        if path.is_symlink() or not path.is_file():raise ValueError('Account database must be an existing regular file: '+required)
        path.read_text() # Fail closed on unreadable credential databases.
    data={}
    for file in DBS:
        keys=groups if file in ('group','gshadow') else users
        all_rows=entries(file)
        if file in ('subuid','subgid'):
            lines=system.read(ETC/file).splitlines()
            data[file]={key:([line for line in lines if line.startswith(key+':')] or None) for key in keys}
        else:data[file]={key:all_rows.get(key) for key in keys}
    return {'users':list(users),'groups':list(groups),'data':data}


class DatabaseLock:
    def __init__(self,libc,files):self.libc,self.files=libc,files
    def ulckpwdf(self):
        for path,identity in reversed(self.files):
            if path.exists() and (path.stat().st_dev,path.stat().st_ino)==identity:path.unlink()
        self.libc.ulckpwdf()


def lock_accounts():
    libc=ctypes.CDLL(None)
    if libc.lckpwdf()!=0:raise RuntimeError('Account database is busy; retry later.')
    locked=[]
    try:
        for file in DBS:
            path=ETC/(file+'.lock')
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            try:
                os.write(fd,(str(os.getpid())+'\0').encode());info=os.fstat(fd)
                locked.append((path,(info.st_dev,info.st_ino)))
            finally:os.close(fd)
    except Exception:
        DatabaseLock(libc,locked).ulckpwdf()
        raise RuntimeError('Account/group database lock exists; no recovery writes applied.') from None
    return DatabaseLock(libc,locked)


def restore_accounts(record):
    old=record['old'];current=capture(old['users'],old['groups'])
    if record.get('expected') and current!=record['expected']:
        raise RuntimeError('These account/group records changed after this action; refusing to overwrite newer changes. Undo newer changes first.')
    libc=lock_accounts()
    try:
        if capture(old['users'],old['groups'])!=current:raise RuntimeError('Account state changed while locking.')
        for file in DBS:
            path=ETC/file
            if not old['data'][file]:continue
            if not path.exists() and all(v is None for v in old['data'][file].values()):continue
            if path.is_symlink():raise RuntimeError('Symlink account database is unsupported.')
            originals=old['data'][file];existing=entries(file)
            if file in ('passwd','group'):
                for key,value in originals.items():
                    if value is None:continue
                    ident=value.split(':')[2]
                    if any(other!=key and other not in originals and row.split(':')[2]==ident for other,row in existing.items()):
                        raise RuntimeError('UID/GID collision prevents safe account recovery.')
        # Never remove an active created account or a group subsequently used as a primary group.
        for key,value in old['data']['passwd'].items():
            if value is None and current['data']['passwd'].get(key):
                uid=current['data']['passwd'][key].split(':')[2]
                code=system.command(['pgrep','-u',uid])[0]
                if code not in (0,1):raise RuntimeError('Cannot verify created-account processes; install procps before Undo.')
                if code==0:raise RuntimeError('Created user has active processes; log out before Undo.')
        for key,value in old['data']['group'].items():
            if value is None and current['data']['group'].get(key):
                gid=current['data']['group'][key].split(':')[2]
                if any(row.split(':')[3]==gid and not(name in old['data']['passwd'] and old['data']['passwd'][name] is None) for name,row in entries('passwd').items()):raise RuntimeError('Created group is now a primary group in use; recovery refused.')
        # All conflict checks finish before changing any database.
        for file in DBS:
            path=ETC/file;originals=old['data'][file]
            if not originals:continue
            if not path.exists() and all(v is None for v in originals.values()):continue
            info=path.stat();lines=path.read_text().splitlines();seen=set();result=[]
            for line in lines:
                key=line.split(':',1)[0]
                if key in originals:
                    if key in seen:continue
                    seen.add(key)
                    if originals[key] is not None:result.extend(originals[key] if isinstance(originals[key],list) else [originals[key]])
                else:result.append(line)
            for key,value in originals.items():
                if key not in seen and value is not None:result.extend(value if isinstance(value,list) else [value])
            write_file(path,'\n'.join(result)+'\n',stat.S_IMODE(info.st_mode));os.chown(path,info.st_uid,info.st_gid)
    finally:libc.ulckpwdf()


def local_user(user,regular=False):
    name(user)
    if user not in entries('passwd'):raise ValueError('Select an existing local Linux user; directory/LDAP accounts are not edited.')
    account=pwd.getpwnam(user)
    if regular and not 1000<=account.pw_uid<60000:raise ValueError('This operation is restricted to regular local users (UID >=1000).')
    return account


def local_group(group):
    name(group)
    if group not in entries('group'):raise ValueError('Select an existing local group.')
    return grp.getgrnam(group)


def overview():
    rows=[]
    for user,line in entries('passwd').items():
        fields=line.split(':');account=pwd.getpwnam(user)
        groups=[g.gr_name for g in grp.getgrall() if user in g.gr_mem]
        rows.append((user,fields[2],fields[3],fields[5],fields[6],','.join(groups)))
    return rows


def plan(op,request,operator):
    user=request.get('user','');group=request.get('group','')
    if op=='group-create':
        name(group)
        if group in entries('group'):raise ValueError('Group already exists.')
        return Plan('Create local group '+group,commands=[['groupadd',group]],account_groups=[group])
    if op=='group-delete':
        obj=local_group(group)
        if not 1000<=obj.gr_gid<60000 or any(p.pw_gid==obj.gr_gid for p in pwd.getpwall()):raise ValueError('System groups and primary groups in use cannot be deleted here.')
        if obj.gr_mem:raise ValueError('Remove supplementary members explicitly before deleting this group.')
        return Plan('Delete empty local group '+group,commands=[['groupdel',group]],account_groups=[group])
    if op=='create':
        name(user)
        try:pwd.getpwnam(user)
        except KeyError:pass
        else:raise ValueError('User already exists locally or through NSS.')
        if user in entries('group'):raise ValueError('A group with this name already exists; choose another username.')
        shell=request.get('shell','/bin/bash')
        if shell not in ('/bin/bash','/bin/sh','/usr/sbin/nologin'):raise ValueError('Unsupported login shell')
        return Plan('Create local user '+user,account_users=[user],account_groups=[user],
            commands=[['useradd','--create-home','--user-group','--shell',shell,user]],
            details=['New password is locked until Set password is used. Home defaults to the distribution configuration.',
                     'Undo removes the created account records but preserves home files; it never recursively deletes user data.'])
    account=local_user(user,True)
    dangerous=op in ('delete','lock','disable','shell') or (op=='group-remove' and group in ('sudo','adm'))
    if user==operator and dangerous:raise ValueError('This action cannot disable/remove the current management account. Use a separately verified administrator session.')
    groups=[g.gr_name for g in grp.getgrall() if user in g.gr_mem or g.gr_name==user]
    result=Plan(op+' local user '+user,account_users=[user],account_groups=groups)
    if op=='delete':
        code=system.command(['pgrep','-u',str(account.pw_uid)])[0]
        if code not in (0,1):raise ValueError('Cannot verify active processes; install procps before account deletion.')
        if code==0:raise ValueError('User has active processes. End the session normally before deletion.')
        result.commands=[['userdel',user]]
        result.details=['Account is removed without -r. Home/mail/data files are retained. Samba credentials are managed separately.']
    elif op=='password':
        result.commands=[['passwd',user]]
        result.details=['Password is entered into passwd, never into argv/history. Prior password hash is retained only in the private root-owned recovery manifest.']
    elif op in ('lock','unlock'):
        result.commands=[['usermod','--lock' if op=='lock' else '--unlock',user]]
        result.details=['Password lock does not revoke existing sessions or SSH public-key access. Use account expiry for disabling logins.']
    elif op in ('disable','enable'):
        result.commands=[['usermod','--expiredate','1' if op=='disable' else '-1',user]]
        result.details=['Account expiry affects future logins under the configured PAM/SSH policy. Existing sessions are not killed.']
    elif op=='shell':
        shell=request.get('shell','')
        if shell not in ('/bin/bash','/bin/sh','/usr/sbin/nologin'):raise ValueError('Select a supported shell.')
        result.commands=[['usermod','--shell',shell,user]]
    elif op in ('group-add','group-remove'):
        obj=local_group(group)
        if op=='group-remove' and obj.gr_gid==account.pw_gid:raise ValueError('Primary group membership cannot be removed.')
        result.account_groups=sorted(set(groups+[group]))
        result.commands=[['gpasswd','-a' if op=='group-add' else '-d',user,group]]
        result.details=['Supplementary membership only; existing other memberships are preserved.',
                        'sudo grants administrative access; docker grants root-equivalent container-engine access. Re-login may be needed.']
    else:raise ValueError('Unknown local-user operation')
    return result


def permission_path(value):
    path=Path(value)
    if not path.is_absolute() or any(c in value for c in ('\n','\r','\x00')):raise ValueError('Use a clean absolute path.')
    if path.is_symlink():raise ValueError('Select the actual path, not a symlink.')
    real=path.resolve(strict=True)
    if not any(Path(base) in real.parents for base in ('/home','/srv','/mnt','/media','/opt')):
        raise ValueError('Permission editing here is limited to a selected object under /home, /srv, /mnt, /media or /opt.')
    if not real.is_dir() and not real.is_file():raise ValueError('Select a regular file or directory.')
    return real


def permissions(op,request):
    path=permission_path(request['path']);info=path.stat()
    result=Plan('Permissions: '+op+' '+str(path),metadata={str(path):stat.S_IMODE(info.st_mode)},acl_paths=[str(path)],
                details=['Only this object is changed, not its descendants. Mode/owner/group/POSIX ACL are saved for Undo.'])
    if op=='mode':
        mode=request['mode']
        if not re.fullmatch(r'[0-7]{3,4}',mode) or int(mode,8)&0o7000 not in (0,0o2000):raise ValueError('Use normal rwx bits, optionally setgid; SUID/sticky changes are not offered here.')
        result.metadata[str(path)]=int(mode,8)
    elif op=='owner':
        user=local_user(request['owner']);group=local_group(request['group'])
        result.commands=[['chown','--',str(user.pw_uid)+':'+str(group.gr_gid),str(path)]]
    elif op in ('acl-set','acl-remove'):
        kind=request.get('subject_kind','user');subject=request['subject']
        if kind=='user':local_user(subject);prefix='u'
        elif kind=='group':local_group(subject);prefix='g'
        else:raise ValueError('Choose a user or group ACL subject.')
        default=bool(request.get('default'))
        if default and not path.is_dir():raise ValueError('Default ACL needs a directory.')
        entry=('d:' if default else '')+prefix+':'+subject
        if op=='acl-set':
            perms=request['perms']
            if not re.fullmatch(r'[r-][w-][x-]',perms):raise ValueError('Use rwx notation, e.g. rwx, r-x or r--.')
            entry+=':'+perms
        result.commands=[['setfacl','-m' if op=='acl-set' else '-x',entry,'--',str(path)]]
        result.details+=['setfacl recalculates the ACL mask; inspect effective rights. Default ACL only affects newly created children.']
    else:raise ValueError('Unknown permission operation')
    return result


def ssh_key_plan(user,key):
    account=local_user(user,True);fields=key.strip().split()
    if len(fields)<2 or fields[0] not in ('ssh-ed25519','ssh-rsa','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521'):raise ValueError('Paste one supported OpenSSH public key, not a private key or options.')
    if '\n' in key or '\r' in key:raise ValueError('One public key per operation.')
    try:
        data=base64.b64decode(fields[1],validate=True);size=int.from_bytes(data[:4],'big')
        if data[4:4+size].decode()!=fields[0] or len(data)<size+12:raise ValueError('Key encoding mismatch')
    except (ValueError,UnicodeError) as error:raise ValueError('Invalid public-key encoding') from error
    home=Path(account.pw_dir);folder=home/'.ssh';path=folder/'authorized_keys'
    if home.is_symlink() or folder.is_symlink() or path.is_symlink():raise ValueError('Symlink SSH paths require manual review.')
    content=system.read(path)
    if any(len(line.split())>=2 and line.split()[1]==fields[1] for line in content.splitlines()):raise ValueError('This key already exists.')
    plan=Plan('Add public key for '+user,writes={str(path):content.rstrip()+'\n'+key.strip()+'\n'},modes={str(path):0o600},
        commands=[['chmod','0700',str(folder)],['chown','--',str(account.pw_uid)+':'+str(account.pw_gid),str(folder),str(path)]],
        details=['Adds one public key while preserving existing keys. Verify a new SSH session before changing authentication policies.'])
    if folder.exists():plan.metadata[str(folder)]=0o700
    return plan


def ssh_key_file(user,filename='authorized_keys'):
    """Only conventional local key files; custom sshd sources remain explicit."""
    if filename not in ('authorized_keys','authorized_keys2'):raise ValueError('Unknown SSH key filename')
    account=local_user(user);home=Path(account.pw_dir);path=home/'.ssh'/filename
    for item in [path,*path.parents]:
        if item.is_symlink():raise ValueError('Symlink SSH paths require manual review.')
    if not home.is_dir():raise ValueError('User home does not exist')
    if path.exists() and (not path.is_file() or path.stat().st_size>2*1024*1024):raise ValueError('Expected a regular key file, at most 2 MiB')
    return account,path


def parse_public_key(line):
    """Parse optional OpenSSH restrictions without rewriting them / Διατήρηση options."""
    if not line.strip() or line.lstrip().startswith('#'):return None
    try:fields=shlex.split(line,comments=False,posix=True)
    except ValueError:return None
    for index in (0,1):
        if len(fields)<index+2:continue
        kind,encoded=fields[index:index+2]
        if not kind.startswith(('ssh-','ecdsa-','sk-')):continue
        try:
            blob=base64.b64decode(encoded,validate=True);length=int.from_bytes(blob[:4],'big')
            if not length or length>256 or blob[4:4+length].decode()!=kind or len(blob)<length+8:continue
        except (ValueError,UnicodeError):continue
        fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
        return {'type':kind,'fingerprint':fingerprint,'comment':' '.join(fields[index+2:]),'restricted':bool(index),'blob':encoded}
    return None


def ssh_keys(user,filename='authorized_keys'):
    account,path=ssh_key_file(user,filename)
    content=path.read_bytes().decode('utf-8') if path.exists() else ''
    rows=[]
    for i,line in enumerate(content.splitlines(keepends=True)):
        key=parse_public_key(line)
        if key:rows.append({**key,'index':i,'line':line})
    return path,content,rows


def remove_ssh_key_plan(user,filename,index,expected_content):
    account,path=ssh_key_file(user,filename)
    if not path.exists():raise ValueError('Key file no longer exists')
    content=path.read_bytes().decode('utf-8')
    if content!=expected_content:raise ValueError('Key file changed; refresh before removing a key')
    lines=content.splitlines(keepends=True)
    if not 0<=index<len(lines) or not parse_public_key(lines[index]):raise ValueError('Select one recognized public-key row')
    selected=parse_public_key(lines[index]);del lines[index]
    expected=hashlib.sha256(content.encode()).hexdigest()
    def guard():
        _,current=ssh_key_file(user,filename)
        if not current.exists() or hashlib.sha256(current.read_bytes()).hexdigest()!=expected:
            raise ValueError('Key file changed before apply; refresh and retry')
    return Plan('Remove SSH public key for '+user,
        writes={str(path):''.join(lines)},modes={str(path):stat.S_IMODE(path.stat().st_mode)},guard=guard,
        critical=bool(system.ssh_connection()),secrets=True,
        commands=[['chown','--',str(path.stat().st_uid)+':'+str(path.stat().st_gid),str(path)]],
        details=[str(path),'Remove line '+str(index+1)+': '+selected['type']+' '+selected['fingerprint'],
                 'Only this row is removed. Other keys, restrictions, comments and line endings are preserved.',
                 'Keep this SSH session open and verify a NEW connection. Existing sessions are not revoked.',
                 'Other key files, AuthorizedKeysCommand and certificate authorities are outside this operation.'])
