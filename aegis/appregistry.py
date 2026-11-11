"""Persistent APT-only catalog entries / Προσαρμογή λίστας, όχι εκτέλεση scripts."""
import json
from pathlib import Path
import re
from . import categories
from .actions import Plan

PATH=Path('/etc/aegis-linux-hardener/app-catalog.json')
REMOVED_GUIDES={'pnana','psnet','watcher'}


def package_name(value):
    if not isinstance(value,str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{1,79}',value):
        raise ValueError('Use one Debian package name; no options, paths, version selectors or shell commands.')
    return value


def text(value,limit):
    if not isinstance(value,str) or not value.strip() or len(value)>limit or any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError('Use readable single-line text, maximum '+str(limit)+' characters.')
    return value.strip()


def entry(value):
    if not isinstance(value,dict):raise ValueError('Invalid application entry')
    package=package_name(value.get('package'))
    category=value.get('category')
    if category not in {name for name,_ in categories.GROUPS}:raise ValueError('Choose an existing category')
    command=value.get('command','')
    if not isinstance(command,str) or (command and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]{0,79}',command)):
        raise ValueError('Launcher must be one executable name without arguments or paths; leave blank for package details.')
    return {'key':'custom-'+package,'package':package,'label':text(value.get('label'),100),
            'description':text(value.get('description'),400),'category':category,'command':command}


def validate(value):
    if not isinstance(value,dict) or value.get('schema')!=1:raise ValueError('Invalid app-catalog schema')
    hidden=value.get('hidden',[]);custom=value.get('custom',[])
    if not isinstance(hidden,list) or len(hidden)>500 or any(not isinstance(x,str) or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,99}',x) for x in hidden):raise ValueError('Invalid hidden application list')
    if not isinstance(custom,list) or len(custom)>200:raise ValueError('Maximum 200 custom APT entries')
    rows=[entry(row) for row in custom]
    if len({r['key'] for r in rows})!=len(rows):raise ValueError('Duplicate custom package')
    return {'schema':1,'hidden':sorted(set(hidden)),'custom':rows}


def raw():
    if PATH.is_symlink():raise ValueError('Catalog config must not be a symlink')
    if not PATH.exists():return None
    if not PATH.is_file() or PATH.stat().st_size>256*1024:raise ValueError('Catalog config must be a regular file, maximum 256 KiB')
    return PATH.read_text()


def load():
    content=raw()
    return validate(json.loads(content)) if content is not None else {'schema':1,'hidden':[],'custom':[]}


def get(key):
    return next((row for row in load()['custom'] if row['key']==key),None)


def change_plan(operation,value,builtins):
    from . import catalog
    before=raw();state=load();known={row[0] for row in builtins}
    if operation=='add':
        row=entry(value)
        if any(x['key']==row['key'] for x in state['custom']):raise ValueError('This custom package is already listed')
        existing={catalog.package_for(key) for key in known}|{'docker.io','docker-ce-cli','docker-buildx-plugin','docker-compose-plugin'}
        if row['package'] in existing:raise ValueError('This package already has a built-in entry. Use Restore hidden entries if needed.')
        if not catalog.package_candidate(row['package']) and not catalog.system.installed(row['package']):
            raise ValueError('No APT candidate or installed package found. Refresh APT metadata and check the package name.')
        state['custom'].append(row)
    elif operation=='remove':
        key=value
        if key in known:
            if key in REMOVED_GUIDES:raise ValueError('This unsupported guide is already excluded')
            state['hidden']=sorted(set(state['hidden']+[key]))
        elif any(x['key']==key for x in state['custom']):state['custom']=[x for x in state['custom'] if x['key']!=key]
        else:raise ValueError('Unknown application entry')
    elif operation=='restore':
        if value not in known or value in REMOVED_GUIDES or value not in state['hidden']:raise ValueError('Choose a hidden supported built-in entry')
        state['hidden'].remove(value)
    else:raise ValueError('Unknown catalog operation')
    content=json.dumps(validate(state),ensure_ascii=False,indent=2)+'\n'
    def guard():
        if raw()!=before:raise ValueError('Catalog changed; refresh before applying this edit')
    return Plan('App Installer list: '+operation,writes={str(PATH):content},modes={str(PATH):0o644},guard=guard,
        details=['Changes the catalog list only. Does not install/uninstall any package.',
                 'Configuration survives Aegis updates and is backed up for Undo.',
                 'Custom entries use existing APT repositories; no arbitrary URLs, shell scripts or root launchers.'])
