"""Known missing requirements: reviewed install, recheck, then resume exactly once.
EL: Δεν γίνεται retry αποτυχημένων αλλαγών· οι εξαρτήσεις ελέγχονται πριν την ενέργεια.
"""
import importlib
import getpass
import importlib.util
from pathlib import Path
import shutil
from . import actions,catalog,console,lynis,system

COMMAND_PACKAGES={
 'auditctl':('auditd','auditd'),'augenrules':('auditd','auditd'),
 'aa-status':('apparmor-utils',None),'aa-enforce':('apparmor-utils',None),'aa-complain':('apparmor-utils',None),
 'lynis':('lynis',None),'lsof':('lsof','lsof'),'debsums':('debsums','debsums'),
 'needrestart':('needrestart','needrestart'),'apt-show-versions':('apt-show-versions','apt-show-versions'),
 'debsecan':('debsecan','debsecan'),'aide':('aide','aide'),'aideinit':('aide','aide'),
 'accton':('acct','accounting'),'sar':('sysstat','sysstat'),'updatedb':('plocate','locate'),
 'rsyslogd':('rsyslog',None),'ss':('iproute2',None),'ip':('iproute2',None),
 'fail2ban-client':('fail2ban',None),'ufw':('ufw',None),'nmtui':('network-manager',None),
}


def command_requirement(command):
    package,profile=COMMAND_PACKAGES[command]
    return {'name':command,'commands':[command],'packages':[package],'profile':profile}


def requirements(request):
    """Only fixed recipes selected by known action IDs; never accept package/argv input."""
    kind=request.get('kind');rows=[]
    if kind=='lynis-control':
        control=request.get('control')
        commands={'audit-watches':['auditctl','augenrules'],'aide-init':['aideinit'],
                  'accounting':['accton'],'sysstat':['sar'],'locate-update':['updatedb'],
                  'remote-logging':['rsyslogd']}.get(control,[])
        rows=[command_requirement(c) for c in commands]
        if control=='remote-logging' and request.get('tls'):
            rows.append({'name':'rsyslog TLS module','packages':['rsyslog-gnutls'],'profile':'rsyslog-tls','commands':[]})
        if control=='password-quality':rows=[{'name':'Password quality (libpam-pwquality)','packages':['libpam-pwquality'],'profile':'pwquality','commands':[]}]
    elif kind=='security-inspect':
        command={'needrestart':'needrestart','debsums':'debsums','deleted':'lsof','audit':'auditctl',
                 'versions':'apt-show-versions','aide':'aide','vulnerabilities':'debsecan'}.get(request.get('check'))
        if command:rows=[command_requirement(command)]
    elif kind in ('lynis','apparmor-status','apparmor','fail2ban','ban','unban','ufw','nmtui'):
        command={'lynis':'lynis','apparmor-status':'aa-status','apparmor':'aa-'+str(request.get('mode')),
                 'fail2ban':'fail2ban-client','ban':'fail2ban-client','unban':'fail2ban-client','ufw':'ufw','nmtui':'nmtui'}[kind]
        if command in COMMAND_PACKAGES:rows=[command_requirement(command)]
        if kind=='nmtui':rows[0]['app']='nmtui'
    elif kind in ('network-configure','network'):
        rows=[command_requirement('ip')]
        if list(Path('/etc/netplan').glob('*.yaml')):
            rows.append({'name':'Netplan YAML helper','packages':['python3-yaml'],'commands':[],'module':'yaml'})
    elif kind=='open-app':
        key=request.get('app')
        if key in {r[0] for r in catalog.all_apps()}:rows=[{'name':key,'app':key,'commands':[],'packages':[]}]
    elif kind=='logs-browser':rows=[{'name':'ccze log colors','app':'ccze','commands':[],'packages':[],'optional':True}]
    elif kind=='maintenance' and request.get('mode')=='ucare':rows=[{'name':'uCareSystem Core','app':'ucaresystem-core','commands':[],'packages':[]}]
    elif kind=='monitor-command' and request.get('command')=='ss':rows=[command_requirement('ss')]
    return rows


def available(row):
    if row.get('module'):
        importlib.invalidate_caches()
        return importlib.util.find_spec(row['module']) is not None
    if row.get('app'):return bool(catalog.app_version(row['app']))
    if row.get('commands'):return all(shutil.which(command) for command in row['commands'])
    return all(system.installed(package) for package in row['packages'])


def ensure(request,origin=''):
    for row in requirements(request):
        if available(row):continue
        console.section('Missing requirement / Λείπει απαραίτητο εργαλείο: '+row['name'])
        if row.get('app'):plan=catalog.app_plan(row['app'],request.get('user') or getpass.getuser())
        elif row.get('profile'):plan=lynis.install_profile(row['profile'])
        else:plan=catalog.package_plan(row['packages'])
        plan.title='Install missing requirement and continue: '+row['name']
        plan.details += ['After successful installation Aegis rechecks the requirement and resumes the selected action once.',
                         'n cancels this installation. The original action is skipped when its requirement is mandatory.']
        if not actions.apply(plan,origin):
            print('Installation cancelled; '+('continuing with plain logs.' if row.get('optional') else 'the selected action was not run.'))
            if row.get('optional'):continue
            return False
        importlib.invalidate_caches()
        if not available(row):
            raise RuntimeError(row['name']+' is still unavailable after installation. The selected action was not run; review package/PATH/Python compatibility.')
    return True
