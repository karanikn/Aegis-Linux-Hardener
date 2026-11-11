"""Additional security tools: install and inspect without implicit blocking."""
import json
import sys
from . import system
from .actions import ENTRY
from .catalog import package_plan, package_candidate

TOOLS={
 'portsentry':('PortSentry','Port-scan detection and optional response.',
              'Detection can trigger route/firewall blocks. Review monitored ports and trusted networks before activation.',
              ['/etc/portsentry','/etc/default/portsentry'],'https://packages.debian.org/bookworm/portsentry'),
 'knockd':('knockd','Run configured commands after a recognized port-knock sequence.',
           'Knocking is not SSH authentication. Aegis never closes SSH or enables example firewall commands.',
           ['/etc/knockd.conf','/etc/default/knockd'],'https://www.zeroflux.org/projects/knock'),
 'shorewall':('Shorewall','Configure netfilter firewall/router policies.',
              'Alternative firewall manager. Do not layer it blindly over UFW/firewalld/Docker rules. Activation needs a reviewed topology and console access.',
              ['/etc/shorewall','/etc/default/shorewall'],'https://shorewall.org/'),
}


def information(key):
    label,purpose,note,paths,url=TOOLS[key]
    return '\n'.join([label,'',purpose,'',note,'','Install behavior',
       'New installations are kept stopped/disabled. Existing installs are not changed.',
       'No firewall rule, packet block or SSH restriction is enabled automatically.',
       '','Configuration paths']+paths+['','Source',url])


def install_plan(key):
    if key not in TOOLS:raise ValueError('Unknown security tool')
    if system.installed(key):raise ValueError('Already installed; use status/configuration review. Existing setup is preserved.')
    if system.service(key)=='active':raise ValueError('An active external instance exists; inspect it manually before installation.')
    if not package_candidate(key):raise ValueError('No APT candidate for '+key+' in current metadata. Refresh APT; no foreign suite is added.')
    plan=package_plan([key],'Install '+TOOLS[key][0]+' (inactive)')
    plan.suppress_services=True
    plan.backup_paths=TOOLS[key][3]
    old=system.service_state(key+'.service')
    plan.commands=[['systemctl','disable',key+'.service']]
    plan.rollback_commands=[[sys.executable,str(ENTRY),'--restore-service-state',json.dumps(old)]]
    plan.details += [TOOLS[key][2],'New service startup is suppressed during APT; the new service is disabled afterward.',
                     'Enable/configure only after reviewing its own policy. This action does not replace your active firewall.']
    return plan
