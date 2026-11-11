"""App grouping inspired by awesome-tuis, with Linux administration additions."""
GROUPS=[
 ('Dashboards',{'btop','htop','glances','nmon','collectl','pydf','iotop','vnstat'}),
 ('Networking',{'bandwhich','iftop','iptraf','nload','nethogs','bmon','tcptrack','netdiag','nmap','netscanner','rtop','tcpdump','termshark','nmtui','psnet'}),
 ('System & hardware',{'lm-sensors','hddtemp','hwinfo-tui','ncdu'}),
 ('Security & administration',{'lynis','chkservice','rcconf','samba','logwatch','ccze'}),
 ('Development',{'lazyide'}),
 ('Docker/LXC/K8s',{'docker','docker-dash','dockmate','dtop','lazydocker','winboat'}),
 ('Editors',{'fresh','microneo','pnana'}),
 ('File Managers',{'mc','lf','rovr','unrar-free'}),
 ('Downloads',{'aria2','curl'}),
 ('Games',set()),('Libraries',set()),('Messaging',{'tmate'}),
 ('Miscellaneous',{'ucaresystem-core','watcher'}),('Multimedia',set()),
 ('Productivity',{'tmux','incron'}),('Screensavers',set()),
 ('Web',{'caddy','webmin','cockpit','ngrok','apachetop'}),
]


def category(key):
    return next((name for name,keys in GROUPS if key in keys),'Miscellaneous')
