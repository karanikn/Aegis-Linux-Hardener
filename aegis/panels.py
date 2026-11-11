"""Compact read-only sidebar / Συνοπτικές πληροφορίες χωρίς καθυστέρηση στα πλήκτρα."""
import threading
import time
import textwrap
from . import system


def meter(label, value, total='', width=55):
    value = max(0.0, min(100.0, float(value)))
    size = max(6, min(26, width-28))
    filled = round(size*value/100)
    return ('{} {:5.1f}% {}{} {}'.format(label.ljust(5), value, '━'*filled, '·'*(size-filled), total),
            'danger' if value >= 90 else 'warning' if value >= 75 else 'good')


def dashboard_rows(s, width=70):
    """Pure formatting. Only real filesystems are graphed; runtime mounts summarized."""
    m=s['memory']; rows=[]
    def add(text, role='normal'): rows.append((text,role))
    add(s['hostname']+'  |  '+s['os'],'accent')
    add('Kernel '+s['kernel']+'  |  '+s['architecture'])
    for text in textwrap.wrap('CPU '+s['cpu']+' | '+str(s['cpu_threads'])+' threads',max(20,width)):add(text)
    rows.append(meter('CPU',s['cpu_pct'],width=width))
    rows.append(meter('RAM',m['used_pct'],'/ {:.2f} GiB'.format(m['total_gib']),width))
    rows.append(meter('Swap',m['swap_pct'],'/ {:.2f} GiB'.format(m['swap_gib']),width))
    add('Load '+ ' / '.join('{:.2f}'.format(v) for v in s['load'])+' | Uptime {:.1f}h'.format(s['uptime_hours']))
    add('Virtualization: '+s['virtualization']+' | Desktop: '+('yes' if s['desktop_detected'] else 'no'))
    add('NETWORK / DNS','accent')
    for line in s['addresses'].splitlines():
        fields=line.split()
        if fields and fields[0]=='lo':continue
        add(line)
    for line in s['default_route'].splitlines():add(line)
    names=[line.split(None,1)[1] for line in s['dns'].splitlines() if line.startswith('nameserver ')]
    add('DNS '+', '.join(names) if names else 'DNS: no nameservers reported')
    add('FILESYSTEMS / INODES','accent')
    visible=[f for f in s['filesystems'] if not (f['path']=='/dev' or f['path'].startswith(('/dev/','/run','/sys','/proc')))]
    for f in visible:
        inode='n/a' if f['inode_pct'] is None else '{:.1f}%'.format(f['inode_pct'])
        rows.append(meter(f['path'],f['used_pct'],'{:.1f}G · i {}'.format(f['gib'],inode),width))
    hidden=len(s['filesystems'])-len(visible)
    if hidden:add('{} runtime mounts omitted; Enter opens full dashboard'.format(hidden),'muted')
    add('SECURITY / SERVICES','accent')
    add('SSH: {} | Fail2Ban: {}'.format(s['ssh'],s['fail2ban']))
    add('AppArmor: {} | Telegram: {}'.format(s['apparmor'],s['alerts']))
    add('Firewall: '+s['firewall'].replace('\n',' | '))
    add('Reboot required: '+('YES' if s['reboot_required'] else 'no'),'warning' if s['reboot_required'] else 'good')
    add('Updated '+s['timestamp']+' · refresh ~5s','muted')
    return rows


class LiveDashboard:
    """One collector in a daemon thread; rendering/arrow keys never block on I/O."""
    def __init__(self):
        self.snapshot=None;self.error=None;self.updated=0;self.running=False
        self.lock=threading.Lock()
    def collect(self):
        try:self.snapshot=system.snapshot();self.error=None
        except Exception as error:self.error=str(error)
        finally:self.updated=time.monotonic();self.running=False
    def rows(self,width,height):
        with self.lock:
            if not self.running and time.monotonic()-self.updated>=5:
                self.running=True
                threading.Thread(target=self.collect,daemon=True).start()
        if self.snapshot:return dashboard_rows(self.snapshot,width)
        return [('SYSTEM OVERVIEW','accent'),(self.error or 'Collecting system information…','muted')]
