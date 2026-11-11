"""Real terminal live-search check; no APT calls or program actions."""
import fcntl
import os
import pty
import select
import struct
import subprocess
import termios
import time

CODE='''from aegis.ui import UI
from aegis import appsearch,system
ui=UI()
ui.choose('Live',[('x','Dashboard','demo')],panels={'x':lambda w,h:[('LIVE_SEARCH_READY','normal')]})
def forbidden(*a,**k):raise AssertionError('Search must not run APT or system commands')
system.command=forbidden
rows=[('disk','Disk Tool [Installed]','DISK_DETAIL_READY category: Dashboards'),('packet','Packet Tool','PACKET_DETAIL_READY category: Networking'),('edit','Editor Tool','EDITOR_DETAIL_READY category: Editors')]
result=appsearch.run(ui,rows)
assert result=='packet',result
print('SEARCH_SELECTED_PACKET')
result=appsearch.run(ui,rows)
assert result is None,result
print('SEARCH_CANCELLED')
'''


def main():
    exchanges=[(b'LIVE_SEARCH_READY',b'\n',0),
      (b'App Installer ',b'zzzz',0.5),
      (b'No matching applications.',b'\x15packet',0.3),
      (b'PACKET_DETAIL_READY',b'\n',0.8),
      (b'SEARCH_SELECTED_PACKET',b'\x1b',0.4)]
    master,slave=pty.openpty();fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',32,125,0,0))
    process=subprocess.Popen(['python3','-c',CODE],stdin=slave,stdout=slave,stderr=slave,env={**os.environ,'TERM':'xterm-256color'})
    os.close(slave);data=b'';stage=0;offset=0;pending=None;deadline=time.monotonic()+15
    try:
        while time.monotonic()<deadline:
            if select.select([master],[],[],0.025)[0]:
                try:data+=os.read(master,65536)
                except OSError:break
            if stage<len(exchanges):
                trigger,response,delay=exchanges[stage]
                if pending is None and trigger in data[offset:]:pending=time.monotonic()+delay
                if pending is not None and time.monotonic()>=pending:
                    assert process.poll() is None,data[-1000:]
                    os.write(master,response);offset=len(data);stage+=1;pending=None
            if process.poll() is not None:break
        try:process.wait(timeout=2)
        except subprocess.TimeoutExpired:raise AssertionError(('stage',stage,'output',data[-3500:])) from None
        assert process.returncode==0,data[-1500:]
        assert stage==len(exchanges),(stage,data[-1500:])
        assert b'SEARCH_CANCELLED' in data,data[-1500:]
        assert b'no input' not in data,data[-1500:]
    finally:
        if process.poll() is None:process.kill();process.wait()
        os.close(master)
    print('Live search PTY passed: idle after dashboard, no-match, clear/refilter before Enter, correct selection and Esc; no APT/system queries during typing.')


if __name__=='__main__':main()
