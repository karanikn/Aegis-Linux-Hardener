"""Real-terminal regression: live dashboard -> idle submenu/dialog/pager.

Run from the project root: python3 tests/pty_timeout.py
No package, network, account or host configuration is changed.
"""
import fcntl
import os
import pty
import select
import struct
import subprocess
import termios
import time

CODE='''from aegis.ui import UI
from aegis import console
ui=UI()
def live(number):
    ui.choose('LIVE_'+str(number),[('x','Dashboard','demo')],panels={'x':lambda w,h:[('LIVE_READY_'+str(number),'normal')]})
live(1)
assert ui.choose('WAIT_SUBMENU',[('x','Choice','No timeout here')])=='x'
live(2)
assert console.ask('WAIT_DIALOG','saved')=='typed'
live(3)
ui.view('WAIT_PAGER','Read-only content')
live(4)
try:console.ask('WAIT_CANCEL','saved')
except console.Cancelled:pass
else:raise AssertionError('Expected cancellation')
print('ALL_IDLE_TRANSITIONS_PASSED')
'''
EXCHANGES=[(b'LIVE_READY_1',b'\n',0),(b'WAIT_SUBMENU',b'\n',0.8),
 (b'LIVE_READY_2',b'\n',0),(b'WAIT_DIALOG',b'typed\n',0.8),
 (b'LIVE_READY_3',b'\n',0),(b'WAIT_PAGER',b'q',0.8),
 (b'LIVE_READY_4',b'\n',0),(b'WAIT_CANCEL',b'\x1b',0.8)]


def main():
    master,slave=pty.openpty()
    fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',32,125,0,0))
    process=subprocess.Popen(['python3','-c',CODE],stdin=slave,stdout=slave,stderr=slave,env={**os.environ,'TERM':'xterm-256color'})
    os.close(slave);data=b'';stage=0;pending=None;offset=0;deadline=time.monotonic()+20
    try:
        while time.monotonic()<deadline:
            if select.select([master],[],[],0.025)[0]:
                try:data+=os.read(master,65536)
                except OSError:break
            if stage<len(EXCHANGES):
                trigger,response,delay=EXCHANGES[stage]
                if pending is None and trigger in data[offset:]:pending=time.monotonic()+delay
                if pending is not None and time.monotonic()>=pending:
                    assert process.poll() is None,'Window closed while waiting for user input'
                    os.write(master,response);stage+=1;offset=len(data);pending=None
            if process.poll() is not None:break
        process.wait(timeout=2)
        assert process.returncode==0,data[-1800:]
        assert stage==len(EXCHANGES),(stage,data[-1800:])
        assert b'ALL_IDLE_TRANSITIONS_PASSED' in data,data[-1800:]
        assert b'no input' not in data,data[-1800:]
    finally:
        if process.poll() is None:process.kill();process.wait()
        os.close(master)
    print('4 delayed-input transitions passed: submenu, input dialog, pager and Cancel after a live dashboard (800 ms idle each).')


if __name__=='__main__':main()
