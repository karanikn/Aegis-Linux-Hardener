import os,pty,subprocess,select,time,signal,fcntl,termios,struct

def check(code,trigger,response,expected):
    master,slave=pty.openpty();fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',32,125,0,0))
    process=subprocess.Popen(['python3','-c',code],stdin=slave,stdout=slave,stderr=slave,env={**os.environ,'TERM':'xterm-256color'})
    os.close(slave);data=b'';sent=False;deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        if select.select([master],[],[],.1)[0]:
            try:data+=os.read(master,65536)
            except OSError:break
        if not sent and trigger in data:
            if response=='SIGINT':process.send_signal(signal.SIGINT)
            else:os.write(master,response)
            sent=True
        if process.poll() is not None:
            try:
                while select.select([master],[],[],.05)[0]:data+=os.read(master,65536)
            except OSError:pass
            break
    if process.poll() is None:
        try:process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill();process.wait();raise RuntimeError('PTY timeout: '+repr(data[-800:]))
    os.close(master)
    assert expected in data,(expected,repr(data[-1500:]))
    assert process.returncode==0,repr(data[-1500:])
    return data

prompt="""from aegis import console
import termios,sys
original=termios.tcgetattr(sys.stdin.fileno())
try: print('RESULT='+console.ask('THEME_PROMPT','slate',choices=['slate','blue','nord','dracula']))
except console.Cancelled: print('CANCELLED')
print('TERM_RESTORED='+str(termios.tcgetattr(sys.stdin.fileno())==original))
"""
check(prompt,b'Enter: default',b'\n',b'RESULT=slate')
check(prompt,b'Enter: default',b'\x1bOB\n',b'RESULT=blue')
check(prompt,b'Enter: default',b'nord\n',b'RESULT=nord')
check(prompt,b'Enter: default',b'\x1b',b'CANCELLED')
check(prompt,b'Enter: default','SIGINT',b'TERM_RESTORED=True')
wizard="""import importlib.util
from unittest.mock import Mock
from aegis.ui import UI
spec=importlib.util.spec_from_file_location('entry','aegis.py');app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)
app.prepare_dependencies=lambda *args:True
app.catalog.app_version=lambda *args:None
app.system.installed=lambda *args:None
app.system.command=lambda *args:(0,'[]','')
app.networking.interfaces=lambda:[{'name':'ens192','state':'UP','addresses':['192.0.2.10/24'],'mac':'demo'}]
app.do=Mock()
class WizardUI(UI):
    visits=0
    def choose(self,title,entries,**kwargs):
        if title=='Network Settings':
            self.visits+=1
            return 'configure' if self.visits==1 else None
        if title=='Select network interface':return 'ens192'
        if title=='IPv4 mode':return 'static'
        raise RuntimeError('Unexpected selector '+title)
ui=WizardUI('en','slate');app.network_menu(ui)
assert ui.visits==2
app.do.assert_not_called()
print('WIZARD_CANCEL_RETURNED_WITHOUT_ACTION')
"""
check(wizard,b'Enter: default',b'\x1b',b'WIZARD_CANCEL_RETURNED_WITHOUT_ACTION')
check(wizard,b'Enter: default','SIGINT',b'WIZARD_CANCEL_RETURNED_WITHOUT_ACTION')
check(prompt,b'Enter: default',b'\t\t\n',b'CANCELLED')
secret="from aegis import console;print('SECRET_LENGTH='+str(len(console.ask('TOKEN_DIALOG',secret=True))))"
assert b'test-secret-value' not in check(secret,b'Enter: default',b'test-secret-value\n',b'SECRET_LENGTH=17')
print('9 real modal PTY checks passed: Enter, arrows, typing, Esc, Ctrl+C, Cancel button, secrets, terminal restoration, network-wizard back.')
