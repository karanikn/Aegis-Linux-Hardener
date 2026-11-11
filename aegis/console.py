"""Readable, cancellable prompts with optional arrow-key choices / Ερωτήσεις με επιστροφή."""
import functools
import getpass
import os
import select
import shutil
import sys
from . import themes

LANGUAGE='en'
THEME='slate'

class Cancelled(Exception):
    def __init__(self):super().__init__('Cancelled / Ακυρώθηκε')


def cancellable_menu(function):
    """Restart the same parent menu when a prompt/wizard is cancelled."""
    @functools.wraps(function)
    def wrapped(*args,**kwargs):
        while True:
            try:return function(*args,**kwargs)
            except (Cancelled,KeyboardInterrupt):print('\n'+paint('Back / Επιστροφή','muted'))
    return wrapped


def paint(text,color='cyan'):
    if not sys.stdout.isatty() or os.environ.get('NO_COLOR') or THEME=='plain':return str(text)
    role={'cyan':2,'blue':2,'green':5,'yellow':4,'red':6,'muted':7,'installed':5}.get(color,2)
    palette=themes.PALETTES[themes.valid(THEME)]
    # Role indexes match curses pairs, not tuple indexes.
    value={2:palette[2],4:palette[4],5:palette[5],6:palette[6],7:palette[7]}[role]
    return '\033[38;5;'+str(value)+'m'+str(text)+'\033[0m'


def section(title):
    print('\n'+paint('─'*68,'blue'));print(paint(title));print(paint('─'*68,'blue'))


def arrow_input(default=None,choices=None):
    """Small cbreak editor. Restores terminal on every exit; no shell/readline hooks."""
    import termios,tty
    fd=sys.stdin.fileno();original=termios.tcgetattr(fd)
    values=[str(x) for x in (choices or [])]
    index=values.index(str(default)) if str(default) in values else 0
    buffer=[];cursor=0;chosen=False
    def redraw():
        shown=''.join(buffer) if buffer else (values[index] if chosen and values else '')
        position=cursor if buffer else len(shown)
        width=max(12,shutil.get_terminal_size(fallback=(100,25)).columns-6)
        start=max(0,position-width+1);visible=shown[start:start+width]
        sys.stdout.write('\r\033[2K'+paint('  > ','green')+visible)
        remaining=len(visible)-(position-start)
        if remaining>0:sys.stdout.write('\033['+str(remaining)+'D')
        sys.stdout.flush()
    def key():
        byte=os.read(fd,1)
        if not byte:return ''
        if byte==b'\x1b':
            data=byte
            while select.select([fd],[],[],0.035)[0]:
                data+=os.read(fd,1)
                if len(data)>16 or data[-1:] in b'~ABCDHF':break
            return data.decode('ascii','ignore').replace('\x1bO','\x1b[')
        if byte[0]>=128:
            length=2 if byte[0]<224 else 3 if byte[0]<240 else 4
            byte+=os.read(fd,length-1)
        return byte.decode('utf-8','replace')
    try:
        tty.setcbreak(fd,termios.TCSANOW);redraw()
        while True:
            value=key()
            if value in ('','\x03','\x04','\x1b'):raise Cancelled()
            if value in ('\r','\n'):
                print()
                return ''.join(buffer) if buffer else (values[index] if chosen and values else '')
            if value in ('\x1b[A','\x1b[B','\t'):
                if values:
                    if chosen:index=(index+(-1 if value=='\x1b[A' else 1))%len(values)
                    # First arrow chooses the neighbor of the displayed default.
                    else:index=(index+(-1 if value=='\x1b[A' else 1))%len(values)
                    buffer=[];cursor=0;chosen=True
                elif default is not None:buffer=list(str(default));cursor=len(buffer)
            elif value=='\x1b[C':cursor=min(len(buffer),cursor+1)
            elif value=='\x1b[D':cursor=max(0,cursor-1)
            elif value in ('\x1b[H','\x1b[1~'):cursor=0
            elif value in ('\x1b[F','\x1b[4~'):cursor=len(buffer)
            elif value in ('\x7f','\b'):
                if cursor:cursor-=1;buffer.pop(cursor)
                chosen=False
            elif value=='\x1b[3~':
                if cursor<len(buffer):buffer.pop(cursor)
            elif value=='\x15':buffer=[];cursor=0;chosen=False
            elif value.isprintable() and not value.startswith('\x1b') and len(buffer)<8192:
                if chosen:buffer=[];cursor=0;chosen=False
                buffer[cursor:cursor]=list(value);cursor+=len(value)
            redraw()
    finally:termios.tcsetattr(fd,termios.TCSADRAIN,original);sys.stdout.write('\n');sys.stdout.flush()


def ask(label,default=None,secret=False,choices=None):
    modal=sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get('TERM','dumb')!='dumb' and os.environ.get('AEGIS_DIALOGS','1')!='0'
    display_label=label
    if not modal:print('\n'+paint(label))
    if not modal and not secret and default is not None and str(default):print(paint(('Προεπιλογή: ' if LANGUAGE=='el' else 'Default: ')+str(default),'muted'))
    if not modal and choices:print(paint('↑/↓ · type · Enter: default/selected · Esc: back | '+' / '.join(map(str,choices)),'muted'))
    elif not modal and not secret:print(paint('Enter: default · ↑: edit default · Esc/Ctrl+C or /back: return','muted'))
    while True:
        try:
            if modal:
                from .dialogs import prompt
                value=prompt(display_label,default,secret,choices)
            elif secret:value=getpass.getpass('  > ')
            elif sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get('TERM','dumb')!='dumb':value=arrow_input(default,choices)
            else:value=input(paint('  > ','green'))
        except (KeyboardInterrupt,EOFError):raise Cancelled() from None
        value=value.strip()
        if not secret and value.lower() in ('q','/back','/cancel'):raise Cancelled()
        if not value and default is not None:value=str(default)
        if choices:
            if list(choices)==['y','n']:
                value={'yes':'y','no':'n','ν':'y','ναι':'y','ο':'n','όχι':'n','οχι':'n'}.get(value.casefold(),value)
            canonical=next((str(item) for item in choices if str(item).casefold()==value.casefold()),None)
            if canonical is None:
                display_label=label+' — Choose one of: '+' / '.join(map(str,choices))
                if not modal:print(paint(display_label,'yellow'))
                continue
            return canonical
        return value


def confirm(label=None,default=True):
    label=label or ('Συνέχεια;' if LANGUAGE=='el' else 'Continue?')
    while True:
        value=ask(label+(' [Y/n · Enter=yes]' if default else ' [y/N · Enter=no]'),choices=['y','n'],default='y' if default else 'n').lower()
        if not value:return default
        if value in ('y','yes','ν','ναι'):return True
        if value in ('n','no','ο','όχι','οχι'):return False
        print(paint('Please answer y or n / Απάντησε y ή n.','yellow'))


def pause():
    print('\n'+paint('─'*68,'blue'))
    try:ask('Enter για επιστροφή…' if LANGUAGE=='el' else 'Press Enter to return…')
    except (Cancelled,KeyboardInterrupt):return
