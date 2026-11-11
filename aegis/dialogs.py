"""Centered theme-aware input dialogs / Ερωτήσεις σε πλαίσια με OK και Cancel."""
import curses
import textwrap
from . import console


def prompt(label,default=None,secret=False,choices=None):
    # Import lazily to avoid console/UI cycles / Αποφυγή κυκλικών imports.
    from .ui import UI
    values=[str(x) for x in choices or []]
    state={'text':'','cursor':0,'index':values.index(str(default)) if str(default) in values else 0,'chosen':False,'focus':0}
    def render(screen):
        screen.keypad(True)
        if hasattr(curses,'set_escdelay'):curses.set_escdelay(35)
        normal,accent,selected,warning=UI(console.LANGUAGE,console.THEME).palette(curses,screen)
        while True:
            h,w=screen.getmaxyx();screen.erase()
            if h<15 or w<32:
                screen.addnstr(0,0,'Resize terminal; Esc cancels.',max(1,w-1))
                screen.refresh();key=screen.get_wch()
                if key in ('\x1b','\x03'):raise console.Cancelled()
                continue
            width=min(w-4,92);body=width-6
            lines=textwrap.wrap(label,body)[:max(1,min(4,h-14))] or ['Aegis']
            height=min(h-2,12+len(lines));y=(h-height)//2;x=(w-width)//2
            box=screen.derwin(height,width,y,x);box.bkgd(' ',normal);box.erase();box.box()
            def put(row,text,style=normal):box.addnstr(row,3,str(text),body,style)
            put(0,' Aegis Linux Hardener ',accent|curses.A_BOLD)
            for row,line in enumerate(lines,2):put(row,line,accent|curses.A_BOLD)
            field=3+len(lines)
            # Never show the default for secret fields / Όχι μυστικά στην προεπιλογή.
            put(field-1,('Default: '+str(default)) if default is not None and not secret else '',curses.color_pair(7))
            value=state['text'] or (values[state['index']] if state['chosen'] and values else '')
            shown='*'*len(value) if secret else value
            pos=state['cursor'] if state['text'] else len(shown)
            start=max(0,pos-body+4)
            put(field,('> '+shown[start:start+body-3]).ljust(body),selected if state['focus']==0 else normal)
            if values:put(field+2,'↑/↓: '+' / '.join(values),accent)
            put(height-5,'Enter: default / OK · Tab: buttons',curses.color_pair(7))
            put(height-4,'Esc / Ctrl+C: Cancel',curses.color_pair(7))
            ok='[ OK ]';cancel='[ Cancel ]' if console.LANGUAGE=='en' else '[ Ακύρωση ]'
            box.addstr(height-2,4,ok,selected if state['focus']==1 else accent)
            box.addstr(height-2,18,cancel,selected if state['focus']==2 else accent)
            try:
                curses.curs_set(1 if state['focus']==0 else 0)
                if state['focus']==0:box.move(field,5+min(pos-start,body-4))
            except curses.error:pass
            screen.refresh();box.refresh()
            key=screen.get_wch()
            if key in ('\x1b','\x03','\x04'):raise console.Cancelled()
            if key=='\t':state['focus']=(state['focus']+1)%3;continue
            if key==curses.KEY_BTAB:state['focus']=(state['focus']-1)%3;continue
            if key in ('\n','\r',curses.KEY_ENTER):
                if state['focus']==2:raise console.Cancelled()
                return value
            if state['focus']:
                if key in (curses.KEY_LEFT,curses.KEY_RIGHT):state['focus']=2 if state['focus']==1 else 1
                continue
            if key in (curses.KEY_UP,curses.KEY_DOWN):
                if values:
                    state['index']=(state['index']+(-1 if key==curses.KEY_UP else 1))%len(values)
                    state['chosen']=True;state['text']='';state['cursor']=0
                elif default is not None and not secret:state['text']=str(default);state['cursor']=len(str(default))
            elif key==curses.KEY_LEFT:state['cursor']=max(0,state['cursor']-1)
            elif key==curses.KEY_RIGHT:state['cursor']=min(len(state['text']),state['cursor']+1)
            elif key==curses.KEY_HOME:state['cursor']=0
            elif key==curses.KEY_END:state['cursor']=len(state['text'])
            elif key in (curses.KEY_BACKSPACE,'\x7f','\b'):
                c=state['cursor']
                if c:state['text']=state['text'][:c-1]+state['text'][c:];state['cursor']-=1
            elif key==curses.KEY_DC:
                c=state['cursor'];state['text']=state['text'][:c]+state['text'][c+1:]
            elif key=='\x15':state['text']='';state['cursor']=0;state['chosen']=False
            elif isinstance(key,str) and key.isprintable() and len(state['text'])<8192:
                if state['chosen']:state['text']='';state['cursor']=0;state['chosen']=False
                c=state['cursor'];state['text']=state['text'][:c]+key+state['text'][c:];state['cursor']+=1
    return curses.wrapper(render)
