"""Searchable checkbox lists / Επιλογές με Space, βελάκια, αναζήτηση και ακύρωση."""
import curses
import os
import sys
from . import console


def checklist(ui,title,entries,selected=(),locked=()):
    chosen=set(selected);locked=set(locked);query='';position=0
    if ui.basic or not sys.stdin.isatty() or os.environ.get('TERM','dumb')=='dumb':
        while True:
            rows=[(key,('[x] ' if key in chosen|locked else '[ ] ')+label,detail) for key,label,detail in entries]
            rows=[('__done__','Save selections','Return the selected entries.')]+rows
            value=ui.choose(title,rows)
            if value is None:raise console.Cancelled()
            if value=='__done__':return sorted(chosen)
            if value=='__refresh__' or value in locked:continue
            chosen.symmetric_difference_update({value})
    def render(screen):
        nonlocal query,position
        screen.keypad(True);screen.timeout(-1)
        if hasattr(curses,'set_escdelay'):curses.set_escdelay(35)
        normal,accent,highlight,warning=ui.palette(curses,screen)
        while True:
            screen.erase();h,w=screen.getmaxyx()
            def put(y,text,style=normal):
                try:screen.addnstr(y,2,text,max(1,w-4),style)
                except curses.error:pass
            if h<15 or w<52:
                put(0,'Resize terminal; Esc cancels.');screen.refresh()
                if screen.get_wch() in ('\x1b','\x03'):raise console.Cancelled()
                continue
            rows=[row for row in entries if query.casefold() in (row[0]+' '+row[1]).casefold()]
            position=min(position,max(0,len(rows)-1));capacity=h-9;offset=max(0,position-capacity+1)
            put(1,title,accent|curses.A_BOLD);put(3,'Search: '+query,accent)
            put(4,str(len(chosen|locked))+' selected · '+str(len(locked))+' included by continent · '+str(len(rows))+' results',warning)
            for index,row in enumerate(rows[offset:offset+capacity],offset):
                key,label,detail=row;marker='[x] ' if key in chosen|locked else '[ ] '
                put(6+index-offset,(marker+label+(' [continent]' if key in locked else '')).ljust(w-4),highlight if index==position else normal)
            if not rows:put(6,'No matching entries.')
            put(h-2,'↑/↓/PgUp/PgDn · Space: toggle · type: filter · Ctrl+U: clear · Enter: save · Esc: back',accent)
            screen.refresh();key=screen.get_wch()
            if key in ('\x1b','\x03','\x04'):raise console.Cancelled()
            if key in ('\n','\r',curses.KEY_ENTER):return sorted(chosen)
            if key==' ' and rows:
                value=rows[position][0]
                if value not in locked:chosen.symmetric_difference_update({value})
            elif key==curses.KEY_UP:position=max(0,position-1)
            elif key==curses.KEY_DOWN:position=min(max(0,len(rows)-1),position+1)
            elif key==curses.KEY_NPAGE:position=min(max(0,len(rows)-1),position+capacity)
            elif key==curses.KEY_PPAGE:position=max(0,position-capacity)
            elif key==curses.KEY_HOME:position=0
            elif key==curses.KEY_END:position=max(0,len(rows)-1)
            elif key in ('\x7f','\b',curses.KEY_BACKSPACE):query=query[:-1];position=0
            elif key=='\x15':query='';position=0
            elif isinstance(key,str) and key.isprintable() and len(query)<100:query+=key;position=0
    try:return curses.wrapper(render)
    except KeyboardInterrupt:raise console.Cancelled() from None
