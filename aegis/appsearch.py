"""Live, local catalog search / Φιλτράρισμα σε κάθε πλήκτρο χωρίς APT queries."""
import curses
import os
import sys
import textwrap


def matches(rows,query):
    terms=query.casefold().split()
    return [row for row in rows if all(term in (row[1]+' '+row[2]).casefold() for term in terms)]


def run(ui,rows):
    if ui.basic or not sys.stdin.isatty() or os.environ.get('TERM','dumb')=='dumb':
        query=ui.prompt('Search applications','Αναζήτηση εφαρμογών','')
        return ui.choose('Search results',matches(rows,query))
    state={'query':'','cursor':0,'pos':0}
    def render(screen):
        screen.keypad(True);screen.timeout(-1)
        if hasattr(curses,'set_escdelay'):curses.set_escdelay(35)
        normal,accent,selected,warning=ui.palette(curses,screen)
        while True:
            h,w=screen.getmaxyx();screen.erase()
            if h<15 or w<52:
                screen.addnstr(0,0,'Resize terminal; Esc cancels.',max(1,w-1));screen.refresh()
                if screen.get_wch() in ('\x1b','\x03'):return None
                continue
            result=matches(rows,state['query']);state['pos']=min(state['pos'],max(0,len(result)-1))
            def put(y,x,text,style=normal,width=None):
                try:screen.addnstr(y,x,str(text),min(width or w-x-1,w-x-1),style)
                except curses.error:pass
            put(1,2,'App Installer — Search',accent|curses.A_BOLD)
            put(2,2,ui.context,warning)
            start=max(0,state['cursor']-(w-12));visible=state['query'][start:start+w-10]
            put(4,2,('Search: '+visible).ljust(w-4),selected)
            put(5,2,str(len(result))+' / '+str(len(rows))+' applications · name / package / category / description',accent)
            capacity=h-10;offset=max(0,state['pos']-capacity+1);split=min(43,w//3) if w>=100 else w-3
            for i in range(offset,min(len(result),offset+capacity)):
                key,label,detail=result[i];active=i==state['pos'];style=selected if active else normal
                prefix='> ' if active else '  ';width=split-4
                if label.endswith(' [Installed]'):
                    badge='[Installed]';name=label[:-12];name=name[:max(1,width-len(badge)-1)]
                    put(7+i-offset,2,(prefix+name+' '+badge).ljust(split-2),style,split-2)
                    status=curses.color_pair(9 if active else 8)|curses.A_BOLD if ui.theme!='plain' and curses.has_colors() else style
                    put(7+i-offset,2+len(prefix)+len(name)+1,badge,status,len(badge))
                else:put(7+i-offset,2,(prefix+label).ljust(split-2),style,split-2)
            if not result:put(7,2,'No matching applications. Edit the search text.',warning)
            if result and w>=100:
                for y in range(6,h-3):put(y,split+1,'│',accent)
                lines=[]
                for line in result[state['pos']][2].splitlines():lines+=textwrap.wrap(line,w-split-7) or ['']
                for y,line in enumerate(lines[:h-10],7):put(y,split+4,line,normal,w-split-6)
            put(h-2,2,'Type to filter · ↑/↓/PgUp/PgDn results · Enter actions · Esc back',accent)
            try:curses.curs_set(1);screen.move(4,10+state['cursor']-start)
            except curses.error:pass
            screen.refresh();key=screen.get_wch()
            if key in ('\x1b','\x03'):return None
            if key in ('\n','\r',curses.KEY_ENTER):
                if result:return result[state['pos']][0]
                continue
            if key in (curses.KEY_UP,curses.KEY_DOWN,curses.KEY_PPAGE,curses.KEY_NPAGE):
                delta=-1 if key==curses.KEY_UP else 1 if key==curses.KEY_DOWN else -capacity if key==curses.KEY_PPAGE else capacity
                state['pos']=max(0,min(len(result)-1,state['pos']+delta));continue
            if key==curses.KEY_LEFT:state['cursor']=max(0,state['cursor']-1);continue
            if key==curses.KEY_RIGHT:state['cursor']=min(len(state['query']),state['cursor']+1);continue
            if key==curses.KEY_HOME:state['cursor']=0;continue
            if key==curses.KEY_END:state['cursor']=len(state['query']);continue
            position=state['cursor']
            if key in ('\b','\x7f',curses.KEY_BACKSPACE):
                if position:state['query']=state['query'][:position-1]+state['query'][position:];state['cursor']-=1
            elif key==curses.KEY_DC:state['query']=state['query'][:position]+state['query'][position+1:]
            elif key=='\x15':state['query']='';state['cursor']=0
            elif isinstance(key,str) and key.isprintable() and len(state['query'])<200:
                state['query']=state['query'][:position]+key+state['query'][position:];state['cursor']+=1
            state['pos']=0
    try:return curses.wrapper(render)
    except KeyboardInterrupt:return None
