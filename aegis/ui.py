"""SSH-friendly terminal UI / Έγχρωμο TUI χωρίς pip dependencies."""
import json
import os
from pathlib import Path
import sys
import textwrap
from . import VERSION, TITLE, TAGLINE, system, console, themes


GREEK = {
 'App Installer — categories':'Εγκατάσταση εφαρμογών — κατηγορίες',
 'Search applications':'Αναζήτηση εφαρμογών', 'Manage App Installer list':'Διαχείριση λίστας εφαρμογών',
 'Add APT application':'Προσθήκη εφαρμογής APT', 'Remove entry / hide built-in':'Αφαίρεση / απόκρυψη καταχώρισης',
 'Restore hidden built-in entry':'Επαναφορά κρυμμένης εφαρμογής', 'View catalog configuration':'Προβολή ρυθμίσεων καταλόγου',
 'User Management':'Διαχείριση χρηστών', 'Share Management':'Διαχείριση κοινοχρήστων',
 'Logs':'Καταγραφές / Logs', 'Help':'Βοήθεια',
 'Dashboard': 'Επισκόπηση συστήματος', 'System Monitor': 'Παρακολούθηση συστήματος',
 'Security & Hardening': 'Ασφάλεια & Hardening', 'Fail2Ban Manager': 'Διαχείριση Fail2Ban',
 'Firewall Manager': 'Διαχείριση Firewall', 'App Installer': 'Εγκατάσταση εφαρμογών',
 'Maintenance': 'Συντήρηση', 'Reports & History': 'Αναφορές & Ιστορικό', 'Settings': 'Ρυθμίσεις',
 'Main menu': 'Κεντρικό μενού', 'Network Settings': 'Ρυθμίσεις δικτύου',
 'Lynis recommendations / controls': 'Προτάσεις / έλεγχοι Lynis', 'Undo actions / backups': 'Αναίρεση ενεργειών / backups', 'Top RAM processes': 'Διεργασίες με υψηλή RAM',
 'Top CPU processes': 'Διεργασίες με υψηλή CPU', 'Listening ports': 'Θύρες σε ακρόαση',
 'Connections': 'Συνδέσεις', 'Failed services': 'Αποτυχημένες υπηρεσίες',
 'Docker containers': 'Docker containers', 'Filesystems': 'Συστήματα αρχείων',
 'Open btop': 'Άνοιγμα btop', 'Open ncdu (read-only)': 'Άνοιγμα ncdu (μόνο ανάγνωση)',
 'Status / jails': 'Κατάσταση / jails', 'Install Fail2Ban': 'Εγκατάσταση Fail2Ban',
 'Configure protection': 'Ρύθμιση προστασίας', 'Inspect jail': 'Προβολή jail',
 'Ban IP': 'Αποκλεισμός IP', 'Unban IP': 'Άρση αποκλεισμού IP',
 'Status / existing rules': 'Κατάσταση / υπάρχοντες κανόνες', 'Install UFW': 'Εγκατάσταση UFW',
 'Allow source to port': 'Επιτρεπόμενη πηγή προς θύρα', 'Enable UFW with SSH access': 'Ενεργοποίηση UFW με πρόσβαση SSH',
 'Security overview': 'Επισκόπηση ασφάλειας', 'Run Lynis audit': 'Έλεγχος μέσω Lynis',
 'SSH: block root password login': 'SSH: απαγόρευση root password login',
 'SSH: public keys only': 'SSH: σύνδεση μόνο με κλειδιά', 'SSH: authentication limits': 'SSH: όρια ταυτοποίησης',
 'Kernel/filesystem baseline': 'Βασικές ρυθμίσεις kernel/filesystem',
 'AppArmor status / profiles': 'Κατάσταση / profiles AppArmor',
 'Install AppArmor utilities': 'Εγκατάσταση εργαλείων AppArmor',
 'AppArmor: choose profile mode': 'AppArmor: επιλογή λειτουργίας profile',
 'Automatic security updates': 'Αυτόματες ενημερώσεις ασφάλειας',
 'Install / reconfigure': 'Εγκατάσταση / επαναρύθμιση', 'Status': 'Κατάσταση',
 'Send test': 'Αποστολή δοκιμής', 'Worker logs': 'Logs υπηρεσίας', 'Uninstall alerts': 'Αφαίρεση ειδοποιήσεων',
 'Available updates': 'Διαθέσιμες ενημερώσεις', 'Refresh APT metadata': 'Ανανέωση καταλόγου APT',
 'Upgrade system packages': 'Αναβάθμιση πακέτων συστήματος', 'Clean APT package cache': 'Καθαρισμός cache πακέτων',
 'Run uCareSystem Core': 'Εκτέλεση uCareSystem Core', 'Theme': 'Χρωματικό θέμα',
 'Uninstall Aegis': 'Αφαίρεση Aegis', 'About / update': 'Πληροφορίες / ενημέρωση',
 'Export system report': 'Εξαγωγή αναφοράς συστήματος', 'Change history / backups': 'Ιστορικό αλλαγών / backups',
 'Restore a change': 'Επαναφορά αλλαγής', 'Install FreeRDP 3 client': 'Εγκατάσταση πελάτη FreeRDP 3',
 'Docker: grant desktop user access': 'Docker: πρόσβαση χρήστη desktop',
}


class UI:
    def __init__(self, language='en', theme=None, basic=False):
        self.language, self.theme, self.basic = language, themes.valid(theme or console.THEME), basic
        console.THEME=self.theme
        self.positions = {}
        os.environ.setdefault('ESCDELAY', '35')
        self.refresh_context()

    def refresh_context(self):
        info = system.os_release()
        self.context = '{} | {} | {} | {} CPU'.format(system.socket.gethostname(),
            info.get('PRETTY_NAME', 'Linux'), system.platform.machine(), os.cpu_count())

    def t(self, english, greek):
        return greek if self.language == 'el' else english

    def palette(self, curses, screen):
        if self.theme == 'plain' or not curses.has_colors(): return (0, 0, curses.A_REVERSE, curses.A_BOLD)
        curses.start_color()
        rich = curses.COLORS >= 256
        colors=themes.PALETTES[self.theme]
        if rich:bg,fg,accent,selection,warn,good,bad,muted,badge=colors
        else:bg,fg,accent,selection,warn,good,bad,muted,badge=(curses.COLOR_BLACK,curses.COLOR_WHITE,curses.COLOR_CYAN,curses.COLOR_BLUE,curses.COLOR_YELLOW,curses.COLOR_GREEN,curses.COLOR_RED,curses.COLOR_WHITE,curses.COLOR_GREEN)
        for n,foreground,background in [(1,fg,bg),(2,accent,bg),(3,fg,selection),(4,warn,bg),(5,good,bg),(6,bad,bg),(7,muted,bg),(8,good,bg),(9,badge,selection)]:
            curses.init_pair(n,foreground,background)
        screen.bkgd(' ', curses.color_pair(1))
        return tuple(curses.color_pair(n) for n in (1, 2, 3, 4))

    def choose(self, title, entries, panels=None):
        """entries: (id, title, explanation). No mutation on mere selection."""
        if self.language == 'el':
            title = GREEK.get(title, title)
            entries = [(key, GREEK.get(label, label), detail) for key, label, detail in entries]
        if not entries: return None
        if self.basic or not sys.stdin.isatty() or os.environ.get('TERM', 'dumb') == 'dumb':
            return self.basic_choose(title, entries)
        try:
            import curses
            def render(screen):
                curses.curs_set(0)
                if hasattr(curses, 'set_escdelay'): curses.set_escdelay(35)
                if hasattr(screen, 'keypad'): screen.keypad(True)
                normal, accent, selected, warning = self.palette(curses, screen)
                pos = min(self.positions.get(title, 0), len(entries)-1)
                panel_offset=0;panel_focus=False
                if hasattr(screen,'timeout'):screen.timeout(200 if panels else -1)
                while True:
                    screen.erase()
                    h, w = screen.getmaxyx()
                    if h < 15 or w < 52:
                        raise RuntimeError('Terminal too small; using basic menu')
                    def line(y, x, value, attr=normal, width=None):
                        try: screen.addnstr(y, x, value, max(0, min(width or w-x-1, w-x-1)), attr)
                        except curses.error: pass
                    line(0, 2, TITLE + '  v' + VERSION, accent | curses.A_BOLD)
                    line(1, 2, TAGLINE, normal)
                    line(3, 2, self.context, warning)
                    line(5, 2, title, accent | curses.A_BOLD)
                    split = min(43, w // 3) if w >= 100 else w-3
                    capacity = h - 10
                    start = max(0, pos-capacity+1)
                    for index in range(start,min(len(entries),start+capacity)):
                        y=7+index-start;is_selected=index==pos;attr=selected if is_selected else normal
                        label=entries[index][1];prefix='> ' if is_selected else '  ';width=split-4
                        match=__import__('re').search(r'\s*\[Installed\]$',label,__import__('re').I)
                        if match:
                            badge='[Installed]';name=label[:match.start()]
                            available=max(1,width-len(badge)-1)
                            name=name if len(name)<=available else name[:max(0,available-1)]+'…'
                            line(y,2,(prefix+name+' '+badge).ljust(split-2),attr,split-2)
                            badge_attr=curses.color_pair(9 if is_selected else 8)|curses.A_BOLD if self.theme!='plain' and curses.has_colors() else attr|curses.A_BOLD
                            line(y,2+len(prefix)+len(name)+1,badge,badge_attr,len(badge))
                        else:line(y,2,(prefix+label).ljust(split-2),attr,split-2)
                    if w >= 100:
                        for y in range(6, h-3): line(y, split+1, '│', accent)
                        panel_width=max(15,w-split-7)
                        provider=(panels or {}).get(entries[pos][0])
                        headings={'What it does','Installation / status','Example','Requirements / notes','Important','Official source','Source-build procedure','Install behavior','Configuration paths','Source'}
                        source=provider(panel_width,h-10) if provider else [(x,'accent' if i==0 or x in headings else 'normal') for i,x in enumerate(entries[pos][2].splitlines())]
                        details=[]
                        for text,role in source:
                            details.extend((part,role) for part in (textwrap.wrap(str(text),panel_width,replace_whitespace=False) or ['']))
                        panel_offset=min(panel_offset,max(0,len(details)-(h-10)))
                        roles={'normal':normal,'accent':accent|curses.A_BOLD,'warning':warning,
                               'good':curses.color_pair(5) if self.theme!='plain' and curses.has_colors() else normal,
                               'danger':curses.color_pair(6) if self.theme!='plain' and curses.has_colors() else warning,
                               'muted':curses.color_pair(7) if self.theme!='plain' and curses.has_colors() else normal}
                        for row,(text,role) in enumerate(details[panel_offset:panel_offset+h-10],7):line(row,split+4,text,roles.get(role,normal))
                        if len(details)>h-10:
                            line(h-3,split+4,('INFO' if panel_focus else 'Tab: info')+' | '+str(panel_offset+1)+'–'+str(min(len(details),panel_offset+h-10))+'/'+str(len(details)),accent)
                    elif entries:
                        line(h-3, 2, entries[pos][2], warning)
                    line(h-2, 2, self.t('↑↓/PgUp/PgDn Move  Home/End  Enter Select  Esc/q Back  r Refresh', '↑↓/PgUp/PgDn Κίνηση  Home/End  Enter Επιλογή  Esc/q Πίσω  r Ανανέωση'), accent)
                    screen.refresh()
                    key = screen.getch()
                    if key == -1:continue
                    if key == 9 and w>=100:
                        panel_focus=not panel_focus
                        continue
                    if panel_focus and key in (curses.KEY_UP,curses.KEY_DOWN,curses.KEY_NPAGE,curses.KEY_PPAGE,curses.KEY_HOME,curses.KEY_END):
                        if key==curses.KEY_UP:panel_offset=max(0,panel_offset-1)
                        elif key==curses.KEY_DOWN:panel_offset+=1
                        elif key==curses.KEY_NPAGE:panel_offset+=capacity
                        elif key==curses.KEY_PPAGE:panel_offset=max(0,panel_offset-capacity)
                        elif key==curses.KEY_HOME:panel_offset=0
                        elif key==curses.KEY_END:panel_offset=max(0,len(details)-capacity)
                        continue
                    if key in (curses.KEY_UP, ord('k')): pos = (pos-1) % max(1, len(entries))
                    elif key in (curses.KEY_DOWN, ord('j')): pos = (pos+1) % max(1, len(entries))
                    elif key == curses.KEY_NPAGE: pos = min(len(entries)-1, pos + capacity)
                    elif key == curses.KEY_PPAGE: pos = max(0, pos - capacity)
                    elif key == curses.KEY_HOME: pos = 0
                    elif key == curses.KEY_END: pos = len(entries)-1
                    elif key in (10, 13) and entries:
                        self.positions[title] = pos
                        return entries[pos][0]
                    elif key in (27, ord('q')):
                        self.positions[title] = pos
                        return None
                    elif key == ord('r'): return '__refresh__'
                    if not panel_focus:panel_offset=0
            return curses.wrapper(render)
        except KeyboardInterrupt:return None
        except Exception:
            return self.basic_choose(title, entries)

    def basic_choose(self, title, entries):
        print('\n' + TITLE + ' v' + VERSION + '\n' + self.context + '\n' + title)
        for index, entry in enumerate(entries, 1): print('{}. {} — {}'.format(index, entry[1], entry[2]))
        value = console.ask(self.t('Select number, r=refresh, Enter=back', 'Αριθμός, r=ανανέωση, Enter=πίσω'))
        if value == 'r': return '__refresh__'
        if not value: return None
        try: return entries[int(value)-1][0] if 1 <= int(value) <= len(entries) else '__refresh__'
        except ValueError: return '__refresh__'

    def view(self, title, content):
        producer = content if callable(content) else lambda: content
        if self.basic or not sys.stdin.isatty() or os.environ.get('TERM', 'dumb') == 'dumb':
            while True:
                print('\n' + title + '\n' + str(producer()))
                if input(self.t('r=refresh, Enter=back: ', 'r=ανανέωση, Enter=πίσω: ')).strip() != 'r': return
        try:
            import curses
            def render(screen):
                curses.curs_set(0)
                if hasattr(screen,'timeout'):screen.timeout(-1)
                if hasattr(curses, 'set_escdelay'): curses.set_escdelay(35)
                if hasattr(screen, 'keypad'): screen.keypad(True)
                normal, accent, selected, warning = self.palette(curses, screen)
                offset, text = 0, str(producer())
                wrap_cache = None
                wrapped_lines = []
                while True:
                    screen.erase()
                    h, w = screen.getmaxyx()
                    if wrap_cache != (w, text):
                        wrapped_lines = []
                        for source in text.splitlines():
                            wrapped_lines.extend(textwrap.wrap(source.expandtabs(4), max(20, w-5), replace_whitespace=False, drop_whitespace=False) or [''])
                        wrap_cache = (w, text)
                    lines = wrapped_lines
                    try:
                        screen.addnstr(0, 2, TITLE + ' | ' + title, w-4, accent)
                        for n, line in enumerate(lines[offset:offset+max(1, h-5)], 2):
                            screen.addnstr(n, 2, line, w-4, normal)
                        screen.addnstr(h-2, 2, self.t('↑↓/PgUp/PgDn Scroll  r Refresh  q/Esc Back', '↑↓/PgUp/PgDn Κύλιση  r Ανανέωση  q/Esc Πίσω'), w-4, accent)
                    except curses.error: pass
                    screen.refresh()
                    key = screen.getch()
                    if key in (27, ord('q'), 10, 13): return
                    if key in (curses.KEY_DOWN, ord('j')): offset = min(max(0, len(lines)-1), offset+1)
                    if key in (curses.KEY_UP, ord('k')): offset = max(0, offset-1)
                    if key == curses.KEY_NPAGE: offset = min(max(0, len(lines)-1), offset+max(1, h-5))
                    if key == curses.KEY_PPAGE: offset = max(0, offset-max(1, h-5))
                    if key == curses.KEY_HOME: offset = 0
                    if key == curses.KEY_END: offset = max(0, len(lines)-max(1, h-5))
                    if key == ord('r'): text = str(producer()); offset = 0
            curses.wrapper(render)
        except KeyboardInterrupt:return
        except ImportError:
            print(producer())
            input('Enter...')

    def prompt(self,english,greek,default='',choices=None):
        console.LANGUAGE=self.language;console.THEME=self.theme
        if choices is None:
            if 'English' in english and ('Ελληνικά' in english or english.startswith('Language')):choices=['1','2']
            elif 'tcp/udp' in english:choices=['tcp','udp']
            elif 'complain/enforce' in english:choices=['complain','enforce']
            elif english=='Shell':choices=['/bin/bash','/bin/sh','/usr/sbin/nologin']
            elif english.startswith('Lines per source'):choices=['100','200','500','1000','5000']
        return console.ask(self.t(english,greek),default,choices=choices)

    def error(self, error):
        self.view(self.t('Information / action unavailable', 'Πληροφορίες / μη διαθέσιμη ενέργεια'), str(error))


def table(headers, rows):
    """Plain aligned text is confined to the native terminal, not chat rendering."""
    rows = [[str(x) for x in row] for row in rows]
    widths = [min(70, max([len(str(header))] + [len(row[index]) for row in rows])) for index, header in enumerate(headers)]
    return '\n'.join('  '.join(value[:widths[index]].ljust(widths[index]) for index, value in enumerate(row))
                     for row in [list(headers)] + rows)
