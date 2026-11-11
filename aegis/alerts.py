#!/usr/bin/env python3
"""Linux Telegram Alerts 1.1.0 — bilingual interactive installer + collector (Python 3.9+).
No embedded secrets. No firewall/SSH/Fail2Ban action modifications.
"""
import argparse
import datetime as dt
import fcntl
import getpass
import glob
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

LANGUAGE = 'en'
UNAVAILABLE = {}
EN = {'🚀 Εκκίνηση / αλλαγή boot ID': '🚀 Server boot / boot ID change', '🔐 Επιτυχημένη σύνδεση SSH': '🔐 Successful SSH login', '⛔ Αποτυχημένες προσπάθειες SSH (σύνοψη)': '⛔ Failed SSH attempts (summary)', '🛡️ Αποτυχία ταυτοποίησης sudo': '🛡️ Failed sudo authentication', '🚫 Fail2Ban: αποκλεισμός IP': '🚫 Fail2Ban: IP banned', '🔓 Fail2Ban: άρση αποκλεισμού IP': '🔓 Fail2Ban: IP unbanned', '⚙️ systemd: failed / επιστροφή σε active': '⚙️ systemd: service failed / active again', '🧠 RAM: υψηλή χρήση / αποκατάσταση': '🧠 RAM: high usage / recovery', '🔄 Swap: υψηλή χρήση / αποκατάσταση': '🔄 Swap: high usage / recovery', '🔥 Load ανά CPU: υψηλό / αποκατάσταση': '🔥 Load per CPU: high load / recovery', '💾 Δίσκος: πληρότητα / αποκατάσταση': '💾 Disk: high usage / recovery', '🗂️ Inodes: εξάντληση / αποκατάσταση': '🗂️ Inodes: high usage / recovery', '💥 OOM: εξάντληση μνήμης / killed process': '💥 OOM: out of memory / killed process', '🚨 Κρίσιμα kernel errors (σύνοψη)': '🚨 Critical kernel errors (summary)', '🌐 Αλλαγή IPv4 / link / default route': '🌐 IPv4 / link / default route changes', '🐳 Containers: κατάσταση / health / νέα / αφαίρεση': '🐳 Containers: state / health / added / removed', '🔒 Λήξη τοπικών PEM certificates': '🔒 Local PEM certificate expiry', '📜 Certbot: renewal success / failure από journal': '📜 Certbot: renewal success / failure from journal', '🧩 Linux MD RAID: degraded / αποκατάσταση': '🧩 Linux MD RAID: degraded / recovery', '📝 Αλλαγές passwd / group / sudoers / SSH config': '📝 Changes to passwd / group / sudoers / SSH config', '📊 Ημερήσια αναφορά υγείας': '📊 Daily health report', '📦 Ειδοποιήσεις από δικά σου scripts (enqueue)': '📦 Notifications from your own scripts (enqueue)', 'Ελέγξτε /proc/mdstat και mdadm --detail.': 'Check /proc/mdstat and mdadm --detail.', 'Δημιουργεί δικό του service/timer. Δεν αλλάζει SSH, firewall ή Fail2Ban.': 'Installs its own service/timer. Does not change SSH, firewall or Fail2Ban.', 'Όνομα πελάτη / server': 'Customer / server name', 'Διάστημα ελέγχου, δευτερόλεπτα': 'Check interval, seconds', 'Έλεγχος: sudo linux-telegram-alerts status': 'Status: sudo linux-telegram-alerts status', 'Ρυθμίσεις: sudo linux-telegram-alerts configure': 'Settings: sudo linux-telegram-alerts configure', '🛡️ Αποτυχίες sudo': '🛡️ Failed sudo authentication', '🧠 Υψηλή χρήση RAM': '🧠 High RAM usage', '🔄 Υψηλή χρήση swap': '🔄 High swap usage', '🔥 Υψηλό load ανά CPU': '🔥 High load per CPU', '❌ Υπηρεσία σε failed state': '❌ Service failed', '🌐 Αλλαγή δικτύου IPv4': '🌐 IPv4 network change', '🔒 Πιστοποιητικό κοντά στη λήξη': '🔒 Certificate expiring soon', '📊 Ημερήσια αναφορά': '📊 Daily health report', 'Μη έγκυρη μορφή token.': 'Invalid token format.', 'Chat / Channel ID ή @public_channel': 'Chat / Channel ID or @public_channel', 'Παράδειγμα ID: -1001234567890 ή @channel_name': 'Example ID: -1001234567890 or @channel_name', 'Topic/thread ID (0=χωρίς topic)': 'Topic/thread ID (0=no topic)', 'Διάρκεια υπέρβασης πριν το alert (λεπτά)': 'Sustained threshold duration before alert, minutes', 'Προειδοποίηση certificate, ημέρες': 'Certificate expiry warning, days', 'Επιλογές: ': 'Selected: ', 'Ακυρώθηκε. Δεν εφαρμόστηκαν αλλαγές.': 'Cancelled. No changes applied.', '✅ Εγκαταστάθηκε v': '✅ Installed v', 'Run with sudo / απαιτείται root': 'Run with sudo / root required', 'Αφαιρεί μόνο agent/service/timer. Κρατά token/config/ουρά/backup για ανάκτηση.': 'Removes the agent/service/timer. Retains token/config/queue/backups for recovery.', '🔐 Σύνδεση SSH': '🔐 SSH login', '⛔ Αποτυχίες SSH': '⛔ Failed SSH attempts', '💥 Εξάντληση μνήμης — OOM': '💥 Out of memory — OOM', 'Ελέγξτε το τοπικό kernel journal.': 'Check the local kernel journal.', '❌ Certbot: αποτυχία renewal': '❌ Certbot: renewal failed', 'Ελέγξτε certbot logs / journal.': 'Check Certbot logs / journal.', '✅ Certbot: επιτυχία renewal': '✅ Certbot: renewal succeeded', 'Επιβεβαίωση από καταγεγραμμένο journal event.': 'Confirmed by a recorded journal event.', 'Συμβάντα: {}\nΑπό: {}\nΈως: {}': 'Events: {}\nFrom: {}\nTo: {}', '✅ Υπηρεσία ξανά ενεργή': '✅ Service active again', '🐳 Αλλαγές containers': '🐳 Container changes', '🐳 Προβληματικά containers': '🐳 Unhealthy containers', '📝 Αλλαγή αρχείων ασφάλειας': '📝 Security configuration changed', 'Απλό μενού: το terminal δεν υποστηρίζει curses.': 'Using basic menu: terminal does not support curses.', 'Load ανά CPU ×100 (150=1.5)': 'Load per CPU ×100 (150=1.5)', 'Ώρα ημερήσιας αναφοράς (timezone server)': 'Daily report time (server timezone)', '\nΠροορισμός: {} · Server: {}': '\nDestination: {} · Server: {}', 'Θα εγκατασταθεί timer ανά {}s και θα σταλεί δοκιμαστικό Telegram.': 'Installs a timer with a {}s interval and sends a Telegram test message.', '🧪 Δοκιμή εγκατάστασης\n🖥️ ': '🧪 Installation test\n🖥️ ', 'Γράψε REMOVE: ': 'Type REMOVE: ', '\nΑκυρώθηκε.': '\nCancelled.', '✅ Αποκατάσταση: ': '✅ Recovered: ', 'Μη προσβάσιμο mount: ': 'Inaccessible mount: ', '{}\nΥπολειπόμενες ημέρες: {}\nΛήξη UTC: {}': '{}\nDays remaining: {}\nExpiry UTC: {}', '🚀 Εκκίνηση server': '🚀 Server boot', '✅ Παρακολούθηση ενεργοποιήθηκε': '✅ Monitoring enabled', '↑↓/PgUp/PgDn: κίνηση | Space: ✓ | Enter: OK | q: ακύρωση': '↑↓/PgUp/PgDn: move | Space: select | Enter: OK | q: cancel', 'Αριθμοί για toggle (π.χ. 2 6 11), Enter=OK, q=ακύρωση: ': 'Numbers to toggle (e.g. 2 6 11), Enter=OK, q=cancel: ', 'Μη έγκυρη επιλογή.': 'Invalid selection.', 'Δώστε αριθμό {}–{}.': 'Enter a number from {} to {}.', 'Εφαρμογή εγκατάστασης; Γράψε YES: ': 'Apply installation? Type YES: ', ' και ': ' and ', '🧪 Δοκιμή Telegram': '🧪 Telegram test', ' — ελέγξτε token, ID και δικαιώματα bot.': ' — check the token, chat ID and bot permissions.', 'Συμβάντα από log: {}\n': 'Log events: {}\n', 'Τιμή: {:.2f}\nΌριο: {}': 'Value: {:.2f}\nThreshold: {}', '⚠️ Αδυναμία ελέγχου: ': '⚠️ Check unavailable: ', 'Ελέγξτε dependencies / τοπικά logs. Τύπος: ': 'Check dependencies / local logs. Error type: ', '\n⚙️ Failed/tracked services: {}\n📬 Εκκρεμή: {}\n⏱️ Uptime: {:.1f} ώρες': '\n⚙️ Failed/tracked services: {}\n📬 Pending messages: {}\n⏱️ Uptime: {:.1f} hours', 'Όριο {} %': '{} threshold %', 'Απεγκαταστάθηκε. Διατηρήθηκαν ': 'Uninstalled. Retained ', '✅ Παραδόθηκαν όλα τα μηνύματα.': '✅ All messages delivered.', '⏳ Εκκρεμεί παράδοση· δείτε status/journal.': '⏳ Delivery pending; check status/journal.', 'Ελέγξτε prerequisites / permissions / τοπικό journal.': 'Check prerequisites / permissions / local journal.', '⚠️ Μη προσβάσιμο mount: ': '⚠️ Inaccessible mount: ', 'Mount paths χωρισμένα με κόμμα': 'Mount paths, comma-separated', 'PEM paths/globs, με κόμμα': 'PEM paths/globs, comma-separated', 'Χρήση: {:.1f}% · όριο {}%': 'Usage: {:.1f}% · threshold {}%', ' (Enter=διατήρηση)': ' (Enter=keep current)'}

EN['Linux Telegram Alerts — επιλογή ειδοποιήσεων'] = 'Linux Telegram Alerts — notification selection'

def tr(text):
    """EL/EN: Shared language for installer UI and generated notifications."""
    return EN.get(text, text) if LANGUAGE == 'en' else text


def prompt_input(label, default=None, secret=False):
    # Aegis supplies its trusted UI root; the standalone collector stays dependency-free.
    ui_root=os.environ.get('AEGIS_UI_ROOT','')
    if ui_root and Path(ui_root).resolve() in (Path(__file__).resolve().parent.parent,Path('/opt/aegis-linux-hardener')):
        if str(Path(ui_root).resolve()) not in sys.path:sys.path.insert(0,str(Path(ui_root).resolve()))
        from aegis import console
        console.LANGUAGE=LANGUAGE;console.THEME=os.environ.get('AEGIS_THEME','slate')
        options=['y','n'] if '[Y/n' in label else ['1','2'] if '[1]' in label and '[2]' in label else None
        if options and default is None:default='y'
        try:return console.ask(label,default,secret,options)
        except console.Cancelled:raise KeyboardInterrupt() from None
    rich = sys.stdout.isatty() and not os.environ.get('NO_COLOR')
    def color(text, code): return '\033[' + code + 'm' + text + '\033[0m' if rich else text
    print('\n' + color('─' * 64, '94'))
    print(color(label, '96'))
    if default is not None and str(default):
        print(color(('Προεπιλογή: ' if LANGUAGE == 'el' else 'Default: ') + str(default), '90'))
    value = getpass.getpass('  > ') if secret else input(color('  > ', '92'))
    value = value.strip()
    return str(default) if not value and default is not None else value


def yes_no(label):
    while True:
        value = prompt_input(label + ' [Y/n · Enter=yes]').lower()
        if value in ('', 'y', 'yes', 'ν', 'ναι'): return True
        if value in ('n', 'no', 'ο', 'όχι', 'οχι'): return False


def choose_language(default='en'):
    global LANGUAGE
    while True:
        value = prompt_input('Language / Γλώσσα: [1] English  [2] Ελληνικά', '2' if default == 'el' else '1').lower()
        value = value or ('2' if default == 'el' else '1')
        if value in ('1', 'en', 'english'):
            LANGUAGE = 'en'
            return LANGUAGE
        if value in ('2', 'el', 'gr'):
            LANGUAGE = 'el'
            return LANGUAGE
        print('Please select 1 or 2 / Επίλεξε 1 ή 2.')


VERSION = '1.2.0'
CONF = Path('/etc/linux-telegram-alerts')
BASE = Path('/var/lib/linux-telegram-alerts')
APP = Path('/usr/local/sbin/linux-telegram-alerts')
UNIT = 'linux-telegram-alerts'
F2B_LOG = Path('/var/log/fail2ban.log')
CATEGORIES = [
    ('boot', '🚀 Εκκίνηση / αλλαγή boot ID', True),
    ('ssh_login', '🔐 Επιτυχημένη σύνδεση SSH', True),
    ('ssh_fail', '⛔ Αποτυχημένες προσπάθειες SSH (σύνοψη)', True),
    ('sudo_fail', '🛡️ Αποτυχία ταυτοποίησης sudo', True),
    ('ban', '🚫 Fail2Ban: αποκλεισμός IP', True),
    ('unban', '🔓 Fail2Ban: άρση αποκλεισμού IP', True),
    ('services', '⚙️ systemd: failed / επιστροφή σε active', True),
    ('memory', '🧠 RAM: υψηλή χρήση / αποκατάσταση', True),
    ('swap', '🔄 Swap: υψηλή χρήση / αποκατάσταση', False),
    ('load', '🔥 Load ανά CPU: υψηλό / αποκατάσταση', True),
    ('disk', '💾 Δίσκος: πληρότητα / αποκατάσταση', True),
    ('inodes', '🗂️ Inodes: εξάντληση / αποκατάσταση', True),
    ('oom', '💥 OOM: εξάντληση μνήμης / killed process', True),
    ('kernel', '🚨 Κρίσιμα kernel errors (σύνοψη)', False),
    ('network', '🌐 Αλλαγή IPv4 / link / default route', False),
    ('docker', '🐳 Containers: κατάσταση / health / νέα / αφαίρεση', False),
    ('certs', '🔒 Λήξη τοπικών PEM certificates', False),
    ('certbot', '📜 Certbot: renewal success / failure από journal', False),
    ('raid', '🧩 Linux MD RAID: degraded / αποκατάσταση', False),
    ('config', '📝 Αλλαγές passwd / group / sudoers / SSH config', False),
    ('daily', '📊 Ημερήσια αναφορά υγείας', True),
    ('custom', '📦 Ειδοποιήσεις από δικά σου scripts (enqueue)', True),
]
LABELS = {k: label for k, label, _ in CATEGORIES}
DEFAULTS = {
    'schema': 1, 'language': 'en', 'label': socket.gethostname(), 'chat_id': '', 'thread_id': None,
    'enabled': [k for k, _, yes in CATEGORIES if yes], 'interval': 60,
    'ram_pct': 90, 'swap_pct': 80, 'disk_pct': 85, 'inode_pct': 85,
    'load_per_cpu': 1.5, 'sustain_minutes': 3, 'repeat_minutes': 360,
    'cert_days': 14, 'daily_at': '09:00', 'queue_max': 10000,
    'mounts': ['/'], 'cert_globs': ['/etc/letsencrypt/live/*/cert.pem'],
    'ignore_services': [UNIT + '.service', 'tena-alerts.service'],
}


def run(args, timeout=15):
    """EL/EN: argv list, ποτέ shell=True / never interpolate shell commands."""
    p = subprocess.run(args, capture_output=True, text=True, errors='replace',
                       timeout=timeout, env={**os.environ, 'LC_ALL': 'C'})
    if p.returncode:
        raise RuntimeError('Command failed: ' + args[0])
    return p.stdout


def atomic(path, content, mode=0o600):
    """Ατομικό write + fsync, ιδιωτικό προσωρινό αρχείο / private atomic write."""
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def config():
    c = {**DEFAULTS, **json.loads((CONF / 'config.json').read_text())}
    if c.get('language', 'en') not in ('en', 'el'):
        raise ValueError('Unsupported language')
    if c.get('schema') != 1:
        raise ValueError('Unsupported config schema')
    for key in ('ram_pct', 'swap_pct', 'disk_pct', 'inode_pct'):
        if not 1 <= float(c[key]) <= 100:
            raise ValueError('Invalid threshold: ' + key)
    if not 30 <= int(c['interval']) <= 3600 or c['queue_max'] < 100:
        raise ValueError('Invalid interval / queue_max')
    if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', c['daily_at']):
        raise ValueError('Invalid daily_at')
    if not set(c['enabled']) <= set(LABELS):
        raise ValueError('Unknown notification category')
    return c


class APIError(Exception):
    def __init__(self, code=0, retry=60, migrate=None):
        self.code, self.retry, self.migrate = code, retry, migrate
        # EL/EN: Ποτέ URL/token/response body σε log / never log secrets.
        super().__init__('Telegram HTTP/API code ' + str(code))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api(token, method, body):
    data = json.dumps(body, ensure_ascii=False).encode('utf-8')
    request = urllib.request.Request('https://api.telegram.org/bot' + token + '/' + method,
                                     data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=8) as resp:
            result = json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            result = json.loads(e.read(65536))
        except (ValueError, OSError):
            raise APIError(e.code) from None
    except (OSError, ValueError, urllib.error.URLError):
        raise APIError() from None
    if not result.get('ok'):
        params = result.get('parameters') or {}
        raise APIError(result.get('error_code', 0), params.get('retry_after', 60),
                       params.get('migrate_to_chat_id'))
    return result.get('result')


def dbopen():
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(str(BASE / 'events.sqlite3'), timeout=10)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY, text TEXT NOT NULL, created REAL NOT NULL,
            attempt INTEGER NOT NULL DEFAULT 0, due REAL NOT NULL DEFAULT 0);
    ''')
    return db


def get(db, key, default=None):
    row = db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
    return json.loads(row[0]) if row else default


def put(db, key, value):
    db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', (key, json.dumps(value)))


def clean(text, limit=1400):
    # Journal lines can contain control chars or secrets. Do not send raw log lines.
    return ''.join(ch for ch in str(text) if ch in '\n\t' or ord(ch) >= 32)[:limit]


def notify(db, c, title, detail='', when=None):
    count = db.execute('SELECT count(*) FROM queue').fetchone()[0]
    if count >= c['queue_max']:
        # Roll back cursor + state too: journal events remain replayable while retained.
        raise RuntimeError('Queue capacity reached; collection paused')
    stamp = when or dt.datetime.now().astimezone().isoformat(timespec='seconds')
    text = '{}\n🖥️ {}\n🕒 {}\n{}'.format(title, clean(c['label'], 160), stamp, clean(detail))
    db.execute('INSERT INTO queue(text,created) VALUES (?,?)', (text, time.time()))


def deliver(db, c):
    """Persistent queue / ανθεκτική ουρά. At-least-once, bounded batch + backoff."""
    token = (CONF / 'telegram.token').read_text().strip()
    deadline = time.monotonic() + 35
    sent = 0
    for row in db.execute('SELECT id,text,attempt,due FROM queue ORDER BY id LIMIT 20').fetchall():
        ident, text, attempt, due = row
        if time.monotonic() >= deadline or due > time.time():
            break
        body = {'chat_id': c['chat_id'], 'text': text}
        if c.get('thread_id'):
            body['message_thread_id'] = c['thread_id']
        try:
            api(token, 'sendMessage', body)
        except APIError as e:
            if e.migrate:
                # Retain queued events; use the new destination without rewriting config.
                c['chat_id'] = str(e.migrate)
                put(db, 'migrated_chat_id', c['chat_id'])
            delay = max(float(e.retry), min(3600, 30 * 2 ** min(attempt, 7)))
            db.execute('UPDATE queue SET attempt=?,due=? WHERE id=?',
                       (attempt + 1, time.time() + delay, ident))
            db.commit()
            print('Delivery pending; code={}; retry in {}s'.format(e.code, int(delay)))
            return False
        db.execute('DELETE FROM queue WHERE id=?', (ident,))
        db.commit()
        sent += 1
        time.sleep(1.05)  # EL/EN: <=1 message/sec, bounded timer runtime.
    return db.execute('SELECT count(*) FROM queue').fetchone()[0] == 0


def classify(e):
    """Only extract safe fields / στέλνουμε πεδία, όχι ολόκληρες γραμμές log."""
    m = e.get('MESSAGE', '')
    if not isinstance(m, str):
        return None
    comm = e.get('_COMM', '')
    ident = e.get('SYSLOG_IDENTIFIER', '')
    if comm in ('sshd', 'sshd-session') or ident in ('sshd', 'sshd-session'):
        match = re.search(r'Accepted (\S+) for (\S+) from (\S+) port (\d+)', m)
        if match:
            return 'ssh_login', tr('🔐 Σύνδεση SSH'), '👤 {}\n🌍 IP: {}\n🔑 {}'.format(match[2], match[3], match[1])
        if re.search(r'Failed (password|publickey)|Invalid user|authentication failure', m, re.I):
            return 'ssh_fail', tr('⛔ Αποτυχίες SSH'), ''
    if (comm == 'sudo' or ident == 'sudo') and re.search(r'authentication failure|incorrect password', m, re.I):
        return 'sudo_fail', tr('🛡️ Αποτυχίες sudo'), ''
    if 'fail2ban' in (comm + ident + e.get('_SYSTEMD_UNIT', '')).lower():
        match = re.search(r'\[([^\]]+)\]\s+(Unban|Ban)\s+([0-9a-fA-F:.]+)\b', m)
        if match:
            return ('unban' if match[2] == 'Unban' else 'ban',
                    '🔓 Fail2Ban Unban' if match[2] == 'Unban' else '🚫 Fail2Ban Ban',
                    '🧱 Jail: {}\n🌍 IP: {}'.format(match[1], match[3]))
    if e.get('_TRANSPORT') == 'kernel':
        if re.search(r'Out of memory:|Killed process \d+|oom-kill:', m, re.I):
            return 'oom', tr('💥 Εξάντληση μνήμης — OOM'), tr('Ελέγξτε το τοπικό kernel journal.')
        if str(e.get('PRIORITY', '9')) in ('0', '1', '2', '3'):
            return 'kernel', '🚨 Kernel errors', ''
    if 'certbot' in (comm + ident + e.get('_SYSTEMD_UNIT', '')).lower():
        if re.search(r'failed to renew|renewal failure|all renewals failed', m, re.I):
            return 'certbot', tr('❌ Certbot: αποτυχία renewal'), tr('Ελέγξτε certbot logs / journal.')
        if re.search(r'all renewals succeeded|successfully renewed|renewals succeeded', m, re.I):
            return 'certbot', tr('✅ Certbot: επιτυχία renewal'), tr('Επιβεβαίωση από καταγεγραμμένο journal event.')
    return None


def journal(db, c):
    cursor = get(db, 'cursor')
    args = ['journalctl', '--no-pager', '-o', 'json', '--show-cursor', '-q']
    # Initial install starts at now; never replays the full history.
    args += ['--after-cursor=' + cursor] if cursor else ['-n', '0']
    p = subprocess.run(args, capture_output=True, text=True, errors='replace', timeout=20)
    if p.returncode:
        # Cursor vacuumed: bounded overlap with persistent deduplication by __CURSOR.
        print('Journal cursor unavailable; replaying last 5 minutes')
        p = subprocess.run(['journalctl', '--no-pager', '-o', 'json', '--show-cursor',
                            '-q', '--since=-5min'], capture_output=True, text=True, timeout=20)
        if p.returncode:
            raise RuntimeError('Cannot read system journal')
    seen = set(get(db, 'seen_cursors', []))
    recent = list(get(db, 'seen_cursors', []))
    summary = {}
    for line in p.stdout.splitlines():
        if line.startswith('-- cursor: '):
            put(db, 'cursor', line[11:])
            continue
        if not line.startswith('{'):
            continue
        e = json.loads(line)
        cur = e.get('__CURSOR')
        if cur:
            put(db, 'cursor', cur)
        if cur in seen:
            continue
        if cur:
            seen.add(cur)
            recent.append(cur)
        event = classify(e)
        if event and event[0] in ('ban', 'unban') and F2B_LOG.exists():
            continue  # Prefer standard Fail2Ban log, avoid journal duplicates.
        if not event or event[0] not in c['enabled']:
            continue
        kind, title, details = event
        stamp = dt.datetime.fromtimestamp(int(e['__REALTIME_TIMESTAMP']) / 1e6).astimezone().isoformat(timespec='seconds')
        if kind in ('ssh_fail', 'sudo_fail', 'kernel', 'oom', 'ban', 'unban', 'ssh_login', 'certbot'):
            # One batch message per category. Login/ban samples are capped for flood protection.
            item = summary.setdefault(kind, {'count': 0, 'title': title, 'samples': [], 'first': stamp, 'last': stamp})
            item['count'] += 1
            item['last'] = stamp
            if details and details not in item['samples'] and len(item['samples']) < 5:
                item['samples'].append(title + '\n' + details)
    for item in summary.values():
        detail = tr('Συμβάντα: {}\nΑπό: {}\nΈως: {}').format(item['count'], item['first'], item['last'])
        detail += '\n' + '\n\n'.join(item['samples'])
        notify(db, c, item['title'], detail)
    put(db, 'seen_cursors', recent[-20000:])


def fail2ban(db, c):
    """Default file backend + inode/offset / χωρίς αλλαγή Fail2Ban actions."""
    path = F2B_LOG
    if not path.exists():
        # SYSLOG/journal backend is handled by journal().
        return
    st = path.stat()
    old = get(db, 'f2b_file')
    if old is None:
        put(db, 'f2b_file', {'inode': st.st_ino, 'offset': st.st_size})
        return  # Start at EOF on first enable / όχι παλιό ιστορικό.
    sources = []
    if old['inode'] != st.st_ino:
        rotated = path.with_name(path.name + '.1')
        if rotated.exists() and rotated.stat().st_ino == old['inode']:
            sources.append((rotated, old['offset']))
        sources.append((path, 0))
    else:
        sources.append((path, old['offset'] if st.st_size >= old['offset'] else 0))
    counts, samples = {}, {}
    new_offset = 0
    new_inode = st.st_ino
    for source, offset in sources:
        with source.open('rb') as stream:
            inode = os.fstat(stream.fileno()).st_ino
            stream.seek(offset)
            while True:
                # Process only complete records; finish oversized input on next run.
                before = stream.tell()
                line = stream.readline(65536)
                if not line: break
                if not line.endswith(b'\n'):
                    stream.seek(before)
                    break
                event = classify({'MESSAGE': line.decode('utf-8', errors='replace'), '_COMM': 'fail2ban'})
                if event and event[0] in c['enabled']:
                    kind, title, detail = event
                    counts[kind] = counts.get(kind, 0) + 1
                    values = samples.setdefault(kind, [])
                    if detail not in values and len(values) < 5: values.append(detail)
            if source == path:
                new_offset, new_inode = stream.tell(), inode
    for kind, count in counts.items():
        notify(db, c, '🚫 Fail2Ban Ban' if kind == 'ban' else '🔓 Fail2Ban Unban',
               tr('Συμβάντα από log: {}\n').format(count) + '\n\n'.join(samples[kind]))
    put(db, 'f2b_file', {'inode': new_inode, 'offset': new_offset})


def transition(db, c, key, bad, title, detail, sustained=False):
    now = time.time()
    s = get(db, key, {'active': False, 'since': now, 'last': 0})
    if bad:
        if not s.get('bad'):
            s['since'] = now
        delay = c['sustain_minutes'] * 60 if sustained else 0
        if now - s['since'] >= delay and (not s['active'] or now - s['last'] >= c['repeat_minutes'] * 60):
            notify(db, c, title, detail)
            s.update(active=True, last=now)
    elif s['active']:
        notify(db, c, tr('✅ Αποκατάσταση: ') + title, detail)
        s['active'] = False
    s['bad'] = bool(bad)
    put(db, key, s)


def meminfo():
    return {m[1]: int(m[2]) for m in re.finditer(r'^(\w+):\s+(\d+)', Path('/proc/meminfo').read_text(), re.M)}


def health(db, c):
    enabled = c['enabled']
    mem = meminfo()
    ram = 100 * (1 - mem.get('MemAvailable', mem['MemFree']) / mem['MemTotal'])
    swap = 100 * (1 - mem.get('SwapFree', 0) / mem['SwapTotal']) if mem.get('SwapTotal') else 0
    load = os.getloadavg()[0]
    cpus = os.cpu_count() or 1
    report = '🧠 RAM: {:.1f}%\n🔄 Swap: {:.1f}%\n🔥 Load 1m: {:.2f} / {} CPU'.format(ram, swap, load, cpus)
    for kind, value, limit, title in [
        ('memory', ram, c['ram_pct'], tr('🧠 Υψηλή χρήση RAM')),
        ('swap', swap, c['swap_pct'], tr('🔄 Υψηλή χρήση swap')),
        ('load', load / cpus, c['load_per_cpu'], tr('🔥 Υψηλό load ανά CPU')),
    ]:
        if kind in enabled:
            # Hysteresis avoids threshold flapping / υστέρηση στην αποκατάσταση.
            active = get(db, 'metric:' + kind, {}).get('active', False)
            bad = value >= limit * (0.9 if active else 1)
            transition(db, c, 'metric:' + kind, bad, title,
                       tr('Τιμή: {:.2f}\nΌριο: {}').format(value, limit), True)
    for mount in c['mounts']:
        try:
            v = os.statvfs(mount)
            used = v.f_blocks - v.f_bfree
            disk = 100 * used / max(1, used + v.f_bavail)
            inode = 100 * (v.f_files - v.f_ffree) / v.f_files if v.f_files else 0
            report += '\n💾 {}: {:.1f}% · inodes {:.1f}%'.format(mount, disk, inode)
            for kind, val, limit in [('disk', disk, c['disk_pct']), ('inodes', inode, c['inode_pct'])]:
                if kind in enabled:
                    key = kind + ':' + mount
                    active = get(db, key, {}).get('active', False)
                    transition(db, c, key, val >= (max(0.1, limit - 5) if active else limit),
                               '💾 ' + kind + ': ' + mount, tr('Χρήση: {:.1f}% · όριο {}%').format(val, limit))
            transition(db, c, 'mount-error:' + mount, False, tr('Μη προσβάσιμο mount: ') + mount, '')
        except OSError:
            if 'disk' in enabled or 'inodes' in enabled:
                transition(db, c, 'mount-error:' + mount, True, tr('⚠️ Μη προσβάσιμο mount: ') + mount, '')
    put(db, 'health_report', report)


def services(db, c):
    ignored = set(c['ignore_services'])
    text = run(['systemctl', '--failed', '--type=service', '--no-legend', '--plain', '--no-pager'])
    failed = {line.split()[0] for line in text.splitlines() if line.strip()} - ignored
    previous = set(get(db, 'failed_services', []))
    for unit in sorted(failed - previous):
        notify(db, c, tr('❌ Υπηρεσία σε failed state'), '⚙️ ' + unit)
    remaining = set()
    for unit in sorted(previous - failed):
        status = run(['systemctl', 'show', unit, '-p', 'ActiveState', '--value']).strip()
        if status == 'active':
            notify(db, c, tr('✅ Υπηρεσία ξανά ενεργή'), '⚙️ ' + unit)
        else:
            remaining.add(unit)  # reset-failed/inactive is not a confirmed recovery.
    put(db, 'failed_services', sorted(failed | remaining))


def network(db, c):
    values = {
        'addresses': json.loads(run(['ip', '-j', '-4', 'address', 'show'])),
        'routes': json.loads(run(['ip', '-j', '-4', 'route', 'show', 'default'])),
    }
    # Keep stable fields; temporary counters/lifetimes must not trigger changes.
    snapshot = {'links': sorted((x['ifname'], x.get('operstate'),
                  sorted(a['local'] for a in x.get('addr_info', []))) for x in values['addresses']),
                'routes': sorted((x.get('dev', ''), x.get('gateway', ''), x.get('metric', 0)) for x in values['routes'])}
    # Normalize tuples to JSON lists before comparing persisted state.
    snapshot = json.loads(json.dumps(snapshot))
    old = get(db, 'network')
    if old is not None and old != snapshot:
        notify(db, c, tr('🌐 Αλλαγή δικτύου IPv4'), json.dumps(snapshot, ensure_ascii=False))
    put(db, 'network', snapshot)


def docker(db, c):
    ids = run(['docker', 'ps', '-aq']).split()
    current = {}
    for offset in range(0, len(ids), 100):
        for line in run(['docker', 'inspect', '--format', '{{json .}}'] + ids[offset:offset+100]).splitlines():
            item = json.loads(line)
            s = item['State']
            current[item['Id'][:12]] = {'name': item['Name'].lstrip('/'), 'status': s['Status'],
                                      'health': s.get('Health', {}).get('Status', 'no-healthcheck'),
                                      'restart': item.get('RestartCount', 0)}
    previous = get(db, 'docker')
    if previous is not None:
        changes = []
        for key in sorted(set(previous) | set(current)):
            if previous.get(key) != current.get(key):
                changes.append('{} → {}'.format(key, json.dumps(current.get(key, 'removed'), ensure_ascii=False)))
        if changes:
            notify(db, c, tr('🐳 Αλλαγές containers'), '\n'.join(changes[:10]))
    else:
        bad = [x['name'] for x in current.values() if x['status'] in ('dead', 'restarting') or x['health'] == 'unhealthy']
        if bad:
            notify(db, c, tr('🐳 Προβληματικά containers'), '\n'.join(bad[:10]))
    put(db, 'docker', current)


def certs(db, c):
    if time.time() - get(db, 'cert_check', 0) < 21600:
        return
    paths = sorted({p for pattern in c['cert_globs'] for p in glob.glob(pattern)})
    if not paths:
        if not get(db, 'certs_no_matches', False):
            print('ℹ️ ' + msg('No matching PEM certificates; skipping certificate check.',
                              'Δεν βρέθηκαν PEM certificates· παραλείπεται ο έλεγχος.'))
        put(db, 'certs_no_matches', True)
        return
    put(db, 'certs_no_matches', False)
    for p in paths:
        text = run(['openssl', 'x509', '-in', p, '-noout', '-enddate'])
        expiry = dt.datetime.strptime(text.strip().split('=', 1)[1], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt.timezone.utc)
        days = math.floor((expiry.timestamp() - time.time()) / 86400)
        transition(db, c, 'cert:' + p, days <= c['cert_days'], tr('🔒 Πιστοποιητικό κοντά στη λήξη'),
                   tr('{}\nΥπολειπόμενες ημέρες: {}\nΛήξη UTC: {}').format(p, days, expiry.isoformat()))
    put(db, 'cert_check', time.time())


def raid(db, c):
    text = Path('/proc/mdstat').read_text()
    bad = bool(re.search(r'\[[U_]*_[U_]*\]', text)) or bool(re.search(r'^md\S*\s*:\s*inactive', text, re.M))
    transition(db, c, 'raid', bad, '🧩 MD RAID degraded / inactive', tr('Ελέγξτε /proc/mdstat και mdadm --detail.'))


def configs(db, c):
    paths = ['/etc/passwd', '/etc/group', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config']
    paths += glob.glob('/etc/sudoers.d/*') + glob.glob('/etc/ssh/sshd_config.d/*.conf')
    hashes = {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in paths if Path(p).is_file()}
    old = get(db, 'config_hashes')
    if old is not None:
        changed = [p for p in set(old) | set(hashes) if old.get(p) != hashes.get(p)]
        if changed:
            notify(db, c, tr('📝 Αλλαγή αρχείων ασφάλειας'), '\n'.join(sorted(changed)))
    # Only hashes are stored / μόνο hashes, χωρίς περιεχόμενα ή κωδικούς.
    put(db, 'config_hashes', hashes)


def collect(db, c):
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    old = get(db, 'boot')
    if old != boot:
        if 'boot' in c['enabled']:
            notify(db, c, tr('🚀 Εκκίνηση server') if old else tr('✅ Παρακολούθηση ενεργοποιήθηκε'),
                   'Kernel: {}\nBoot ID: {}'.format(os.uname().release, boot))
        put(db, 'boot', boot)
    # Cursor and all generated events share a transaction / κοινό transaction.
    journal(db, c)
    checks = [('fail2ban', fail2ban), ('health', health), ('services', services), ('network', network),
              ('docker', docker), ('certs', certs), ('raid', raid), ('config', configs)]
    missing = unavailable(c)
    for name, fn in checks:
        if name == 'fail2ban':
            if not set(c['enabled']) & {'ban', 'unban'}: continue
        elif name != 'health' and name not in c['enabled']:
            continue
        if name in missing:
            if not get(db, 'unavailable:' + name):
                print('ℹ️ {}: {} — {}'.format(name, missing[name], msg('check skipped', 'παράλειψη ελέγχου')))
            put(db, 'unavailable:' + name, True)
            continue
        put(db, 'unavailable:' + name, False)
        try:
            fn(db, c)
            transition(db, c, 'collector:' + name, False, 'Collector ' + name, '')
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
            # Do not silently disable unsupported collectors; one warning + recovery.
            transition(db, c, 'collector:' + name, True, tr('⚠️ Αδυναμία ελέγχου: ') + name,
                       tr('Ελέγξτε dependencies / τοπικά logs. Τύπος: ') + type(e).__name__)
    now = dt.datetime.now().astimezone()
    if 'daily' in c['enabled'] and now.strftime('%H:%M') >= c['daily_at'] and get(db, 'daily') != now.date().isoformat():
        pending = db.execute('SELECT count(*) FROM queue').fetchone()[0]
        notify(db, c, tr('📊 Ημερήσια αναφορά'), get(db, 'health_report', '') +
               tr('\n⚙️ Failed/tracked services: {}\n📬 Εκκρεμή: {}\n⏱️ Uptime: {:.1f} ώρες').format(
                   len(get(db, 'failed_services', [])), pending,
                   float(Path('/proc/uptime').read_text().split()[0]) / 3600))
        put(db, 'daily', now.date().isoformat())


def checklist(selected):
    """Terminal checkboxes: arrows + Space + Enter. Fallback: numeric toggles."""
    selected = set(selected) - set(UNAVAILABLE)
    try:
        import curses
        def ui(win):
            pos = 0
            curses.curs_set(0)
            if hasattr(curses, 'set_escdelay'): curses.set_escdelay(35)
            if hasattr(win, 'keypad'): win.keypad(True)
            while True:
                win.erase()
                h, w = win.getmaxyx()
                if h < 8 or w < 45:
                    raise RuntimeError('Terminal too small')
                win.addnstr(0, 0, tr('Linux Telegram Alerts — επιλογή ειδοποιήσεων'), w - 1)
                win.addnstr(1, 0, tr('↑↓/PgUp/PgDn: κίνηση | Space: ✓ | Enter: OK | q: ακύρωση'), w - 1)
                visible = h - 4
                start = max(0, pos - visible + 1)
                for y, (key, label, _) in enumerate(CATEGORIES[start:start+visible], 3):
                    index = start + y - 3
                    # Plain checkbox markers work even on terminals with poor emoji support.
                    line = '[{}] {}{}'.format('-' if key in UNAVAILABLE else ('x' if key in selected else ' '), tr(label),
                        ' [' + UNAVAILABLE[key] + ']' if key in UNAVAILABLE else '')
                    win.addnstr(y, 0, line, w - 2, curses.A_REVERSE if index == pos else 0)
                win.refresh()
                key = win.getch()
                if key in (curses.KEY_DOWN, ord('j')): pos = (pos + 1) % len(CATEGORIES)
                elif key in (curses.KEY_UP, ord('k')): pos = (pos - 1) % len(CATEGORIES)
                elif key == curses.KEY_NPAGE: pos = min(len(CATEGORIES)-1, pos + visible)
                elif key == curses.KEY_PPAGE: pos = max(0, pos - visible)
                elif key == curses.KEY_HOME: pos = 0
                elif key == curses.KEY_END: pos = len(CATEGORIES)-1
                elif key == ord(' '):
                    name = CATEGORIES[pos][0]
                    if name not in UNAVAILABLE:
                        selected.symmetric_difference_update({name})
                elif key in (10, 13): return sorted(selected)
                elif key in (27, ord('q')): raise KeyboardInterrupt
        if sys.stdin.isatty() and os.environ.get('TERM', 'dumb') != 'dumb':
            return curses.wrapper(ui)
    except (ImportError, RuntimeError):
        pass
    except Exception:
        print(tr('Απλό μενού: το terminal δεν υποστηρίζει curses.'))
    while True:
        for n, (key, label, _) in enumerate(CATEGORIES, 1):
            print('{:2}. [{}] {}{}'.format(n, '-' if key in UNAVAILABLE else ('x' if key in selected else ' '), tr(label),
                  ' [' + UNAVAILABLE[key] + ']' if key in UNAVAILABLE else ''))
        answer = input(tr('Αριθμοί για toggle (π.χ. 2 6 11), Enter=OK, q=ακύρωση: ')).strip()
        if not answer: return sorted(selected)
        if answer.lower() == 'q': raise KeyboardInterrupt
        try:
            indices = [int(x) for x in answer.replace(',', ' ').split()]
            if not all(1 <= n <= len(CATEGORIES) for n in indices): raise ValueError
            for n in indices:
                key = CATEGORIES[n-1][0]
                if key not in UNAVAILABLE: selected.symmetric_difference_update({key})
        except ValueError:
            print(tr('Μη έγκυρη επιλογή.'))


def ask(prompt, default=''):
    return prompt_input(prompt, default)


def integer(prompt, default, low, high):
    while True:
        try:
            n = int(ask(prompt, str(default)))
            if low <= n <= high: return n
        except ValueError:
            pass
        print(tr('Δώστε αριθμό {}–{}.').format(low, high))


def msg(english, greek):
    return english if LANGUAGE == 'en' else greek


def unavailable(c, check_paths=False):
    """Optional features are skipped, never installed implicitly / χωρίς αυτόματο install."""
    missing = {}
    for category, command in [('docker', 'docker'), ('network', 'ip'), ('certs', 'openssl'),
                              ('certbot', 'certbot')]:
        if not shutil.which(command):
            missing[category] = msg('{} command not found', 'Δεν βρέθηκε η εντολή {}').format(command)
    if not F2B_LOG.exists() and not shutil.which('fail2ban-client'):
        for category in ('ban', 'unban'):
            missing[category] = msg('Fail2Ban not detected', 'Δεν εντοπίστηκε Fail2Ban')
    md = Path('/proc/mdstat')
    if not md.exists() or not re.search(r'^md\S*\s*:', md.read_text(), re.M):
        missing['raid'] = msg('No Linux MD arrays detected', 'Δεν εντοπίστηκαν Linux MD arrays')
    if check_paths and not any(glob.glob(pattern) for pattern in c['cert_globs']):
        missing['certs'] = msg('No matching PEM certificates', 'Δεν βρέθηκαν PEM certificates στα δηλωμένα paths')
    return missing


def skip_optional(c, check_paths=False):
    missing = unavailable(c, check_paths)
    skipped = [key for key in c['enabled'] if key in missing]
    for key in skipped:
        print('⚠️ ' + msg('Skipping {}: {}. Continuing.', 'Παράλειψη {}: {}. Συνεχίζουμε.').format(key, missing[key]))
    c['enabled'] = [key for key in c['enabled'] if key not in missing]
    return missing


def dependencies(c):
    # These are essential to the architecture; a working install is impossible without them.
    missing = [cmd for cmd in ('systemctl', 'journalctl') if not shutil.which(cmd)]
    if missing:
        raise RuntimeError('Missing required systemd commands: ' + ', '.join(missing))
    skip_optional(c, check_paths=True)



def install():
    global UNAVAILABLE
    if not sys.stdin.isatty():
        raise RuntimeError('Interactive terminal required; download the installer first')
    if not Path('/run/systemd/system').is_dir():
        raise RuntimeError('Requires Linux booted with systemd; OpenRC/containers not supported')
    existing = (CONF / 'config.json').exists()
    c = config() if existing else dict(DEFAULTS)
    c['language'] = choose_language(c.get('language', 'en'))
    old_destination = (c['chat_id'], c.get('thread_id'))
    token = (CONF / 'telegram.token').read_text().strip() if existing else ''
    print('Linux Telegram Alerts v' + VERSION)
    print(tr('Δημιουργεί δικό του service/timer. Δεν αλλάζει SSH, firewall ή Fail2Ban.'))
    # Existing TENA installation stays untouched. Avoid double-alerts: require manual migration.
    legacy = [p for p in ('/etc/systemd/system/tena-alerts.timer',
                         '/etc/systemd/system/telegram-notifications.timer') if Path(p).exists()]
    if legacy:
        raise RuntimeError('Found previous installer: ' + ', '.join(legacy) +
                           '. Migration required before installation; existing files unchanged.')
    c['label'] = ask(tr('Όνομα πελάτη / server'), c['label'])
    while True:
        entered = prompt_input('Bot Token' + (tr(' (Enter=διατήρηση)') if token else ''), secret=True)
        token = entered or token
        if re.fullmatch(r'\d+:[A-Za-z0-9_-]{20,}', token): break
        print(tr('Μη έγκυρη μορφή token.'))
    while True:
        chat = ask(tr('Chat / Channel ID ή @public_channel'), str(c['chat_id']))
        if re.fullmatch(r'-?\d+|@[A-Za-z][A-Za-z0-9_]{4,}', chat):
            c['chat_id'] = chat
            break
        print(tr('Παράδειγμα ID: -1001234567890 ή @channel_name'))
    c['thread_id'] = integer(tr('Topic/thread ID (0=χωρίς topic)'), c.get('thread_id') or 0, 0, 2147483647) or None
    UNAVAILABLE = unavailable(c)
    for key, reason in UNAVAILABLE.items():
        print('ℹ️ {}: {}'.format(tr(LABELS[key]), reason))
    c['enabled'] = checklist([key for key in c['enabled'] if key not in UNAVAILABLE])
    skip_optional(c)
    c['interval'] = integer(tr('Διάστημα ελέγχου, δευτερόλεπτα'), c['interval'], 30, 3600)
    for category, key, label in [('memory', 'ram_pct', 'RAM'), ('swap', 'swap_pct', 'Swap'),
                                  ('disk', 'disk_pct', 'Disk'), ('inodes', 'inode_pct', 'Inodes')]:
        if category in c['enabled']:
            c[key] = integer(tr('Όριο {} %').format(label), c[key], 1, 100)
    if any(k in c['enabled'] for k in ('memory', 'swap', 'load')):
        c['sustain_minutes'] = integer(tr('Διάρκεια υπέρβασης πριν το alert (λεπτά)'), c['sustain_minutes'], 1, 60)
    if 'load' in c['enabled']:
        c['load_per_cpu'] = integer(tr('Load ανά CPU ×100 (150=1.5)'), int(c['load_per_cpu'] * 100), 10, 2000) / 100
    if 'disk' in c['enabled'] or 'inodes' in c['enabled']:
        c['mounts'] = list(dict.fromkeys(ask(tr('Mount paths χωρισμένα με κόμμα'), ','.join(c['mounts'])).split(',')))
        c['mounts'] = [p.strip() for p in c['mounts']]
        valid = []
        for mount in c['mounts']:
            if mount.startswith('/') and Path(mount).is_dir():
                valid.append(mount)
            else:
                print('⚠️ ' + msg('Skipping missing/invalid mount: {}', 'Παράλειψη μη έγκυρου mount: {}').format(mount))
        c['mounts'] = valid
        if not valid:
            c['enabled'] = [key for key in c['enabled'] if key not in ('disk', 'inodes')]
    if 'certs' in c['enabled']:
        c['cert_days'] = integer(tr('Προειδοποίηση certificate, ημέρες'), c['cert_days'], 1, 180)
        c['cert_globs'] = [p.strip() for p in ask(tr('PEM paths/globs, με κόμμα'), ','.join(c['cert_globs'])).split(',')]
    if 'daily' in c['enabled']:
        while True:
            value = ask(tr('Ώρα ημερήσιας αναφοράς (timezone server)'), c['daily_at'])
            if re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', value):
                c['daily_at'] = value
                break
    dependencies(c)
    if existing and old_destination != (c['chat_id'], c.get('thread_id')) and (BASE / 'events.sqlite3').exists():
        with sqlite3.connect('file:' + str(BASE / 'events.sqlite3') + '?mode=ro', uri=True) as pending_db:
            if pending_db.execute('SELECT count(*) FROM queue').fetchone()[0]:
                raise RuntimeError('Destination change blocked: deliver the pending queue to its current chat first')
    # Read-only checks verify journal access and destination before system writes.
    run(['journalctl', '-n', '0', '--no-pager'])
    api(token, 'getMe', {})
    api(token, 'getChat', {'chat_id': c['chat_id']})
    print(tr('\nΠροορισμός: {} · Server: {}').format(c['chat_id'], c['label']))
    print(tr('Επιλογές: ') + ', '.join(c['enabled']))
    print(tr('Θα εγκατασταθεί timer ανά {}s και θα σταλεί δοκιμαστικό Telegram.').format(c['interval']))
    if not yes_no('Apply installation?' if LANGUAGE == 'en' else 'Εφαρμογή εγκατάστασης;'):
        print(tr('Ακυρώθηκε. Δεν εφαρμόστηκαν αλλαγές.'))
        return
    # Test actual posting permissions; getChat alone does not guarantee can_post_messages.
    api(token, 'sendMessage', {'chat_id': c['chat_id'], 'text': tr('🧪 Δοκιμή εγκατάστασης\n🖥️ ') + c['label'],
                             **({'message_thread_id': c['thread_id']} if c['thread_id'] else {})})
    service = '''[Unit]
Description=Linux Telegram Alerts collector and queue sender
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/linux-telegram-alerts run
User=root
UMask=0077
TimeoutStartSec=180
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/linux-telegram-alerts
ProtectKernelTunables=true
ProtectKernelModules=true
RestrictSUIDSGID=true
'''
    timer = '''[Unit]
Description=Linux Telegram Alerts periodic checks
[Timer]
OnBootSec=30s
OnActiveSec=5s
OnUnitInactiveSec={}s
AccuracySec=5s
[Install]
WantedBy=timers.target
'''.format(c['interval'])
    targets = {APP: (Path(__file__).read_text(), 0o750),
               CONF / 'config.json': (json.dumps(c, ensure_ascii=False, indent=2) + '\n', 0o600),
               CONF / 'telegram.token': (token + '\n', 0o600),
               Path('/etc/systemd/system/' + UNIT + '.service'): (service, 0o644),
               Path('/etc/systemd/system/' + UNIT + '.timer'): (timer, 0o644)}
    # Refuse overwrite of unrelated files; backups are root-only on every reconfigure.
    if not existing and any(p.exists() for p in targets):
        raise RuntimeError('Existing target paths without config; refusing overwrite')
    for folder in (CONF, BASE):
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        folder.chmod(0o700)
    backup = BASE / ('backup-' + dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    backup.mkdir(mode=0o700)
    present = {p: p.exists() for p in targets}
    for n, p in enumerate(targets):
        if p.exists(): shutil.copy2(p, backup / str(n))
    was_enabled = subprocess.run(['systemctl', 'is-enabled', '--quiet', UNIT + '.timer'], capture_output=True).returncode == 0
    was_active = subprocess.run(['systemctl', 'is-active', '--quiet', UNIT + '.timer'], capture_output=True).returncode == 0
    run(['systemctl', 'stop', UNIT + '.timer']) if existing else None
    run(['systemctl', 'stop', UNIT + '.service']) if existing else None
    try:
        for p, (content, mode) in targets.items(): atomic(p, content, mode)
        if existing:
            # A reconfigured destination must not inherit a migrated ID from the old chat.
            with dbopen() as db:
                db.execute("DELETE FROM state WHERE key='migrated_chat_id'")
                # Reset expired backoff; preserve messages.
                db.execute('UPDATE queue SET due=0')
        if shutil.which('systemd-analyze'):
            run(['systemd-analyze', 'verify', '/etc/systemd/system/' + UNIT + '.service',
                 '/etc/systemd/system/' + UNIT + '.timer'])
        else:
            print('ℹ️ ' + msg('systemd-analyze not found; skipping optional unit verification.',
                              'Δεν βρέθηκε systemd-analyze· παραλείπεται ο προαιρετικός έλεγχος units.'))
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', UNIT + '.timer'])
    except Exception:
        # Best-effort rollback restores owned files and previous timer state.
        subprocess.run(['systemctl', 'disable', '--now', UNIT + '.timer'], capture_output=True)
        for n, p in enumerate(targets):
            if present[p]: shutil.copy2(backup / str(n), p)
            elif p.exists(): p.unlink()
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
        if was_enabled: subprocess.run(['systemctl', 'enable', UNIT + '.timer'], capture_output=True)
        if was_active: subprocess.run(['systemctl', 'start', UNIT + '.timer'], capture_output=True)
        raise
    print(tr('✅ Εγκαταστάθηκε v') + VERSION)
    print(tr('Έλεγχος: sudo linux-telegram-alerts status'))
    print(tr('Ρυθμίσεις: sudo linux-telegram-alerts configure'))
    print('Backup: ' + str(backup))


def main():
    global LANGUAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', default='install' if Path(__file__).name.startswith('install-') else 'run',
                        choices=['install', 'configure', 'run', 'test', 'status', 'enqueue', 'uninstall'])
    parser.add_argument('message', nargs='*')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError(tr('Run with sudo / απαιτείται root'))
    if sys.version_info < (3, 9): raise RuntimeError('Python 3.9+ required')
    os.umask(0o077)
    if args.command in ('install', 'configure'):
        install()
        return
    if args.command == 'uninstall':
        print(tr('Αφαιρεί μόνο agent/service/timer. Κρατά token/config/ουρά/backup για ανάκτηση.'))
        if not yes_no('Uninstall alerts?' if LANGUAGE == 'en' else 'Αφαίρεση ειδοποιήσεων;'): return
        run(['systemctl', 'disable', '--now', UNIT + '.timer'])
        run(['systemctl', 'stop', UNIT + '.service'])
        for p in (APP, Path('/etc/systemd/system/' + UNIT + '.service'), Path('/etc/systemd/system/' + UNIT + '.timer')):
            p.unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'])
        print(tr('Απεγκαταστάθηκε. Διατηρήθηκαν ') + str(CONF) + tr(' και ') + str(BASE))
        return
    c = config()
    LANGUAGE = c.get('language', 'en')
    with dbopen() as db:
        if args.command == 'status':
            count, oldest = db.execute('SELECT count(*),min(created) FROM queue').fetchone()
            print('Version: {}\nServer: {}\nChat: {}\nEnabled: {}\nQueue: {}\nOldest Unix timestamp: {}'.format(
                VERSION, c['label'], c['chat_id'], ', '.join(c['enabled']), count, oldest))
            print(run(['systemctl', 'show', UNIT + '.timer', '-p', 'ActiveState', '-p', 'NextElapseUSecMonotonic']))
            return
        if args.command == 'enqueue':
            if 'custom' not in c['enabled']: raise RuntimeError('Custom alerts disabled')
            # stdin supported to keep message out of process arguments.
            text = ' '.join(args.message) if args.message else sys.stdin.read(10000)
            if not text.strip(): raise ValueError('Empty message')
            notify(db, c, '📦 Custom event', text)
            return
        with (BASE / 'collector.lock').open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            migration = get(db, 'migrated_chat_id')
            if migration: c['chat_id'] = migration
            if args.command == 'test':
                notify(db, c, tr('🧪 Δοκιμή Telegram'), '✅ Unicode / emoji / persistent queue test')
            else:
                # Drain first: a full queue must not prevent retries and cause deadlock.
                deliver(db, c)
                collect(db, c)
            db.commit()
            empty = deliver(db, c)
            if args.command == 'test':
                print(tr('✅ Παραδόθηκαν όλα τα μηνύματα.') if empty else tr('⏳ Εκκρεμεί παράδοση· δείτε status/journal.'))
                if not empty: sys.exit(2)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(tr('\nΑκυρώθηκε.'), file=sys.stderr)
        sys.exit(130)
    except APIError as error:
        print(str(error) + tr(' — ελέγξτε token, ID και δικαιώματα bot.'), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        # Suppress network exception repr: it can embed a token-bearing URL.
        print('Linux Telegram Alerts: {}: {}'.format(type(error).__name__,
              str(error) if isinstance(error, (RuntimeError, ValueError)) else tr('Ελέγξτε prerequisites / permissions / τοπικό journal.')), file=sys.stderr)
        sys.exit(1)
