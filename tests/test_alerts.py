"""Offline tests. No host installation / κανένα πραγματικό Telegram request."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('alerts', Path(__file__).resolve().parents[1] / 'aegis/alerts.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class AlertsTests(unittest.TestCase):
    def setUp(self):
        a.LANGUAGE = 'el'
        a.UNAVAILABLE = {}
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.base = patch.object(a, 'BASE', self.root / 'state')
        self.conf = patch.object(a, 'CONF', self.root / 'config')
        self.f2b = patch.object(a, 'F2B_LOG', self.root / 'fail2ban.log')
        for p in (self.base, self.conf, self.f2b): p.start()
        a.CONF.mkdir()
        (a.CONF / 'telegram.token').write_text('123:SECRET_FOR_TEST_ONLY')
        self.c = {**a.DEFAULTS, 'label': 'TENA-Deb-01', 'chat_id': '-100123',
                  'enabled': [k for k, _, _ in a.CATEGORIES]}
        self.db = a.dbopen()

    def tearDown(self):
        self.db.close()
        for p in (self.base, self.conf, self.f2b): p.stop()
        self.temp.cleanup()

    def queued(self):
        return self.db.execute('SELECT text FROM queue ORDER BY id').fetchall()

    def test_ssh_extracts_fields_without_raw_log(self):
        event = a.classify({'_COMM': 'sshd-session', 'MESSAGE': 'Accepted publickey for nikos from 10.1.1.22 port 55022 ssh2 TOKEN_X'})
        self.assertEqual(event[0], 'ssh_login')
        self.assertIn('nikos', event[2])
        self.assertIn('10.1.1.22', event[2])
        self.assertNotIn('TOKEN_X', event[2])

    def test_ssh_failure_and_sudo(self):
        self.assertEqual(a.classify({'_COMM': 'sshd', 'MESSAGE': 'Failed password for invalid user test from 10.0.0.1'})[0], 'ssh_fail')
        self.assertEqual(a.classify({'_COMM': 'sudo', 'MESSAGE': 'pam_unix(sudo:auth): authentication failure'})[0], 'sudo_fail')

    def test_unban_ipv6(self):
        event = a.classify({'_COMM': 'fail2ban-server', 'MESSAGE': '[sshd] Unban 2001:db8::123'})
        self.assertEqual(event[0], 'unban')
        self.assertIn('2001:db8::123', event[2])

    def test_no_arbitrary_log_forwarding(self):
        self.assertIsNone(a.classify({'_COMM': 'random', 'MESSAGE': 'Accepted password for root from 1.2.3.4 port 2'}))
        self.assertIsNone(a.classify({'MESSAGE': [1, 2, 3]}))

    def test_oom_and_kernel(self):
        self.assertEqual(a.classify({'_TRANSPORT': 'kernel', 'MESSAGE': 'Out of memory: Killed process 123 (app)'})[0], 'oom')
        self.assertEqual(a.classify({'_TRANSPORT': 'kernel', 'PRIORITY': '3', 'MESSAGE': 'disk error'})[0], 'kernel')

    def test_certbot_success_requires_explicit_message(self):
        self.assertIsNone(a.classify({'_COMM': 'certbot', 'MESSAGE': 'Starting renewal'}))
        self.assertEqual(a.classify({'_COMM': 'certbot', 'MESSAGE': 'All renewals succeeded'})[0], 'certbot')

    def test_unicode_persistent_queue(self):
        a.notify(self.db, self.c, '🚀 Εκκίνηση', 'Σύνδεση επιτυχής')
        self.db.commit()
        other = sqlite3.connect(str(a.BASE / 'events.sqlite3'))
        self.assertIn('Εκκίνηση', other.execute('SELECT text FROM queue').fetchone()[0])
        self.assertNotIn('SECRET', self.queued()[0][0])
        other.close()

    def test_cursor_and_events_rollback_together(self):
        self.db.commit()
        with self.assertRaises(RuntimeError):
            with self.db:
                a.notify(self.db, self.c, 'test')
                a.put(self.db, 'cursor', 'advance')
                raise RuntimeError('Simulated crash before commit')
        self.assertEqual(len(self.queued()), 0)
        self.assertIsNone(a.get(self.db, 'cursor'))

    def test_queue_limit_preserves_existing(self):
        self.c['queue_max'] = 1
        a.notify(self.db, self.c, 'first')
        with self.assertRaises(RuntimeError): a.notify(self.db, self.c, 'second')
        self.assertEqual(len(self.queued()), 1)

    def test_successful_delivery_deletes_only_after_api_ok(self):
        a.notify(self.db, self.c, 'test')
        with patch.object(a, 'api', return_value={}) as api, patch.object(a.time, 'sleep'):
            self.assertTrue(a.deliver(self.db, self.c))
        self.assertEqual(api.call_args[0][2]['chat_id'], '-100123')
        self.assertEqual(self.queued(), [])

    def test_429_persists_and_obeys_retry_after(self):
        a.notify(self.db, self.c, 'test')
        with patch.object(a, 'api', side_effect=a.APIError(429, 120)), patch.object(a.time, 'time', return_value=1000):
            self.assertFalse(a.deliver(self.db, self.c))
        attempt, due = self.db.execute('SELECT attempt,due FROM queue').fetchone()
        self.assertEqual((attempt, due), (1, 1120))

    def test_migration_keeps_message(self):
        a.notify(self.db, self.c, 'test')
        with patch.object(a, 'api', side_effect=a.APIError(400, migrate=-100999)):
            a.deliver(self.db, self.c)
        self.assertEqual(a.get(self.db, 'migrated_chat_id'), '-100999')
        self.assertEqual(len(self.queued()), 1)

    def test_backoff_skips_network(self):
        a.notify(self.db, self.c, 'test')
        self.db.execute('UPDATE queue SET due=99999999999')
        with patch.object(a, 'api') as api:
            self.assertFalse(a.deliver(self.db, self.c))
            api.assert_not_called()

    def test_sustained_limit_and_one_recovery(self):
        with patch.object(a.time, 'time', return_value=1000):
            a.transition(self.db, self.c, 'ram', True, 'RAM', '', sustained=True)
        self.assertEqual(len(self.queued()), 0)
        with patch.object(a.time, 'time', return_value=1181):
            a.transition(self.db, self.c, 'ram', True, 'RAM', '', sustained=True)
            a.transition(self.db, self.c, 'ram', True, 'RAM', '', sustained=True)
        self.assertEqual(len(self.queued()), 1)
        a.transition(self.db, self.c, 'ram', False, 'RAM', '')
        a.transition(self.db, self.c, 'ram', False, 'RAM', '')
        self.assertEqual(len(self.queued()), 2)
        self.assertIn('Αποκατάσταση', self.queued()[-1][0])

    def test_service_inactive_is_not_recovery(self):
        a.put(self.db, 'failed_services', ['app.service'])
        with patch.object(a, 'run', side_effect=['', 'inactive']): a.services(self.db, self.c)
        self.assertEqual(self.queued(), [])
        with patch.object(a, 'run', side_effect=['', 'active']): a.services(self.db, self.c)
        self.assertEqual(len(self.queued()), 1)

    def test_journal_replay_dedup(self):
        e = {'MESSAGE': 'Accepted publickey for nikos from 10.1.1.22 port 5000',
             '_COMM': 'sshd', '__CURSOR': 'abc', '__REALTIME_TIMESTAMP': '1000000000000000'}
        text = json.dumps(e) + '\n-- cursor: abc\n'
        result = a.subprocess.CompletedProcess([], 0, text, '')
        with patch.object(a.subprocess, 'run', return_value=result):
            a.journal(self.db, self.c)
            a.journal(self.db, self.c)
        self.assertEqual(len(self.queued()), 1)
        self.assertEqual(a.get(self.db, 'cursor'), 'abc')

    def test_fail2ban_initial_eof_append_rotation(self):
        a.F2B_LOG.write_text('old [sshd] Ban 192.0.2.1\n')
        a.fail2ban(self.db, self.c)
        self.assertEqual(len(self.queued()), 0)
        with a.F2B_LOG.open('a') as f: f.write('new [sshd] Ban 192.0.2.2\n')
        a.fail2ban(self.db, self.c)
        a.fail2ban(self.db, self.c)
        self.assertEqual(len(self.queued()), 1)
        with a.F2B_LOG.open('a') as f: f.write('rotate [sshd] Unban 192.0.2.2\n')
        a.F2B_LOG.rename(a.F2B_LOG.with_name('fail2ban.log.1'))
        a.F2B_LOG.write_text('new-file [sshd] Ban 192.0.2.3\n')
        a.fail2ban(self.db, self.c)
        self.assertEqual(len(self.queued()), 3)

    def test_docker_state_changed(self):
        a.put(self.db, 'docker', {'abc': {'name': 'web', 'status': 'running', 'health': 'healthy', 'restart': 0}})
        item = {'Id': 'abc', 'Name': '/web', 'State': {'Status': 'exited'}, 'RestartCount': 0}
        with patch.object(a, 'run', side_effect=['abc\n', json.dumps(item) + '\n']):
            a.docker(self.db, self.c)
        self.assertIn('exited', self.queued()[0][0])

    def test_cert_expired_alert(self):
        cert = self.root / 'cert.pem'
        cert.write_text('placeholder')
        self.c['cert_globs'] = [str(cert)]
        with patch.object(a, 'run', return_value='notAfter=Jan  1 00:00:00 2020 GMT\n'):
            a.certs(self.db, self.c)
        self.assertEqual(len(self.queued()), 1)
        self.assertIn('Υπολειπόμενες', self.queued()[0][0])

    def test_token_api_error_is_redacted(self):
        err = a.APIError(403)
        self.assertNotIn('SECRET', str(err))
        self.assertNotIn('https', str(err))



# Installer integration tests: redirect every absolute system path into a temp tree.
class InstallerTests(unittest.TestCase):
    setUp = AlertsTests.setUp
    tearDown = AlertsTests.tearDown

    def simulate(self, fail_enable=False):
        real_path = Path
        sysroot = self.root / 'system'
        (sysroot / 'run/systemd/system').mkdir(parents=True)
        (sysroot / 'etc/systemd/system').mkdir(parents=True)
        (sysroot / 'usr/local/sbin').mkdir(parents=True)
        app = sysroot / 'usr/local/sbin/linux-telegram-alerts'
        if fail_enable:
            (a.CONF / 'config.json').write_text(json.dumps(self.c))
            app.write_text('original-agent')
        else:
            (a.CONF / 'telegram.token').unlink()
        def path(value):
            text = str(value)
            if text.startswith(('/run/systemd/', '/etc/systemd/', '/etc/fail2ban/')):
                return real_path(str(sysroot) + text)
            return real_path(value)
        def command(args, timeout=15):
            if fail_enable and args[:3] == ['systemctl', 'enable', '--now']:
                raise RuntimeError('Simulated enable failure')
            return ''
        # Answers: hostname/token retention/chat/topic, interval, thresholds, sustain,
        # mounts/time, confirmation. Checklist is narrowed to boot to isolate installer.
        answers = iter(['2', 'Test server', '-100123', '0', '60', 'y'])
        with patch.object(a, 'Path', side_effect=path), patch.object(a, 'APP', app), \
             patch.object(a.sys.stdin, 'isatty', return_value=True), \
             patch.object(a, 'checklist', return_value=['boot']), \
             patch.object(a, 'dependencies'), patch.object(a, 'unavailable', return_value={}), patch.object(a, 'api', return_value={}), \
             patch.object(a, 'run', side_effect=command), \
             patch.object(a.subprocess, 'run', return_value=a.subprocess.CompletedProcess([], 1)), \
             patch.object(a.getpass, 'getpass', return_value='123456:abcdefghijklmnopqrstuvwx'), \
             patch('builtins.input', side_effect=lambda prompt: next(answers)):
            a.install()
        return app, sysroot

    def test_install_targets_permissions_and_units(self):
        app, root = self.simulate()
        self.assertTrue(app.exists())
        self.assertEqual((a.CONF / 'telegram.token').stat().st_mode & 0o777, 0o600)
        self.assertEqual(a.CONF.stat().st_mode & 0o777, 0o700)
        conf = json.loads((a.CONF / 'config.json').read_text())
        self.assertEqual(conf['enabled'], ['boot'])
        self.assertNotIn('abcdefghijkl', app.read_text())
        self.assertIn('OnUnitInactiveSec=60s', (root / 'etc/systemd/system/linux-telegram-alerts.timer').read_text())

    def test_failed_enable_rolls_back_files(self):
        with self.assertRaisesRegex(RuntimeError, 'Simulated enable'):
            self.simulate(fail_enable=True)
        self.assertEqual(json.loads((a.CONF / 'config.json').read_text()), self.c)
        # Token existed before install; it is restored exactly.
        self.assertEqual((a.CONF / 'telegram.token').read_text(), '123:SECRET_FOR_TEST_ONLY')
        self.assertEqual((self.root / 'system/usr/local/sbin/linux-telegram-alerts').read_text(), 'original-agent')




class NewBehaviorTests(unittest.TestCase):
    setUp = AlertsTests.setUp
    tearDown = AlertsTests.tearDown
    queued = AlertsTests.queued
    def test_english_ui_and_message(self):
        a.LANGUAGE = 'en'
        self.assertEqual(a.tr('Όνομα πελάτη / server'), 'Customer / server name')
        event = a.classify({'_COMM': 'sshd', 'MESSAGE': 'Accepted publickey for nikos from 10.0.0.1 port 123'})
        self.assertEqual(event[1], '🔐 SSH login')
        a.transition(self.db, self.c, 'ram', True, 'RAM', '')
        a.transition(self.db, self.c, 'ram', False, 'RAM', '')
        self.assertIn('Recovered', self.queued()[-1][0])

    def test_language_choice_default_and_greek(self):
        with patch('builtins.input', return_value=''):
            self.assertEqual(a.choose_language(), 'en')
        with patch('builtins.input', return_value='2'):
            self.assertEqual(a.choose_language(), 'el')

    def test_missing_docker_skips_and_continues(self):
        a.LANGUAGE = 'en'
        self.c['enabled'] = ['boot', 'docker', 'services']
        with patch.object(a.shutil, 'which', side_effect=lambda name: None if name == 'docker' else '/usr/bin/' + name):
            a.dependencies(self.c)
        self.assertEqual(self.c['enabled'], ['boot', 'services'])

    def test_core_missing_still_explains_required_systemd(self):
        with patch.object(a.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'required systemd'):
                a.dependencies(self.c)

    def test_missing_certificates_does_not_queue_problem(self):
        self.c['cert_globs'] = [str(self.root / 'does-not-exist/*.pem')]
        a.certs(self.db, self.c)
        a.certs(self.db, self.c)
        self.assertEqual(self.queued(), [])
        self.c['enabled'] = ['certs', 'boot']
        a.skip_optional(self.c, check_paths=True)
        self.assertEqual(self.c['enabled'], ['boot'])

    def test_all_translatable_literals_have_english_translation(self):
        import ast
        tree = ast.parse(Path(a.__file__).read_text())
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'tr' and n.args and isinstance(n.args[0], ast.Constant):
                text = n.args[0].value
                if isinstance(text, str) and any('\u0370' <= ch <= '\u03ff' for ch in text):
                    self.assertIn(text, a.EN)
        for _, label, _ in a.CATEGORIES:
            self.assertIn(label, a.EN)

    def test_unavailable_checkbox_cannot_be_selected(self):
        a.LANGUAGE = 'en'
        a.UNAVAILABLE = {'docker': 'docker command not found'}
        index = next(i for i, x in enumerate(a.CATEGORIES, 1) if x[0] == 'docker')
        with patch.object(a.sys.stdin, 'isatty', return_value=False), patch('builtins.input', side_effect=[str(index), '']):
            selected = a.checklist(['boot', 'docker'])
        self.assertEqual(selected, ['boot'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
