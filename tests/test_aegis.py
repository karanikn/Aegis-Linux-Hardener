"""Offline safety/behavior tests. No real APT, SSH or firewall modifications."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from aegis import actions, catalog, security, system


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

app = load('aegis_entry', ROOT / 'aegis.py')
stage = load('aegis_stage', ROOT / 'install_stage.py')


class SystemTests(unittest.TestCase):
    def test_os_release_does_not_execute_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'os-release'
            path.write_text('ID=ubuntu\nPRETTY_NAME="Ubuntu test"\nID_LIKE=debian\nX="$(touch /tmp/not-executed)"\n')
            result = system.os_release(path)
            self.assertEqual(result['X'], '$(touch /tmp/not-executed)')
            self.assertTrue(system.debian_based(result))

    def test_docker_base_maps_derivative_to_ubuntu(self):
        self.assertEqual(system.base_distribution({'ID': 'linuxmint', 'UBUNTU_CODENAME': 'noble'}), ('ubuntu', 'noble'))

    def test_unknown_suite_not_guessed(self):
        with self.assertRaises(ValueError): system.base_distribution({'ID': 'kali', 'VERSION_CODENAME': 'kali-rolling'})

    def test_non_debian_not_claimed_supported(self):
        self.assertFalse(system.debian_based({'ID': 'fedora'}))

    def test_memory_uses_available(self):
        with patch.object(system, 'read', return_value='MemTotal: 1000 kB\nMemAvailable: 400 kB\nMemFree: 50 kB\nSwapTotal: 0 kB\n'):
            result = system.memory()
        self.assertAlmostEqual(result['used_pct'], 60)
        self.assertEqual(result['swap_pct'], 0)

    def test_missing_optional_command_does_not_crash(self):
        code, text, error = system.command(['/command/that/does/not/exist'])
        self.assertEqual(code, 127)
        self.assertTrue(error)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = patch.object(actions, 'STATE', self.root / 'state')
        self.policy = patch.object(actions, 'POLICY', self.root / 'policy-rc.d')
        self.uid = patch.object(actions.os, 'geteuid', return_value=0)
        for p in (self.state, self.policy, self.uid): p.start()
        self.file = self.root / 'config'
        self.file.write_text('old\n')
        self.file.chmod(0o640)

    def tearDown(self):
        for p in (self.state, self.policy, self.uid): p.stop()
        self.temp.cleanup()

    def manifest(self):
        path = next((actions.STATE / 'backups').glob('*/manifest.json'))
        return path.parent, json.loads(path.read_text())

    def test_cancel_creates_no_snapshot_or_file_change(self):
        with patch('builtins.input', return_value='NO'):
            self.assertIsNone(actions.apply(actions.Plan('test', writes={str(self.file): 'new'})))
        self.assertEqual(self.file.read_text(), 'old\n')
        self.assertFalse(actions.STATE.exists())

    def test_apply_and_manual_restore_preserve_modes(self):
        plan = actions.Plan('test', writes={str(self.file): 'new'})
        with patch('builtins.input', return_value='y'), patch.object(actions, 'checked'):
            actions.apply(plan)
        self.assertEqual(self.file.read_text(), 'new')
        folder, manifest = self.manifest()
        actions.restore(folder, manifest)
        self.assertEqual(self.file.read_text(), 'old\n')
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o640)

    def test_failed_validation_restores_and_records_failure(self):
        plan = actions.Plan('test', writes={str(self.file): 'new'}, validate=[['fake-validator']])
        with patch('builtins.input', return_value='y'), patch.object(actions, 'checked', side_effect=RuntimeError('invalid')):
            with self.assertRaises(RuntimeError): actions.apply(plan)
        self.assertEqual(self.file.read_text(), 'old\n')
        self.assertEqual(self.manifest()[1]['status'], 'rolled-back')

    def test_new_file_removed_on_rollback(self):
        new = self.root / 'new-file'
        with patch('builtins.input', return_value='y'), patch.object(actions, 'checked'):
            actions.apply(actions.Plan('new', writes={str(new): 'content'}))
        folder, manifest = self.manifest()
        actions.restore(folder, manifest)
        self.assertFalse(new.exists())

    def test_timer_armed_before_file_mutation(self):
        calls = []
        def check(args):
            calls.append(args)
            if args[0] == 'systemd-run': self.assertEqual(self.file.read_text(), 'old\n')
        with patch('builtins.input', return_value='y'), patch.object(actions, 'checked', side_effect=check), \
             patch.object(actions.shutil, 'which', return_value='/usr/bin/systemd-run'), \
             patch.object(actions.system, 'command', return_value=(0, 'active', '')):
            actions.apply(actions.Plan('critical', writes={str(self.file): 'new'}, critical=True), 'old-session')
        self.assertEqual(calls[0][0], 'systemd-run')
        self.assertEqual(self.manifest()[1]['status'], 'awaiting-confirmation')

    def test_missing_timer_support_blocks_before_writes(self):
        with patch('builtins.input', return_value='y'), patch.object(actions.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'systemd-run'): actions.apply(actions.Plan('critical', critical=True))
        self.assertEqual(self.file.read_text(), 'old\n')

    def test_same_ssh_connection_cannot_confirm(self):
        folder = self.root / 'manifest'; folder.mkdir()
        manifest = {'status': 'awaiting-confirmation', 'origin': 'same'}
        with patch.object(actions, 'load_manifest', return_value=(folder, manifest)):
            with self.assertRaisesRegex(ValueError, 'NEW SSH'): actions.confirm('id', 'same')

    def test_new_ssh_connection_confirms_and_stops_timer(self):
        folder = self.root / 'manifest'; folder.mkdir()
        manifest = {'id': 'id', 'title': 'test', 'status': 'awaiting-confirmation', 'origin': 'old'}
        with patch.object(actions, 'load_manifest', return_value=(folder, manifest)), \
             patch('builtins.input', return_value='y'), patch.object(actions, 'checked') as check:
            actions.confirm('id', 'new')
        self.assertEqual(manifest['status'], 'confirmed')
        self.assertIn('aegis-rollback-id.timer', check.call_args[0][0])

    def test_existing_policy_is_not_overwritten(self):
        actions.POLICY.write_text('administrator policy')
        with patch('builtins.input', return_value='y'):
            with self.assertRaisesRegex(RuntimeError, 'policy-rc.d'):
                actions.apply(actions.Plan('install', suppress_services=True))
        self.assertEqual(actions.POLICY.read_text(), 'administrator policy')

    def test_policy_guard_covers_package_and_local_config(self):
        seen = []
        def check(args):
            seen.append(actions.POLICY.exists())
        plan = actions.Plan('package', validate=[['fake-install']], suppress_services=True,
                            late_writes={str(self.file): 'localhost-only'}, commands=[['fake-start']])
        with patch('builtins.input', return_value='y'), patch.object(actions, 'checked', side_effect=check):
            actions.apply(plan)
        self.assertEqual(seen, [True, False])
        self.assertEqual(self.file.read_text(), 'localhost-only')
        self.assertFalse(actions.POLICY.exists())

    def test_pending_change_blocks_another_apply(self):
        folder = actions.STATE / 'backups/test'; folder.mkdir(parents=True)
        (folder / 'manifest.json').write_text('{"status":"awaiting-confirmation"}')
        with patch('builtins.input', return_value='y'):
            with self.assertRaisesRegex(RuntimeError, 'previous change'):
                actions.apply(actions.Plan('test', writes={str(self.file): 'new'}))
        self.assertEqual(self.file.read_text(), 'old\n')

    def test_symlink_write_is_refused(self):
        link = self.root / 'link'; link.symlink_to(self.file)
        with self.assertRaises(RuntimeError): actions.write_file(link, 'bad')
        self.assertEqual(self.file.read_text(), 'old\n')


class SecurityTests(unittest.TestCase):
    def test_ip_and_jail_validation_reject_injection(self):
        for name in ('sshd; reboot', 'sshd\n[DEFAULT]'):
            with self.assertRaises(ValueError): security.jail_name(name)
        with self.assertRaises(ValueError): security.network('1.2.3.4; reboot')
        self.assertEqual(security.network('192.168.5.12/24'), '192.168.5.0/24')

    def test_fail2ban_plan_limits_what_it_changes(self):
        with patch.object(security, 'require'), patch.object(security, 'available_jails', return_value=[('sshd', 'SSH')]), \
             patch.object(system, 'service', return_value='inactive'):
            plan = security.fail2ban_plan(['sshd'], '10.1.1.0/24', '6', '600', '900', '2222')
        text = next(iter(plan.writes.values()))
        self.assertIn('port = 2222', text)
        self.assertIn('backend = systemd', text)
        self.assertNotIn('banaction', text)
        self.assertEqual(plan.validate, [['fail2ban-client', '-t']])

    def test_no_invalid_or_unavailable_jail(self):
        with patch.object(security, 'require'), patch.object(security, 'available_jails', return_value=[]):
            with self.assertRaises(ValueError): security.fail2ban_plan(['arbitrary'], '', 6, 600, 900, 22)

    def test_sysctl_does_not_disable_forwarding(self):
        with patch.object(system, 'command', return_value=(0, '0', '')):
            plan = security.sysctl_plan()
        text = next(iter(plan.writes.values()))
        self.assertNotIn('ip_forward', text)
        self.assertEqual(len(plan.rollback_commands), 4)

    def test_unknown_privileged_action_is_rejected(self):
        with patch.object(system, 'debian_based', return_value=True):
            with self.assertRaises(ValueError): app.dispatch({'kind': 'shell', 'command': 'reboot'}, '')

    def test_keys_only_requires_explicit_verified_session(self):
        with patch.object(system, 'debian_based', return_value=True), patch.object(security, 'ssh_plan', return_value=actions.Plan('ssh')):
            with self.assertRaisesRegex(ValueError, 'second-session'):
                app.dispatch({'kind': 'ssh', 'mode': 'keys-only', 'user': 'test', 'source': '127.0.0.1'}, '')


class CatalogTests(unittest.TestCase):
    def test_ucare_first_and_requested_apps_present(self):
        self.assertEqual(catalog.APPS[0][0], 'ucaresystem-core')
        self.assertTrue({'docker', 'caddy', 'webmin', 'winboat', 'cockpit'} <= {x[0] for x in catalog.APPS})

    def test_existing_apps_are_not_reinstalled_or_migrated(self):
        with patch.object(catalog, 'app_version', return_value='existing'):
            with self.assertRaisesRegex(ValueError, 'Already installed'): catalog.app_plan('docker', 'user')

    def test_cockpit_binds_only_loopback(self):
        with patch.object(catalog, 'app_version', return_value=None), patch.object(system, 'debian_based', return_value=True):
            plan = catalog.app_plan('cockpit', 'user')
        text = next(iter(plan.writes.values()))
        self.assertIn('ListenStream=127.0.0.1:9090', text)
        self.assertNotIn('0.0.0.0', text)
        self.assertTrue(plan.suppress_services)

    def test_caddy_local_file_is_written_after_package_install(self):
        with patch.object(catalog, 'app_version', return_value=None), \
             patch.object(catalog, 'fetch', return_value=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture'), \
             patch.object(catalog.Path, 'exists', return_value=False):
            plan = catalog.app_plan('caddy', 'user')
        self.assertIn('127.0.0.1:8080', plan.late_writes['/etc/caddy/Caddyfile'])
        self.assertNotIn('/etc/caddy/Caddyfile', plan.writes)
        self.assertTrue(plan.suppress_services)
        self.assertIn(['apt-get', 'install', 'caddy'], plan.validate)

    def test_webmin_preserves_tls_settings_and_limits_binding(self):
        with patch.object(catalog, 'app_version', return_value=None), \
             patch.object(catalog, 'fetch', return_value=b'-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture'), \
             patch.object(catalog.Path, 'exists', return_value=False):
            plan = catalog.app_plan('webmin', 'user')
        text = plan.late_writes['/etc/webmin/miniserv.conf']('keyfile=/etc/webmin/miniserv.pem\nbind=0.0.0.0\n')
        self.assertIn('keyfile=/etc/webmin/miniserv.pem', text)
        self.assertIn('bind=127.0.0.1', text)
        self.assertNotIn('bind=0.0.0.0', text)
        self.assertEqual(plan.modes['/etc/webmin/miniserv.conf'], 0o600)

    def test_docker_does_not_remove_conflicting_runtime(self):
        with patch.object(catalog, 'app_version', return_value=None), \
             patch.object(system, 'base_distribution', return_value=('debian', 'bookworm')), \
             patch.object(system, 'installed', side_effect=lambda package: '1' if package == 'containerd' else None), \
             patch.object(catalog, 'fetch') as fetch:
            with self.assertRaisesRegex(ValueError, 'NOT removed'): catalog.app_plan('docker', 'user')
            fetch.assert_not_called()

    def test_missing_winboat_requirements_do_not_trigger_install(self):
        with patch.object(catalog, 'app_version', return_value=None), patch.object(catalog, 'winboat_requirements', return_value=['KVM missing']), \
             patch.object(catalog, 'latest_asset') as download:
            with self.assertRaisesRegex(ValueError, 'KVM missing'): catalog.app_plan('winboat', 'user')
            download.assert_not_called()

    def test_release_digest_mismatch_rejected(self):
        metadata = {'assets': [{'name': 'ucaresystem-core_1_all.deb',
            'browser_download_url': 'https://github.com/Utappia/uCareSystem/releases/download/v1/file.deb', 'digest': 'sha256:wrong'}]}
        with patch.object(catalog, 'fetch', side_effect=[json.dumps(metadata).encode(), b'package']):
            with self.assertRaisesRegex(ValueError, 'SHA256'): catalog.latest_asset('Utappia/uCareSystem', r'ucaresystem-core_.*\.deb')


class UITests(unittest.TestCase):
    def test_unusable_terminal_falls_back_to_numbered_menu(self):
        from aegis.ui import UI
        def broken_wrapper(callback): raise ValueError('unsupported TERM')
        fake = types.SimpleNamespace(wrapper=broken_wrapper)
        with patch.dict(sys.modules, {'curses': fake}), patch.object(sys.stdin, 'isatty', return_value=True), \
             patch.dict(os.environ, {'TERM': 'unsupported-terminal'}), patch('builtins.input', return_value='1'):
            self.assertEqual(UI().choose('test', [('ok', 'Test', 'Read only')]), 'ok')


class ArchiveTests(unittest.TestCase):
    def test_path_traversal_rejected(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as tar:
            entry = tarfile.TarInfo('../escape'); entry.size = 1
            tar.addfile(entry, io.BytesIO(b'x'))
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError): stage.extract(data.getvalue(), Path(folder))

    def test_archive_symlink_rejected(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as tar:
            entry = tarfile.TarInfo('link'); entry.type = tarfile.SYMTYPE; entry.linkname = '/etc'
            tar.addfile(entry)
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError): stage.extract(data.getvalue(), Path(folder))


if __name__ == '__main__': unittest.main(verbosity=2)
