"""Offline log/export/launch and menu regression checks. No real Telegram sends."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
import urllib.error
from unittest.mock import Mock,patch
from aegis import actions,catalog,launch,logs,system

spec=importlib.util.spec_from_file_location('aegis_v04_entry',Path(__file__).resolve().parents[1]/'aegis.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)


def snapshot():return {'category':'system','label':'System','text':'reviewed snapshot\n','filename':'aegis-system-20261111-120000.log'}


class LogsV04(unittest.TestCase):
    def test_ccze_registered_once(self):
        self.assertEqual([r[0] for r in catalog.APPS].count('ccze'),1)
    def test_control_sequences_and_known_secrets_masked(self):
        text='\x1b[31mred\x1b[0m\x1b]0;BAD\x07 password="secret one" api_key=example Authorization: Bearer abc 123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef user@example.org'
        cleaned=logs.clean(text)
        self.assertNotIn('\x1b',cleaned);self.assertNotIn('secret one',cleaned);self.assertNotIn('Bearer abc',cleaned)
        self.assertNotIn('ABCDEFGHIJKLMNOPQRSTUVWXYZ',cleaned);self.assertNotIn('api_key=example',cleaned)
        self.assertIn('user@example.org',cleaned)
    def test_invalid_category_and_query_never_run(self):
        with patch.object(system,'command') as command:
            for args in [('bad','today',500,''),('system','yesterday;id',500,''),('service','today',500,'ssh.service; id')]:
                with self.assertRaises(ValueError):logs.collect(*args)
            command.assert_not_called()
    def test_journal_unit_and_limit_are_separate_arguments(self):
        with patch.object(system,'command',return_value=(0,'line\n','')) as command:
            result=logs.collect('service','hour',200,'ssh.service')
        args=command.call_args.args[0]
        self.assertIn('ssh.service',args);self.assertIn('1 hour ago',args);self.assertNotIn('--no-all',args)
        self.assertIn('line',result['text'])
    def test_container_stderr_is_log_content(self):
        with patch.object(system,'command',return_value=(0,'stdout','stderr')):
            result=logs.collect('container','day',100,'demo')
        self.assertIn('stderr',result['text'])
    def test_custom_file_cannot_read_etc(self):
        with self.assertRaises(ValueError):logs.tail_file('/etc/passwd',100)
    def test_custom_file_symlink_outside_log_root_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'link';path.symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):logs.tail_file(path,100)
    def test_ccze_raw_ansi_and_no_lookups(self):
        with patch('shutil.which',return_value='/usr/bin/ccze'),patch.object(logs.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout='colored')) as run:
            self.assertEqual(logs.colorize('snapshot'),'colored')
        self.assertEqual(run.call_args.args[0],['ccze','-A','-o','nolookups'])
    def test_missing_ccze_has_plain_fallback(self):
        with patch('shutil.which',return_value=None):self.assertEqual(logs.colorize('plain'),'plain')
    def test_export_private_and_original_user_owned(self):
        account=types.SimpleNamespace(pw_dir='/home/demo',pw_uid=1000,pw_gid=1000)
        with patch.object(logs.pwd,'getpwnam',return_value=account):
            plan=logs.export_plan(snapshot(),'/home/demo/test.log','demo')
        self.assertEqual(plan.modes['/home/demo/test.log'],0o600)
        self.assertEqual(plan.writes['/home/demo/test.log'],'reviewed snapshot\n')
        self.assertEqual(plan.commands[0],['chown','--','1000:1000','/home/demo/test.log'])
    def test_export_refuses_system_configuration(self):
        account=types.SimpleNamespace(pw_dir='/home/demo',pw_uid=1000,pw_gid=1000)
        with patch.object(logs.pwd,'getpwnam',return_value=account):
            with self.assertRaises(ValueError):logs.export_plan(snapshot(),'/etc/ssh/sshd_config','demo')
    def test_attachment_uses_exact_snapshot_and_topic(self):
        boundary,body=logs.multipart(snapshot(),{'chat_id':'-100123','thread_id':42})
        self.assertIn(b'reviewed snapshot\n',body);self.assertIn(b'message_thread_id',body);self.assertIn(b'42',body)
        self.assertIn(b'filename="aegis-system-20261111-120000.log"',body)
    def test_filename_cannot_inject_multipart_headers(self):
        data=snapshot();data['filename']='x"\r\nInjected: yes'
        with self.assertRaises(ValueError):logs.multipart(data,{'chat_id':'1'})
    def test_telegram_success_no_real_network(self):
        response=Mock();response.read.return_value=b'{"ok":true,"result":{"message_id":123}}'
        response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        opener=Mock();opener.open.return_value=response
        with patch.object(logs.urllib.request,'build_opener',return_value=opener),patch.object(actions,'event'):
            self.assertEqual(logs.send(snapshot(),{'chat_id':'1'},'FAKE_TOKEN'),123)
        request=opener.open.call_args.args[0]
        self.assertTrue(request.full_url.endswith('/sendDocument'))
    def test_network_error_does_not_leak_token_or_retry(self):
        opener=Mock();opener.open.side_effect=urllib.error.URLError('https://api.telegram.org/botSECRET/sendDocument')
        with patch.object(logs.urllib.request,'build_opener',return_value=opener):
            with self.assertRaises(RuntimeError) as error:logs.send(snapshot(),{'chat_id':'1'},'SECRET')
        self.assertNotIn('SECRET',str(error.exception));self.assertEqual(opener.open.call_count,1)


class LaunchV04(unittest.TestCase):
    def test_tmate_and_ngrok_open_help_only(self):
        with patch('shutil.which',side_effect=lambda name:'/usr/bin/'+name):
            self.assertEqual(launch.launch_args('tmate'),['/usr/bin/tmate','--help'])
            self.assertEqual(launch.launch_args('ngrok'),['/usr/bin/ngrok','help'])
    def test_ncdu_read_only(self):
        with patch('shutil.which',return_value='/usr/bin/ncdu'):self.assertIn('-r',launch.launch_args('ncdu'))
    def test_interface_shell_injection_rejected(self):
        with self.assertRaises(ValueError):launch.launch_args('tcpdump','eth0;id')
    def test_tcpdump_limited_and_explicit_interface(self):
        with patch.object(system.socket,'if_nameindex',return_value=[(1,'eth0')]),patch('shutil.which',return_value='/usr/bin/tcpdump'):
            self.assertEqual(launch.launch_args('tcpdump','eth0'),['/usr/bin/tcpdump','-nn','-i','eth0','-c','100'])
    def test_user_tool_drops_root(self):
        account=types.SimpleNamespace(pw_dir='/home/demo',pw_uid=1000,pw_gid=1000)
        with patch.object(catalog,'app_version',return_value='1'),patch('shutil.which',return_value='/usr/bin/htop'),patch.object(launch.pwd,'getpwnam',return_value=account),patch.object(os,'geteuid',return_value=0),patch.object(launch.subprocess,'run') as run,contextlib.redirect_stdout(io.StringIO()):
            launch.open_app('htop','demo')
        self.assertEqual(run.call_args.args[0][:4],['runuser','-u','demo','--'])
    def test_nmtui_routes_to_protected_flow(self):self.assertIn('Network Settings',launch.GUIDES['nmtui'])


class MenusV04(unittest.TestCase):
    def ui(self):
        ui=Mock();ui.language='en';ui.t.side_effect=lambda en,el:en;ui.choose.return_value=None
        return ui
    def test_help_last_and_security_managers_nested(self):
        ui=self.ui();app.menu(ui)
        entries=ui.choose.call_args.args[1];keys=[e[0] for e in entries]
        self.assertEqual(keys[-1],'help');self.assertIn('logs',keys)
        self.assertNotIn('fail2ban',keys);self.assertNotIn('firewall',keys)
        ui=self.ui()
        with patch.object(catalog,'package_versions',return_value={}):app.hardening_menu(ui)
        keys=[e[0] for e in ui.choose.call_args.args[1]]
        self.assertIn('fail2ban-manager',keys);self.assertIn('firewall-manager',keys)
    def test_network_installed_status_uses_live_detection(self):
        ui=self.ui()
        with patch.object(catalog,'app_version',return_value='1.42'),patch.object(system,'installed',return_value='1'):
            app.network_menu(ui)
        row=next(e for e in ui.choose.call_args.args[1] if e[0]=='nmtui-install')
        self.assertIn('[Installed]',row[1]);self.assertIn('Installed: 1.42',row[2])
    def test_installed_app_offers_open_not_install(self):
        ui=self.ui()
        with patch.object(catalog,'app_version',return_value='3.2'):app.app_actions(ui,'htop')
        keys=[e[0] for e in ui.choose.call_args.args[1]]
        self.assertIn('open',keys);self.assertNotIn('install',keys)
    def test_help_all_reads_complete_packaged_readme(self):
        ui=self.ui();ui.choose.side_effect=['all',None]
        app.help_menu(ui)
        text=(Path(app.ENTRY).parent/'README.md').read_text()
        shown=ui.view.call_args.args[1]
        self.assertNotIn('img.shields.io',shown)
        in_badges=False
        for line in text.splitlines():
            if line=='<!-- aegis:badges -->':in_badges=True;continue
            if line=='<!-- /aegis:badges -->':in_badges=False;continue
            if not in_badges and line.strip():self.assertIn(line,shown)


if __name__=='__main__':unittest.main()
