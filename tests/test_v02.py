"""v0.2 regression/safety tests — no live network or security changes."""
import configparser
import base64
import hashlib
import tarfile
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from aegis import console, networking as n, lynis, system, actions, recovery
from aegis.ui import UI


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
app=load('v02entry',ROOT/'aegis.py')
stage=load('v02stage',ROOT/'install_stage.py')


class PromptTests(unittest.TestCase):
    def test_enter_and_y_confirm(self):
        for value in ('','y','Y','yes'):
            with patch('builtins.input',return_value=value):self.assertTrue(console.confirm('Continue?'))
    def test_n_cancels(self):
        with patch('builtins.input',return_value='n'):self.assertFalse(console.confirm('Continue?'))
    def test_invalid_confirmation_is_not_silently_approved(self):
        with patch('builtins.input',side_effect=['APPLY','n']):self.assertFalse(console.confirm())
    def test_secret_input_is_hidden(self):
        with patch.object(console.getpass,'getpass',return_value='token') as hidden,patch('builtins.input') as raw:
            self.assertEqual(console.ask('Secret',secret=True),'token');hidden.assert_called_once();raw.assert_not_called()


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.etc=patch.object(n,'ETC',self.root/'etc');self.etc.start();n.ETC.mkdir()
    def tearDown(self):self.etc.stop();self.temp.cleanup()
    def test_static_validated_before_changes(self):
        v=n.validate_values('static','192.168.5.20/24','192.168.5.1','192.168.10.5,1.1.1.1')
        self.assertEqual(v['dns'],['192.168.10.5','1.1.1.1'])
    def test_bad_addresses_rejected(self):
        for addr,gw in [('192.168.5.0/24',''),('192.168.5.255/24',''),('192.168.5.20/24','192.168.6.1'),('1.2.3.4; reboot','')]:
            with self.assertRaises(ValueError):n.validate_values('static',addr,gw)
    def test_interface_injection_and_loopback_rejected(self):
        for value in ('lo','eth0;reboot','../eth0'):
            with self.assertRaises(ValueError):n.interface_name(value)
    def test_dhcp_does_not_require_static_values(self):self.assertEqual(n.validate_values('dhcp')['address'],'')
    def test_ifupdown_preserves_ipv6_and_other_interfaces(self):
        p=n.ETC/'network/interfaces';p.parent.mkdir()
        p.write_text('auto lo\niface lo inet loopback\nauto ens18\niface ens18 inet dhcp\niface ens18 inet6 auto\nauto ens19\niface ens19 inet dhcp\n')
        with patch.object(n,'supported_link'),patch.object(n,'detect_backend',return_value=('ifupdown',[p])):
            plan=n.network_plan('ens18','static','192.168.5.20/24','192.168.5.1','-')
        text=plan.writes[str(p)]
        self.assertIn('iface ens18 inet6 auto',text);self.assertIn('iface ens19 inet dhcp',text)
        self.assertIn('address 192.168.5.20/24',text);self.assertTrue(plan.critical);self.assertTrue(plan.detached)
    def test_ifupdown_custom_hooks_are_not_destroyed(self):
        p=n.ETC/'interfaces';p.write_text('iface ens18 inet static\n post-up /custom/script\n')
        with patch.object(n,'supported_link'),patch.object(n,'detect_backend',return_value=('ifupdown',[p])):
            with self.assertRaisesRegex(ValueError,'hooks'):n.network_plan('ens18','dhcp')
    def test_ifupdown_include_source_directory_supported(self):
        p=n.ETC/'network/interfaces';p.parent.mkdir();d=p.parent/'interfaces.d';d.mkdir()
        (d/'server').write_text('iface ens18 inet dhcp\n')
        p.write_text('source-directory interfaces.d\n')
        self.assertIn(d/'server',n.ifupdown_sources())
    def test_nm_secrets_preserved_but_not_printed(self):
        p=n.ETC/'wifi.nmconnection'
        cfg=configparser.ConfigParser(interpolation=None)
        cfg.read_string('[connection]\nuuid=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n[wifi-security]\npsk=PRIVATE-WIFI-SECRET\n[ipv4]\nmethod=auto\n[ipv6]\nmethod=auto\n')
        with patch.object(n,'supported_link'),patch.object(n,'detect_backend',return_value=('networkmanager',(p,'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',cfg))):
            plan=n.network_plan('wlan0','static','192.168.5.20/24','192.168.5.1','1.1.1.1')
        self.assertIn('PRIVATE-WIFI-SECRET',plan.writes[str(p)]);self.assertNotIn('PRIVATE-WIFI-SECRET',plan.preview())
        self.assertIn('[ipv6]\nmethod=auto',plan.writes[str(p)]);self.assertEqual(plan.modes[str(p)],0o600)
    def test_netplan_static_to_dhcp_removes_old_ipv4_without_sequence_merge(self):
        import yaml
        d=n.ETC/'netplan';d.mkdir();p=d/'50-cloud-init.yaml'
        p.write_text('network:\n  version: 2\n  ethernets:\n    ens18:\n      addresses: [192.168.5.20/24, "2001:db8::1/64"]\n      gateway4: 192.168.5.1\n      dhcp4: false\n')
        matches=n.netplan_matches('ens18',n.netplan_documents())
        # Ignore any vendor YAML in the build host; only the fixture controls this test.
        real_glob=Path.glob
        def fixture_glob(path,pattern):
            return iter([]) if str(path) in ('/run/netplan','/lib/netplan') else real_glob(path,pattern)
        with patch.object(n,'supported_link'),patch.object(n,'detect_backend',return_value=('netplan',matches)),patch.object(Path,'glob',fixture_glob):
            plan=n.network_plan('ens18','dhcp')
        old=yaml.safe_load(plan.writes[str(p)])['network']['ethernets']['ens18']
        self.assertEqual(old['addresses'],['2001:db8::1/64']);self.assertNotIn('gateway4',old);self.assertTrue(old['dhcp4'])
        self.assertNotIn('192.168.5.20',plan.writes[str(d/'99-aegis-ens18.yaml')])
    def test_networkd_complex_route_not_silently_replaced(self):
        p=n.ETC/'server.network';p.write_text('[Match]\nName=ens18\n[Network]\nDHCP=yes\n[Route]\nGateway=1.2.3.4\n')
        with patch.object(n,'supported_link'),patch.object(n,'detect_backend',return_value=('networkd',p)):
            with self.assertRaisesRegex(ValueError,'Advanced'):n.network_plan('ens18','dhcp')
    def test_activation_reloads_nm_before_connection_up(self):
        with patch.object(n.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as run:
            n.reload_backend('networkmanager','ens18','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
        self.assertEqual(run.call_args_list[0].args[0],['nmcli','connection','reload'])
        self.assertIn('up',run.call_args_list[1].args[0])


class LynisTests(unittest.TestCase):
    def test_historical_fail2ban_hint_is_not_blindly_applied(self):
        row=next(x for x in lynis.CONTROLS if x[0]=='DEB-0880')
        self.assertIn('invalid',row[3]);self.assertEqual(row[2],'existing')
    def test_irreversible_locks_not_exposed(self):
        self.assertNotIn('kernel.modules_disabled',lynis.EXTRA_SYSCTL)
        self.assertEqual(lynis.EXTRA_SYSCTL['kernel.unprivileged_bpf_disabled'][0],'2')
        self.assertNotEqual(lynis.EXTRA_SYSCTL['kernel.yama.ptrace_scope'][0],'3')
    def test_core_dump_policy_is_file_based_and_undoable(self):
        plan=lynis.plan('core-dumps',{})
        self.assertIn('/etc/security/limits.d/60-aegis-core.conf',plan.writes)
        self.assertIn('Storage=none',next(v for k,v in plan.writes.items() if 'coredump' in k))
    def test_new_user_defaults_do_not_modify_existing_shadow(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(lynis,'ETC',Path(temp)):
            p=Path(temp)/'login.defs';p.write_text('ENCRYPT_METHOD YESCRYPT\nPASS_MAX_DAYS 99999\nUMASK 022\n')
            plan=lynis.plan('login-defaults',{'min_days':'1','max_days':'365'})
            self.assertEqual(list(plan.writes),[str(p)])
            self.assertIn('ENCRYPT_METHOD YESCRYPT',plan.writes[str(p)])
    def test_findings_parser_maps_control_without_executing_it(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'report';p.write_text('warning[]=PKGS-7392|Vulnerable packages|-|-\nsuggestion[]=BOOT-5122|GRUB|-|-\n')
            rows=lynis.findings(p)
        self.assertEqual(rows[0]['coverage'],'inspect');self.assertEqual(rows[1]['coverage'],'manual')
    def test_permissions_snapshot_only_metadata(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(lynis,'ETC',Path(temp)):
            p=Path(temp)/'crontab';p.write_text('example')
            # Root ownership is checked independently; fixture ownership is replaced only in this unit test.
            original=Path.stat
            def fake_stat(path,*args,**kwargs):
                value=original(path,*args,**kwargs)
                return types.SimpleNamespace(st_uid=0,st_mode=value.st_mode) if path==p else value
            with patch.object(Path,'stat',fake_stat):plan=lynis.plan('permissions',{'paths':['crontab']})
            self.assertEqual(plan.metadata,{str(p):0o600});self.assertEqual(plan.writes,{})


class RecoveryTests(unittest.TestCase):
    def test_empty_package_state_is_not_an_undo_promise(self):
        with patch.object(system,'command',return_value=(0,'','')):
            with self.assertRaisesRegex(RuntimeError,'empty'):recovery.inventory()
    def test_new_packages_diff_and_old_version_diff(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/'packages-before.json').write_text(json.dumps({'packages':{'old':'1'},'manual':['old']}))
            (p/'packages-after.json').write_text(json.dumps({'packages':{'old':'2','new':'1'},'manual':['old','new']}))
            before,after,added,changed=recovery.diff(p)
        self.assertEqual(added,['new']);self.assertEqual(changed,['old'])
    def test_missing_old_deb_refuses_to_claim_complete_undo(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/'packages-before.json').write_text(json.dumps({'packages':{'old':'1'},'manual':[]}))
            (p/'packages-after.json').write_text(json.dumps({'packages':{'old':'2'},'manual':[]}))
            with patch.object(recovery,'inventory',return_value={'packages':{'old':'2'},'manual':[]}):
                with self.assertRaisesRegex(RuntimeError,'unavailable'):recovery.undo_packages(p)
    def test_undo_does_not_remove_preexisting_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            (p/'packages-before.json').write_text(json.dumps({'packages':{'original':'1'},'manual':['original']}))
            (p/'packages-after.json').write_text(json.dumps({'packages':{'original':'1','new':'1'},'manual':['original','new']}))
            with patch.object(recovery,'inventory',return_value={'packages':{'original':'1','new':'1'},'manual':[]}),patch.object(system,'command',return_value=(0,'Remv original [1]\nRemv new [1]','')):
                with self.assertRaisesRegex(RuntimeError,'pre-existing'):recovery.undo_packages(p)


class NavigationTests(unittest.TestCase):
    def test_page_down_and_end_select_expected_items_without_commands(self):
        import types
        for keys,expected in [([338,10],'14'),([360,10],'29'),([360,339,10],'15'),([360,262,10],'0')]:
            sequence=iter(keys)
            class Screen:
                def erase(self):pass
                def getmaxyx(self):return (24,100)
                def addnstr(self,*args):pass
                def refresh(self):pass
                def getch(self):return next(sequence)
                def keypad(self,*args):pass
                def bkgd(self,*args):pass
            fake=types.SimpleNamespace(curs_set=lambda x:None,has_colors=lambda:False,A_REVERSE=1,A_BOLD=2,
                KEY_UP=259,KEY_DOWN=258,KEY_NPAGE=338,KEY_PPAGE=339,KEY_HOME=262,KEY_END=360,error=RuntimeError,
                wrapper=lambda fn:fn(Screen()),set_escdelay=lambda ms:None)
            with patch.dict(sys.modules,{'curses':fake}),patch.object(sys.stdin,'isatty',return_value=True),patch.dict(os.environ,{'TERM':'xterm'}),patch.object(system,'command') as command:
                chosen=UI(theme='plain').choose('test',[(str(i),'row '+str(i),'description') for i in range(30)])
                self.assertEqual(chosen,expected);command.assert_not_called()


class InstallerModeTests(unittest.TestCase):
    def payload(self):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as archive:
            for name,value in {'aegis.py':b'print("Portable test")\n','aegis/__init__.py':b'','aegis/system.py':b''}.items():
                member=tarfile.TarInfo(name);member.size=len(value);archive.addfile(member,io.BytesIO(value))
        raw=data.getvalue();return base64.b64encode(raw).decode(),hashlib.sha256(raw).hexdigest()
    def test_install_creates_readable_program_and_launcher_with_undo(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);real_path=Path
            (root/'run/systemd/system').mkdir(parents=True)
            payload,digest=self.payload()
            def mapped(value):
                text=str(value)
                if text.startswith(('/opt/','/usr/local/bin/','/run/systemd/','/var/backups','/var/lib/aegis-linux-hardener')):
                    return real_path(str(root)+text)
                return real_path(value)
            with patch.object(stage,'Path',side_effect=mapped),patch.object(stage,'PAYLOAD',payload),patch.object(stage,'DIGEST',digest), \
                 patch.object(actions,'STATE',root/'state'),patch.object(stage.os,'geteuid',return_value=0), \
                 patch.object(system,'debian_based',return_value=True),patch.object(console,'confirm',return_value=True), \
                 patch.object(sys,'argv',['install_stage.py','--install','--no-launch']):
                stage.main()
            target=root/'opt/aegis-linux-hardener'
            self.assertEqual(target.stat().st_mode & 0o777,0o755)
            self.assertTrue((target/'aegis.py').is_file())
            self.assertEqual((root/'usr/local/bin/aegis').stat().st_mode & 0o777,0o755)
            manifests=list((root/'state/backups').glob('*/manifest.json'))
            self.assertEqual(len(manifests),1)
            self.assertEqual(json.loads(manifests[0].read_text())['operation'],'program-install')
    def test_portable_does_not_create_installed_paths(self):
        payload,digest=self.payload()
        with patch.object(stage,'PAYLOAD',payload),patch.object(stage,'DIGEST',digest), \
             patch.object(sys,'argv',['install_stage.py','--portable']),patch.object(stage.subprocess,'run') as run:
            stage.main()
        run.assert_called_once()
        self.assertNotIn('/opt/aegis-linux-hardener',str(run.call_args))




# Additional transactions are discovered by unittest discovery, not only direct script execution.
class TransactionV02Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.state=patch.object(actions,'STATE',self.root/'state');self.uid=patch.object(actions.os,'geteuid',return_value=0)
        self.state.start();self.uid.start()
    def tearDown(self):self.state.stop();self.uid.stop();self.temp.cleanup()
    def test_metadata_mode_restored_without_copying_directory_contents(self):
        path=self.root/'home';path.mkdir();(path/'data').write_text('not copied');path.chmod(0o755)
        with patch('builtins.input',return_value=''),patch.object(actions,'checked'):
            actions.apply(actions.Plan('metadata',metadata={str(path):0o750}))
        manifest_path=next((actions.STATE/'backups').glob('*/manifest.json'))
        value=json.loads(manifest_path.read_text())
        self.assertEqual(value['files'][0]['kind'],'metadata');self.assertNotIn('copy',value['files'][0])
        actions.restore(manifest_path.parent,value)
        self.assertEqual(path.stat().st_mode & 0o777,0o755);self.assertEqual((path/'data').read_text(),'not copied')
    def test_portable_recovery_runner_survives_source_removal(self):
        source=self.root/'portable';(source/'aegis').mkdir(parents=True)
        entry=source/'aegis.py';entry.write_text('print("recovery")\n');(source/'aegis/__init__.py').write_text('')
        with patch.object(actions,'ENTRY',entry):
            folder,manifest=actions.backup(actions.Plan('portable',critical=True,rollback_commands=[['python',str(entry),'rollback','ID']]),'old-session')
        import shutil
        shutil.rmtree(source)
        self.assertTrue(Path(manifest['runner']).is_file())
        self.assertEqual(manifest['rollback_commands'][0][1],manifest['runner'])
    def test_network_activation_is_detached_from_parent_ssh(self):
        path=self.root/'network.conf';path.write_text('old')
        calls=[]
        with patch('builtins.input',return_value='y'),patch.object(actions,'checked',side_effect=lambda args:calls.append(args)), \
             patch.object(actions.shutil,'which',return_value='/usr/bin/systemd-run'),patch.object(system,'command',return_value=(0,'active','')):
            actions.apply(actions.Plan('network',critical=True,detached=True,writes={str(path):'new'},commands=[['NEVER-RUN-IN-SSH']]),'old-session')
        self.assertFalse(any(args[0]=='NEVER-RUN-IN-SSH' for args in calls))
        self.assertTrue(any('activate' in args for args in calls))
        p=next((actions.STATE/'backups').glob('*/manifest.json'));manifest=json.loads(p.read_text())
        self.assertEqual(manifest['status'],'awaiting-activation')
        with patch.object(actions,'load_manifest',return_value=(p.parent,manifest)),patch.object(actions,'checked') as checked:
            actions.activate(manifest['id'])
        checked.assert_called_once_with(['NEVER-RUN-IN-SSH'])
        self.assertEqual(json.loads(p.read_text())['status'],'awaiting-confirmation')


class IdentityV02Tests(unittest.TestCase):
    def test_ssh_identity_recovered_through_sudo_ancestor(self):
        expected='192.0.2.10 54321 192.0.2.20 22'
        fake=types.SimpleNamespace(read_bytes=lambda:('SSH_CONNECTION='+expected+'\0').encode())
        with patch.dict(os.environ,{'SSH_CONNECTION':''}),patch.object(system.os,'getppid',return_value=42),patch.object(system,'Path',return_value=fake):
            self.assertEqual(system.ssh_connection(),expected)
    def test_irreversible_existing_bpf_lock_is_not_treated_as_reversible(self):
        with patch.object(system,'command',return_value=(0,'1','')):
            with self.assertRaisesRegex(ValueError,'irreversibly'):
                lynis.plan('sysctl-extra',{'keys':['kernel.unprivileged_bpf_disabled']})


if __name__=='__main__':unittest.main(verbosity=2)
