"""Management safety fixtures. Never modifies host accounts/network/shares/packages."""
import configparser
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock,patch
from aegis import actions,catalog,management,nameconfig,networking,shares,system,uninstall,users

spec=importlib.util.spec_from_file_location('entry_v05',Path(__file__).resolve().parents[1]/'aegis.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)

class NameConfigV05(unittest.TestCase):
    def test_hosts_add_preserves_comments_and_core_lines(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(nameconfig,'ETC',Path(folder)):
            p=Path(folder)/'hosts';p.write_text('127.0.0.1 localhost\n# comment\n')
            plan=nameconfig.hosts_plan('add','192.0.2.10','files files.example')
            text=plan.writes[str(p)]
            self.assertIn('127.0.0.1 localhost',text);self.assertIn('# comment',text);self.assertIn('192.0.2.10\tfiles files.example',text)
    def test_hosts_core_identity_deletion_refused(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(nameconfig,'ETC',Path(folder)):
            (Path(folder)/'hosts').write_text('::1 localhost\n')
            with self.assertRaisesRegex(ValueError,'protected'):nameconfig.hosts_plan('delete',index=0,expected='::1 localhost')
    def test_hosts_stale_selection_refused(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(nameconfig,'ETC',Path(folder)):
            (Path(folder)/'hosts').write_text('192.0.2.1 newer\n')
            with self.assertRaisesRegex(ValueError,'changed'):nameconfig.hosts_plan('delete',index=0,expected='192.0.2.1 old')
    def test_hosts_injection_rejected(self):
        with self.assertRaises(ValueError):nameconfig.hostnames('valid\n[global]')
    def test_nm_dns_only_preserves_address_gateway_and_secrets(self):
        cfg=configparser.ConfigParser(interpolation=None)
        cfg.read_string('[connection]\nuuid=11111111-1111-1111-1111-111111111111\n[ipv4]\nmethod=manual\naddress1=192.0.2.10/24,192.0.2.1\n[ipv6]\nmethod=auto\n[wifi-security]\npsk=PRIVATE\n')
        with patch.object(networking,'detect_backend',return_value=('networkmanager',(Path('/etc/NetworkManager/system-connections/test'),'11111111-1111-1111-1111-111111111111',cfg))):
            plan=nameconfig.dns_plan('ens192','1.1.1.1 2001:db8::53','example.org')
        text=next(iter(plan.writes.values()))
        self.assertIn('address1=192.0.2.10/24,192.0.2.1',text);self.assertIn('method=manual',text);self.assertIn('psk=PRIVATE',text)
        self.assertTrue(plan.critical and plan.detached);self.assertNotIn('PRIVATE',plan.preview())
    def test_ambiguous_manager_never_falls_back_to_resolver_file(self):
        with patch.object(networking,'detect_backend',side_effect=ValueError('Ambiguous Netplan match')):
            with self.assertRaisesRegex(ValueError,'Ambiguous'):nameconfig.dns_plan('ens192','1.1.1.1')
    def test_networkd_dns_keeps_addresses_and_routes(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'eth.network';path.write_text('[Match]\nName=ens192\n[Network]\nAddress=192.0.2.10/24\nGateway=192.0.2.1\n[Route]\nDestination=198.51.100.0/24\nGateway=192.0.2.2\n')
            with patch.object(networking,'detect_backend',return_value=('networkd',path)),patch.object(system,'service',return_value='active'):
                plan=nameconfig.dns_plan('ens192','1.1.1.1')
            self.assertIn('[Route]\nDestination=198.51.100.0/24',plan.writes[str(path)])
            self.assertIn('Address=192.0.2.10/24',plan.writes[str(path)])
    def test_dns_reapply_never_activates_a_different_nm_profile(self):
        with patch.object(system,'command',return_value=(0,'different','')):
            with self.assertRaisesRegex(ValueError,'profile changed'):nameconfig.reload_dns({'backend':'networkmanager','iface':'ens192','uuid':'11111111-1111-1111-1111-111111111111'})

class AccountsV05(unittest.TestCase):
    def account(self):return types.SimpleNamespace(pw_name='demo',pw_uid=1000,pw_gid=1000,pw_dir='/home/demo',pw_shell='/bin/bash')
    def test_current_operator_cannot_be_disabled(self):
        with patch.object(users,'local_user',return_value=self.account()):
            for op in ('delete','lock','disable','shell'):
                with self.assertRaisesRegex(ValueError,'management account'):users.plan(op,{'user':'demo'},'demo')
    def test_delete_keeps_home_and_requires_no_processes(self):
        with patch.object(users,'local_user',return_value=self.account()),patch.object(users.grp,'getgrall',return_value=[]),patch.object(system,'command',return_value=(1,'','')):
            plan=users.plan('delete',{'user':'demo'},'admin')
        self.assertEqual(plan.commands,[['userdel','demo']]);self.assertFalse(plan.backup_paths)
    def test_active_user_cannot_be_deleted(self):
        with patch.object(users,'local_user',return_value=self.account()),patch.object(users.grp,'getgrall',return_value=[]),patch.object(system,'command',return_value=(0,'100','')):
            with self.assertRaisesRegex(ValueError,'active processes'):users.plan('delete',{'user':'demo'},'admin')
    def test_add_group_uses_append_not_replace(self):
        with patch.object(users,'local_user',return_value=self.account()),patch.object(users,'local_group',return_value=types.SimpleNamespace(gr_gid=1001)),patch.object(users.grp,'getgrall',return_value=[]):
            plan=users.plan('group-add',{'user':'demo','group':'team'},'admin')
        self.assertEqual(plan.commands,[['gpasswd','-a','demo','team']])
    def test_permission_plan_is_nonrecursive_and_snapshots_acl(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'data';path.mkdir()
            with patch.object(users,'permission_path',return_value=path):plan=users.permissions('mode',{'path':str(path),'mode':'2770'})
            self.assertEqual(plan.metadata,{str(path):0o2770});self.assertEqual(plan.acl_paths,[str(path)]);self.assertFalse(plan.commands)
    def test_suid_mode_rejected(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(users,'permission_path',return_value=Path(folder)):
            with self.assertRaises(ValueError):users.permissions('mode',{'path':folder,'mode':'4755'})
    def test_public_key_rejects_private_or_multiline_text(self):
        with patch.object(users,'local_user',return_value=self.account()):
            with self.assertRaises(ValueError):users.ssh_key_plan('demo','-----BEGIN PRIVATE KEY-----')
    def fixture(self,path):
        values={'passwd':'demo:x:1000:1000::/home/demo:/bin/bash\nother:x:1001:1001::/home/other:/bin/bash\n',
                'shadow':'demo:OLDHASH:1:0:99999:7:::\nother:OTHERHASH:1:0:99999:7:::\n',
                'group':'demo:x:1000:\nother:x:1001:\n','gshadow':'demo:!::\nother:!::\n',
                'subuid':'demo:100000:65536\ndemo:300000:65536\n','subgid':'demo:100000:65536\n'}
        for name,text in values.items():(path/name).write_text(text)
    def test_scoped_account_restore_preserves_other_users_and_subuid_ranges(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(users,'ETC',Path(folder)),patch.object(users,'lock_accounts',return_value=Mock()),patch.object(users.os,'chown'):
            path=Path(folder);self.fixture(path);old=users.capture(['demo'],['demo'])
            self.assertEqual(len(old['data']['subuid']['demo']),2)
            (path/'shadow').write_text((path/'shadow').read_text().replace('OLDHASH','NEWHASH'))
            expected=users.capture(['demo'],['demo'])
            with (path/'passwd').open('a') as f:f.write('later:x:1002:1002::/home/later:/bin/bash\n')
            users.restore_accounts({'old':old,'expected':expected})
            self.assertIn('later:x:1002',(path/'passwd').read_text());self.assertIn('OLDHASH',(path/'shadow').read_text())
            self.assertEqual((path/'subuid').read_text().count('demo:'),2)
    def test_newer_target_password_change_blocks_undo(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(users,'ETC',Path(folder)):
            path=Path(folder);self.fixture(path);old=users.capture(['demo'],[])
            (path/'shadow').write_text((path/'shadow').read_text().replace('OLDHASH','LATERHASH'))
            with self.assertRaisesRegex(RuntimeError,'changed after'):users.restore_accounts({'old':old,'expected':old})
    def test_database_locks_are_released(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(users,'ETC',Path(folder)),patch.object(users.ctypes,'CDLL') as cdll:
            cdll.return_value.lckpwdf.return_value=0
            lock=users.lock_accounts();self.assertTrue((Path(folder)/'passwd.lock').exists());lock.ulckpwdf()
            self.assertFalse(list(Path(folder).glob('*.lock')))

class SharesV05(unittest.TestCase):
    def test_samba_install_inactive_no_firewall(self):
        with patch.object(system,'installed',return_value=None),patch.object(system,'service',return_value='inactive'),patch.object(system,'debian_based',return_value=True):plan=shares.install_plan()
        self.assertTrue(plan.suppress_services);self.assertNotIn('ufw',str(plan.commands));self.assertFalse(plan.writes)
    def test_share_create_authenticated_subnet_scoped_data_not_modified(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'samba').mkdir();(root/'samba/smb.conf').write_text('[global]\nworkgroup = WORKGROUP\n[old]\npath=/srv/old\n')
            with patch.object(shares,'ETC',root),patch.object(shares,'standalone'),patch.object(shares,'inventory',return_value=[('old','/srv/old','yes','no','')]),patch.object(users,'permission_path',return_value=Path('/srv/team')),patch.object(Path,'is_dir',return_value=True),patch.object(users,'local_group'),patch.object(system,'service',return_value='inactive'):
                plan=shares.share_plan('create',{'name':'team','path':'/srv/team','valid_users':'@team','allow_networks':'192.0.2.0/24','readonly':False})
            text=plan.writes[str(root/'samba/aegis-shares.conf')]
            self.assertIn('guest ok = no',text);self.assertIn('hosts allow = 192.0.2.0/24',text);self.assertIn('[old]',plan.writes[str(root/'samba/smb.conf')])
            self.assertFalse(plan.commands);self.assertNotIn('/srv/team',plan.backup_paths)
    def test_external_share_edit_refused(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(shares,'ETC',Path(folder)),patch.object(shares,'standalone'),patch.object(shares,'inventory',return_value=[]):
            (Path(folder)/'samba').mkdir();(Path(folder)/'samba/smb.conf').write_text('[global]\n')
            with self.assertRaisesRegex(ValueError,'limited'):shares.share_plan('remove',{'name':'external'})
    def test_credentials_snapshot_failure_is_not_treated_as_missing_user(self):
        with patch.object(system,'command',return_value=(1,'','error')):
            with self.assertRaisesRegex(RuntimeError,'Cannot snapshot'):shares.credential_rows(['demo'])
    def test_credential_snapshot_contains_only_requested_user(self):
        with patch.object(system,'command',return_value=(0,'demo:1000:A:B:[U]:LCT-1:\nother:1001:C:D:[U]:LCT-2:\n','')):
            rows=shares.credential_rows(['demo'])
        self.assertEqual(list(rows),['demo']);self.assertNotIn('other',str(rows))
    def test_inherited_readonly_and_guest_are_reported(self):
        text='[global]\nread only = no\nguest ok = yes\n[team]\npath = /srv/team\n'
        with patch.object(system,'command',return_value=(0,text,'')):rows=shares.inventory()
        self.assertEqual(rows[0][2:4],('no','yes'))

class UninstallV05(unittest.TestCase):
    def test_apt_remove_is_not_purge_or_autoremove(self):
        with patch.object(system,'installed',return_value='1'),patch.object(system,'command',return_value=(0,'Remv htop [1]\n','')):
            plan=uninstall.plan('htop')
        self.assertTrue(plan.package_change);self.assertEqual(plan.commands,[['apt-get','remove','--no-auto-remove','--','htop']])
    def test_collateral_package_removal_refused(self):
        with patch.object(system,'installed',return_value='1'),patch.object(system,'command',return_value=(0,'Remv htop [1]\nRemv otherapp [2]\n','')):
            with self.assertRaisesRegex(ValueError,'other packages'):uninstall.plan('htop')
    def test_active_networkmanager_removal_refused(self):
        with patch.object(system,'service',return_value='active'):
            with self.assertRaisesRegex(ValueError,'NetworkManager is active'):uninstall.plan('nmtui')
    def test_running_docker_workloads_block_uninstall(self):
        with patch.object(system,'command',return_value=(0,'container123','')):
            with self.assertRaisesRegex(ValueError,'Running containers'):uninstall.plan('docker')
    def test_monitor_catalog_contains_all_relevant_tools(self):
        self.assertTrue({'htop','glances','iotop','iftop','dtop','lazydocker','tcpdump','termshark'}<=app.MONITOR_APPS)
    def test_new_menu_hierarchy(self):
        ui=Mock();ui.t.side_effect=lambda a,b:a;ui.choose.return_value=None
        app.menu(ui);keys=[r[0] for r in ui.choose.call_args.args[1]]
        self.assertIn('users',keys);self.assertIn('shares',keys);self.assertEqual(keys[-1],'help')

class RecoveryV05(unittest.TestCase):
    def test_acl_backup_and_restore_use_exact_private_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);target=root/'data';target.mkdir();(target/'keep').write_text('content');target.chmod(0o750)
            acl='# file: '+str(target)+'\n# owner: 0\n# group: 0\nuser::rwx\ngroup::r-x\nother::---\n'
            state=root/'state'
            with patch.object(actions,'STATE',state),patch.object(system,'command',return_value=(0,acl,'')):
                backup,manifest=actions.backup(actions.Plan('acl',metadata={str(target):0o700},acl_paths=[str(target)]),'')
                target.chmod(0o700)
                with patch.object(actions.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as run:
                    actions.restore(backup,manifest)
                self.assertEqual(run.call_args.args[0],['setfacl','--restore=-'])
                self.assertEqual(run.call_args.kwargs['input'],acl+'\n')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o750);self.assertEqual((target/'keep').read_text(),'content')
    def test_scoped_account_expected_state_is_saved_after_apply(self):
        old={'users':['demo'],'groups':[],'data':{'passwd':{'demo':None}}};after={'users':['demo'],'groups':[],'data':{'passwd':{'demo':'demo:x:1000:1000::/home/demo:/bin/bash'}}}
        with tempfile.TemporaryDirectory() as folder,patch.object(actions.os,'geteuid',return_value=0),patch.object(actions,'STATE',Path(folder)/'state'),patch.object(actions.console,'confirm',return_value=True),patch.object(users,'capture',side_effect=[old,after]),contextlib.redirect_stdout(io.StringIO()):
            ident=actions.apply(actions.Plan('Create demo',account_users=['demo']))
            manifest=json.loads((Path(folder)/'state/backups'/ident/'manifest.json').read_text())
            self.assertEqual(manifest['files'][0]['expected'],after)
            self.assertEqual(stat.S_IMODE((Path(folder)/'state/backups'/ident/'manifest.json').stat().st_mode),0o600)
    def test_metadata_restore_refuses_replaced_object(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(actions,'STATE',Path(folder)/'state'):
            path=Path(folder)/'data';path.mkdir()
            backup,manifest=actions.backup(actions.Plan('mode',metadata={str(path):0o700}),'')
            moved=path.with_name('old');path.rename(moved);path.mkdir();path.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError,'replaced'):actions.restore(backup,manifest)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o755)

if __name__=='__main__':unittest.main()
