"""v0.3 sidebar, package identity and verified-release safety checks."""
import hashlib
import io
import json
import struct
import tarfile
import unittest
from unittest.mock import patch
from aegis import catalog,panels,toolinstall,defense,system


def elf(arch='amd64'):
    data=bytearray(64);data[:6]=b'\x7fELF\x02\x01';data[18:20]=struct.pack('<H',62 if arch=='amd64' else 183)
    return bytes(data)


def archive(name,data=b'test',kind=None):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
        item=tarfile.TarInfo(name);item.size=len(data)
        if kind:item.type=kind;item.linkname='/etc/shadow';tar.addfile(item)
        else:tar.addfile(item,io.BytesIO(data))
    return buffer.getvalue()


class CatalogV03(unittest.TestCase):
    def test_requested_entries_and_order(self):
        requested='htop mc aria2 iftop curl rcconf unrar-free lm-sensors hddtemp tcpdump iotop iptraf nmon collectl nload nethogs bmon tcptrack vnstat netdiag logwatch watcher incron ncdu pydf rtop tmux tmate ngrok nmtui chkservice apachetop bandwhich glances netscanner nmap hwinfo-tui psnet dtop docker-dash dockmate lazydocker microneo fresh lazyide pnana rovr lf termshark'.split()
        keys=[r[0] for r in catalog.APPS]
        self.assertEqual(len(keys),len(set(keys)))
        self.assertTrue(set(requested)<=set(keys))
        self.assertEqual(keys[0],'ucaresystem-core')
        self.assertEqual(keys[1:],sorted(keys[1:],key=str.casefold))
    def test_explicit_aliases(self):
        self.assertEqual(catalog.DISTRO_SPECS['iptraf'][2],'iptraf-ng')
        self.assertEqual(catalog.DISTRO_SPECS['nmtui'][2],'network-manager')
    def test_all_apps_have_meaningful_information(self):
        for key,*_ in catalog.APPS:
            text=catalog.app_information(key)
            self.assertIn('What it does',text);self.assertIn('Official source',text)
    def test_bulk_inventory_not_query_per_application(self):
        with patch.object(system,'command',return_value=(0,'htop\tinstalled\t3.2\n','')) as call,patch('shutil.which',return_value=None):
            versions=catalog.catalog_versions()
        self.assertEqual(versions['htop'],'3.2');self.assertEqual(call.call_count,1)
    def test_ambiguous_or_windows_app_never_installs_wrong_package(self):
        with patch.object(catalog,'app_version',return_value=None),patch.object(catalog,'package_plan') as install:
            for key in ('watcher','psnet'):
                with self.assertRaises(ValueError):catalog.app_plan(key,'tester')
            install.assert_not_called()
    def test_missing_hddtemp_does_not_add_old_repository(self):
        with patch.object(catalog,'app_version',return_value=None),patch.object(catalog,'package_candidate',return_value=None):
            with self.assertRaisesRegex(ValueError,'No APT candidate'):catalog.app_plan('hddtemp','tester')
    def test_nmtui_new_install_no_daemon_start(self):
        with patch.object(catalog,'app_version',return_value=None),patch.object(catalog,'package_candidate',return_value='1'),patch.object(system,'debian_based',return_value=True):
            plan=catalog.app_plan('nmtui','tester')
        self.assertTrue(plan.suppress_services)
        self.assertIn('disable',plan.commands[0]);self.assertNotIn('start',str(plan.commands))
    def test_source_only_tools_are_explicit(self):
        with patch.object(catalog,'app_version',return_value=None),patch.object(catalog,'package_candidate',return_value=None):
            for key in ('pnana',):
                with self.assertRaisesRegex(ValueError,'No APT candidate or verified prebuilt'):catalog.app_plan(key,'tester')


class ArtifactsV03(unittest.TestCase):
    def test_path_escape_rejected(self):
        with self.assertRaisesRegex(ValueError,'Unsafe archive'):toolinstall.archive_binary(archive('../dtop'), 'dtop')
    def test_symlink_not_installed_as_executable(self):
        with self.assertRaisesRegex(ValueError,'regular file'):toolinstall.archive_binary(archive('dtop',kind=tarfile.SYMTYPE),'dtop')
    def test_matching_executable_only(self):
        self.assertEqual(toolinstall.archive_binary(archive('folder/dtop',elf()),'dtop'),elf())
    def test_architecture_checked(self):
        toolinstall.validate_elf(elf(),'amd64')
        with self.assertRaises(ValueError):toolinstall.validate_elf(elf(),'arm64')
        with self.assertRaises(ValueError):toolinstall.validate_elf(b'#!/bin/sh\n','amd64')
    def test_patterns_never_pick_windows_or_wrong_arch(self):
        import re
        self.assertTrue(re.fullmatch(toolinstall.asset_pattern('dtop','amd64'),'dtop-x86_64-unknown-linux-gnu.tar.gz'))
        self.assertFalse(re.fullmatch(toolinstall.asset_pattern('dtop','amd64'),'dtop-aarch64-unknown-linux-gnu.tar.gz'))
    def test_checksum_mismatch_fails(self):
        with self.assertRaisesRegex(ValueError,'mismatch'):
            toolinstall.verify_checksum({}, {'digest':'sha256:'+'0'*64}, b'x','a/b',None)
    def test_manifest_checksum_name_matching(self):
        data=b'test';digest=hashlib.sha256(data).hexdigest()
        release={'assets':[{'name':'checksums.txt','browser_download_url':'https://github.com/a/b/releases/download/v1/checksums.txt'}]}
        found,_=toolinstall.verify_checksum(release,{'name':'tool.tar.gz'},data,'a/b',lambda *a:(digest+'  tool.tar.gz\n').encode())
        self.assertEqual(found,digest)
    def test_python_requirements_not_system_python_replacement(self):
        self.assertFalse(toolinstall.python_compatible('<3.15,>=3.13',(3,11,0)))
        self.assertTrue(toolinstall.python_compatible('<3.15,>=3.13',(3,13,2)))
        self.assertTrue(toolinstall.python_compatible('>=3.10',(3,10,0)))


class DefenseV03(unittest.TestCase):
    def test_defense_install_stays_inactive_with_backup(self):
        state={'unit':'portsentry.service','active':False,'enabled':False}
        with patch.object(system,'installed',return_value=None),patch.object(system,'service',return_value='inactive'),patch.object(system,'service_state',return_value=state),patch.object(system,'debian_based',return_value=True),patch.object(defense,'package_candidate',return_value='1'):
            for key in defense.TOOLS:
                plan=defense.install_plan(key)
                self.assertTrue(plan.suppress_services);self.assertTrue(plan.backup_paths)
                self.assertEqual(plan.commands[0][1],'disable')
                self.assertFalse(plan.writes)
    def test_existing_active_external_defense_not_modified(self):
        with patch.object(system,'installed',return_value=None),patch.object(system,'service',return_value='active'):
            with self.assertRaisesRegex(ValueError,'active external'):defense.install_plan('portsentry')


class PanelsV03(unittest.TestCase):
    def test_meter_clamps_and_has_severity(self):
        text,role=panels.meter('RAM',500)
        self.assertIn('100.0%',text);self.assertEqual(role,'danger')
        self.assertEqual(panels.meter('CPU',20)[1],'good')
    def test_dashboard_formatting_never_executes_commands(self):
        s={'hostname':'test','os':'Debian','kernel':'6','architecture':'amd64','cpu':'Demo CPU','cpu_threads':2,'cpu_pct':30,'load':[0,0,0],
           'memory':{'used_pct':40,'total_gib':4,'swap_pct':0,'swap_gib':2},'uptime_hours':2,'virtualization':'vmware','desktop_detected':False,
           'addresses':'lo UNKNOWN 127.0.0.1/8\nens192 UP 192.0.2.10/24','default_route':'default via 192.0.2.1',
           'dns':'nameserver 192.0.2.1','filesystems':[{'path':'/','used_pct':50,'inode_pct':2,'gib':40},{'path':'/run/credentials/x','used_pct':0,'inode_pct':0,'gib':0}],
           'ssh':'active','fail2ban':'inactive','apparmor':'active','alerts':'active','firewall':'inactive','reboot_required':False,'timestamp':'demo'}
        with patch.object(system,'command') as command:
            rows=panels.dashboard_rows(s,70)
            command.assert_not_called()
        text='\n'.join(x[0] for x in rows)
        self.assertIn('192.0.2.10',text);self.assertIn('runtime mounts omitted',text)
        self.assertNotIn('/run/credentials/x',text);self.assertIn('SECURITY',text)

if __name__=='__main__':unittest.main()
