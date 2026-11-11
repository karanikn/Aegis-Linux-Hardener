"""Themes, cancelled workflows, hostname, categories and source-build guards."""
import configparser
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest.mock import Mock,patch
from aegis import actions,catalog,categories,console,nameconfig,sourcebuild,themes
from aegis.ui import UI

spec=importlib.util.spec_from_file_location('entry_v06',Path(__file__).resolve().parents[1]/'aegis.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)

class PromptsV06(unittest.TestCase):
    def test_ctrl_c_becomes_navigation_cancel(self):
        with patch('builtins.input',side_effect=KeyboardInterrupt),patch.object(console.sys.stdin,'isatty',return_value=False),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(console.Cancelled):console.ask('IPv4','192.0.2.10/24')
    def test_typed_back_cancels_free_text(self):
        with patch('builtins.input',return_value='/back'),patch.object(console.sys.stdin,'isatty',return_value=False),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(console.Cancelled):console.ask('Address')
    def test_cancelled_wizard_reenters_same_parent(self):
        calls=[]
        @console.cancellable_menu
        def menu():
            calls.append('parent')
            if len(calls)==1:raise console.Cancelled()
            return 'returned'
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(menu(),'returned')
        self.assertEqual(len(calls),2)
    def test_known_options_passed_to_arrow_editor(self):
        ui=UI('en','nord')
        with patch.object(console,'ask',return_value='udp') as ask:
            self.assertEqual(ui.prompt('Protocol tcp/udp','Πρωτόκολλο','tcp'),'udp')
        self.assertEqual(ask.call_args.kwargs['choices'],['tcp','udp'])
    def test_default_retained_for_noninteractive_input(self):
        with patch('builtins.input',return_value=''),patch.object(console.sys.stdin,'isatty',return_value=False),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(console.ask('Theme','slate',choices=list(themes.PALETTES)),'slate')
    def test_installed_marker_after_name(self):self.assertEqual(app.installed_label('iftop','1.0'),'iftop [Installed]')
    def test_theme_palettes_have_status_and_selection_colors(self):
        self.assertEqual(len(themes.PALETTES),10)
        values=set()
        for theme in themes.PALETTES:
            if theme=='plain':continue
            ui=UI(theme=theme);curses=Mock();curses.has_colors.return_value=True;curses.COLORS=256;curses.color_pair.side_effect=lambda i:i
            ui.palette(curses,Mock())
            pairs={call.args[0]:call.args[1:] for call in curses.init_pair.call_args_list}
            self.assertEqual(pairs[8][0],themes.PALETTES[theme][5]);values.add(pairs[8][0])
            self.assertEqual(pairs[9][1],themes.PALETTES[theme][3])
        self.assertGreater(len(values),5)

class HostnameV06(unittest.TestCase):
    def test_hostname_change_preserves_loopback_and_unrelated_aliases(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(nameconfig,'ETC',Path(folder)),patch('shutil.which',return_value='/usr/bin/hostnamectl'),patch.object(nameconfig.system.socket,'gethostname',return_value='old'):
            (Path(folder)/'hostname').write_text('old\n');(Path(folder)/'hosts').write_text('127.0.0.1 localhost\n127.0.1.1 old old.example.org keep-alias # local\n::1 localhost ip6-localhost\n')
            plan=nameconfig.hostname_plan('new.example.org')
            text=plan.writes[str(Path(folder)/'hosts')]
            self.assertIn('127.0.0.1 localhost',text);self.assertIn('::1 localhost ip6-localhost',text);self.assertIn('new.example.org new keep-alias',text)
            self.assertNotIn('old.example.org',text)
            self.assertIn('--hostname-runtime',plan.rollback_commands[0]);self.assertEqual(plan.rollback_commands[0][-1],'old')
    def test_invalid_hostnames_never_build_commands(self):
        for value in ('Bad_Name','-node','node-','node;id','x'*65,'a..b'):
            with self.assertRaises(ValueError):nameconfig.hostname_plan(value)
    def test_hosts_update_can_be_declined(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(nameconfig,'ETC',Path(folder)),patch('shutil.which',return_value='hostnamectl'),patch.object(nameconfig.system.socket,'gethostname',return_value='old'):
            plan=nameconfig.hostname_plan('new',False)
        self.assertEqual(len(plan.writes),1)

class CatalogV06(unittest.TestCase):
    def test_every_entry_has_exactly_one_category(self):
        for key,*_ in catalog.APPS:
            hits=[group for group,keys in categories.GROUPS if key in keys]
            self.assertEqual(len(hits),1,key)
    def test_netscanner_source_route_and_pnana_guidance(self):
        self.assertEqual(catalog.capability('netscanner',{})[0],'source')
        self.assertEqual(catalog.capability('pnana',{})[0],'guide')
        self.assertEqual(catalog.capability('psnet',{})[0],'guide')
        self.assertEqual(catalog.capability('hddtemp',{})[0],'unavailable')
    def test_netscanner_missing_apt_uses_known_source_recipe(self):
        with patch.object(catalog,'app_version',return_value=None),patch.object(catalog,'package_candidate',return_value=None),patch.object(sourcebuild,'source_plan',return_value=actions.Plan('source')) as source:
            self.assertEqual(catalog.app_plan('netscanner','demo').title,'source')
        source.assert_called_once_with('demo')
    def test_unavailable_entry_does_not_offer_failed_install_button(self):
        ui=Mock();ui.choose.return_value=None
        with patch.object(catalog,'app_version',return_value=None),patch.object(catalog,'package_candidates',return_value={}):app.app_actions(ui,'pnana')
        ids=[row[0] for row in ui.choose.call_args.args[1]]
        self.assertNotIn('install',ids);self.assertIn('details',ids)
    def test_all_apps_remains_available_beside_categories(self):
        ui=Mock();ui.choose.return_value=None
        app.apps_menu(ui);entries=ui.choose.call_args.args[1]
        self.assertEqual(entries[0][0],'all');self.assertTrue(any(row[0]=='Docker/LXC/K8s' for row in entries))

class BuildV06(unittest.TestCase):
    def archive(self,entries):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as tar:
            for name,content,kind in entries:
                item=tarfile.TarInfo(name);item.size=len(content)
                if kind:item.type=kind;item.linkname='/etc/shadow';tar.addfile(item)
                else:tar.addfile(item,io.BytesIO(content))
        return data.getvalue()
    def test_source_checksum_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError,'mismatch'):sourcebuild.verified_source('0.6.43','0'*64,b'changed')
    def test_source_links_rejected(self):
        data=self.archive([('netscanner-0.6.43/link',b'',tarfile.SYMTYPE)])
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError,'links'):sourcebuild.extract_source(data,'0.6.43',folder)
    def test_source_path_escape_rejected(self):
        data=self.archive([('netscanner-0.6.43/../../escape',b'x',None)])
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError,'Unsafe'):sourcebuild.extract_source(data,'0.6.43',folder)
    def test_source_requires_lockfile(self):
        data=self.archive([('netscanner-0.6.43/Cargo.toml',b'x',None)])
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError,'lockfile'):sourcebuild.extract_source(data,'0.6.43',folder)
    def test_valid_source_extracts_only_regular_files(self):
        data=self.archive([('netscanner-0.6.43/Cargo.lock',b'lock',None)])
        with tempfile.TemporaryDirectory() as folder:
            root=sourcebuild.extract_source(data,'0.6.43',folder)
            self.assertEqual((root/'Cargo.lock').read_text(),'lock')
    def test_compilation_as_root_uses_regular_user(self):
        account=types.SimpleNamespace(pw_name='demo',pw_uid=1000)
        process=Mock();process.wait.return_value=0
        with tempfile.TemporaryDirectory() as folder,patch.object(sourcebuild.os,'geteuid',return_value=0),patch.object(sourcebuild.subprocess,'Popen',return_value=process) as launch:
            sourcebuild.run_user(['/tmp/cargo','install'],account,{'CARGO_HOME':'/tmp/cargo-home'},Path(folder))
        self.assertEqual(launch.call_args.args[0][:4],['runuser','-u','demo','--']);self.assertTrue(launch.call_args.kwargs['start_new_session'])

if __name__=='__main__':unittest.main()
