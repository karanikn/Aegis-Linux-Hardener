"""Catalog preferences, custom APT boundaries and local search / Κατάλογος και αναζήτηση."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch,Mock
from aegis import appregistry,catalog,appsearch,launch,uninstall,dependencies

spec=importlib.util.spec_from_file_location('entry_v08',Path(__file__).resolve().parents[1]/'aegis.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)


class Registry(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=Path(self.temp.name)/'catalog.json'
        self.setting=patch.object(appregistry,'PATH',self.path);self.setting.start()
        self.row={'package':'duf','label':'duf','description':'Disk dashboard','category':'Dashboards','command':'duf'}
    def tearDown(self):self.setting.stop();self.temp.cleanup()
    def save(self):self.path.write_text(json.dumps({'schema':1,'hidden':[],'custom':[self.row]}))
    def test_guide_only_entries_are_never_visible(self):
        keys={r[0] for r in catalog.visible_apps()}
        self.assertFalse(keys&{'pnana','psnet','watcher'});self.assertEqual(len(keys),56)
    def test_hiding_builtin_does_not_remove_backend_or_packages(self):
        plan=appregistry.change_plan('remove','htop',catalog.APPS)
        self.assertFalse(plan.commands);self.assertFalse(plan.before);self.path.write_text(plan.writes[str(self.path)])
        self.assertNotIn('htop',{r[0] for r in catalog.visible_apps()});self.assertIn('htop',{r[0] for r in catalog.all_apps()})
        restored=appregistry.change_plan('restore','htop',catalog.APPS)
        self.path.write_text(restored.writes[str(self.path)]);self.assertIn('htop',{r[0] for r in catalog.visible_apps()})
    def test_guide_cannot_be_restored(self):
        with self.assertRaises(ValueError):appregistry.change_plan('restore','pnana',catalog.APPS)
    def test_custom_registration_only_changes_config(self):
        with patch.object(catalog,'package_candidate',return_value='1.0'):
            plan=appregistry.change_plan('add',self.row,catalog.APPS)
        self.assertEqual(set(plan.writes),{str(self.path)});self.assertFalse(plan.commands);self.assertFalse(plan.package_change)
        self.path.write_text(plan.writes[str(self.path)])
        self.assertIn('custom-duf',{r[0] for r in catalog.visible_apps()});self.assertEqual(catalog.category_for('custom-duf'),'Dashboards')
    def test_removing_custom_entry_keeps_package_untouched(self):
        self.save();plan=appregistry.change_plan('remove','custom-duf',catalog.APPS)
        self.assertFalse(plan.commands);self.path.write_text(plan.writes[str(self.path)])
        self.assertIsNone(appregistry.get('custom-duf'))
    def test_stale_config_edit_is_rejected(self):
        plan=appregistry.change_plan('remove','htop',catalog.APPS);self.save()
        with self.assertRaisesRegex(ValueError,'changed'):plan.guard()
    def test_package_and_launcher_injection_are_rejected(self):
        for package in ('-y','duf;id','duf=1.2','/tmp/a.deb','duf curl','$(id)','https://example.invalid/a'):
            with self.assertRaises(ValueError):appregistry.entry({**self.row,'package':package})
        for command in ('/bin/sh','sh -c id','duf;id','$(id)','--help'):
            with self.assertRaises(ValueError):appregistry.entry({**self.row,'command':command})
    def test_invalid_category_controls_and_duplicate_package_rejected(self):
        for changes in ({'label':'bad\x1b[2J'},{'description':'two\nlines'},{'category':'injected'}):
            with self.assertRaises(ValueError):appregistry.entry({**self.row,**changes})
        with self.assertRaises(ValueError):appregistry.validate({'schema':1,'custom':[self.row,self.row]})
    def test_symlink_config_rejected(self):
        self.path.symlink_to(Path(self.temp.name)/'other')
        with self.assertRaises(ValueError):appregistry.load()
    def test_unavailable_package_cannot_be_added(self):
        with patch.object(catalog,'package_candidate',return_value=None),patch.object(catalog.system,'installed',return_value=None):
            with self.assertRaises(ValueError):appregistry.change_plan('add',self.row,catalog.APPS)
    def test_builtin_package_and_docker_alias_not_duplicated(self):
        for package in ('htop','network-manager','docker.io'):
            with self.assertRaises(ValueError):appregistry.change_plan('add',{**self.row,'package':package},catalog.APPS)
    def test_custom_install_uses_mapped_apt_package_and_service_guard(self):
        self.save()
        with patch.object(catalog,'app_version',return_value=None),patch.object(catalog,'package_candidate',return_value='1.0'),patch.object(catalog.system,'debian_based',return_value=True):
            plan=catalog.app_plan('custom-duf','demo')
        self.assertIn(['apt-get','install','duf'],plan.before);self.assertTrue(plan.suppress_services)
    def test_custom_installed_status_uses_package_not_random_executable(self):
        self.save()
        with patch.object(catalog.system,'installed',return_value='1.0') as installed:
            self.assertEqual(catalog.app_version('custom-duf'),'1.0');installed.assert_called_once_with('duf')
        with patch.object(catalog,'package_versions',return_value={'duf':'2.0'}):self.assertEqual(catalog.catalog_versions()['custom-duf'],'2.0')
    def test_custom_capability_tracks_apt_candidate(self):
        self.save();self.assertEqual(catalog.capability('custom-duf',{'duf':'1'})[0],'apt');self.assertEqual(catalog.capability('custom-duf',{})[0],'unavailable')
    def test_custom_open_requires_package_owned_executable(self):
        self.save()
        with patch.object(launch.system,'command',return_value=(0,'/usr/bin/other','')):
            with self.assertRaises(ValueError):launch.launch_args('custom-duf')
        with patch.object(launch.system,'command',return_value=(0,'/usr/bin/duf','')),patch.object(Path,'is_file',return_value=True),patch.object(launch.os,'access',return_value=True):
            self.assertEqual(launch.launch_args('custom-duf'),['/usr/bin/duf'])
    def test_custom_blank_launcher_is_package_details(self):
        self.row['command']='';self.save();self.assertIsNone(launch.launch_args('custom-duf'))
    def test_custom_launch_drops_root_and_has_no_injected_arguments(self):
        self.save();account=Mock(pw_uid=1000,pw_dir='/home/demo')
        with patch.object(catalog,'app_version',return_value='1'),patch.object(launch,'launch_args',return_value=['/usr/bin/duf']),patch.object(launch.pwd,'getpwnam',return_value=account),patch.object(launch.os,'geteuid',return_value=0),patch.object(launch.subprocess,'run') as run:
            launch.open_app('custom-duf','demo')
        self.assertEqual(run.call_args.args[0],['runuser','-u','demo','--','env','HOME=/home/demo','/usr/bin/duf'])
    def test_custom_uninstall_maps_package_and_protects_essential(self):
        self.save()
        with patch.object(uninstall.system,'command',return_value=(0,'yes no','')):
            with self.assertRaisesRegex(ValueError,'protected'):uninstall.plan('custom-duf')
        def command(args,**kwargs):return (0,'no no','') if args[0]=='dpkg-query' else (0,'Remv duf [1.0]','')
        with patch.object(uninstall.system,'command',side_effect=command),patch.object(uninstall.system,'installed',return_value='1.0'):
            plan=uninstall.plan('custom-duf')
        self.assertEqual(plan.commands,[['apt-get','remove','--no-auto-remove','--','duf']])
    def test_dependencies_recognize_custom_app(self):
        self.save();self.assertEqual(dependencies.requirements({'kind':'open-app','app':'custom-duf'})[0]['app'],'custom-duf')
    def test_settings_offers_catalog_manager(self):
        ui=Mock();ui.choose.return_value=None;app.settings_menu(ui)
        self.assertIn('catalog',{r[0] for r in ui.choose.call_args.args[1]})


class Search(unittest.TestCase):
    rows=[('duf','duf [Installed]','Category: Dashboards\nAPT package: duf\nDisk usage'),('network','Link Tool','Category: Networking\nPacket inspection'),('greek','Δίσκος','Αποθήκευση')]
    def test_empty_search_keeps_order_and_installed_badge(self):self.assertEqual(appsearch.matches(self.rows,''),self.rows)
    def test_case_insensitive_multiple_terms_match_description(self):self.assertEqual(appsearch.matches(self.rows,'NETWORK packet'),[self.rows[1]])
    def test_package_name_and_unicode_match(self):
        self.assertEqual(appsearch.matches(self.rows,'package: duf'),[self.rows[0]]);self.assertEqual(appsearch.matches(self.rows,'ΔΊΣΚΟΣ'),[self.rows[2]])
    def test_no_match_is_empty(self):self.assertEqual(appsearch.matches(self.rows,'no-such-tool'),[])


if __name__=='__main__':unittest.main()
