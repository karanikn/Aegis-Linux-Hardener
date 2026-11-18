"""Persistent GeoIP actions and scheduled publication / Μόνιμη πολιτική και timer."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from aegis import geoip,geoip_engine as g,actions,panels
from aegis.geodata import COUNTRIES


def policy(enabled=True):
    return {**geoip.defaults(),'enabled':enabled,'update_schedule':'daily'}


def cache(prefix='8.8.8.0/24'):
    return {'schema':1,'source':'rir','updated':'2026-11-18','sources':[],'warnings':[],
            'countries':{code:{'4':[prefix] if code=='GR' else [],'6':[]} for code in COUNTRIES}}


class Updates(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name)
        self.patches=[patch.object(g,key,value) for key,value in {'ROOT':root/'state'/'geoip','CONFIG':root/'config.json','CACHE':root/'cache.json','RULES':root/'rules.nft','RUNTIME':root/'engine.py'}.items()]
        for p in self.patches:p.start()
        g.write_json(g.CONFIG,policy());g.write_json(g.CACHE,cache());g.write_text(g.RULES,'old rules')
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def test_scheduled_active_refresh_publishes_and_keeps_snapshot(self):
        with patch.object(g,'collect_rir',return_value=cache('8.8.9.0/24')),patch.object(g,'validate_table'),patch.object(g,'live_table',return_value='old table'),patch.object(g,'replace_table') as publish:
            g.scheduled_update()
        self.assertEqual(publish.call_count,1);self.assertIn('8.8.9.0/24',publish.call_args.args[0])
        snapshots=list((g.ROOT/'scheduled-backups').glob('*.json'));self.assertEqual(len(snapshots),1)
        old=g.read_json(snapshots[0]);self.assertEqual(old['table'],'old table');self.assertEqual(old['rules'],'old rules')
        self.assertEqual(g.read_json(g.CACHE)['countries']['GR']['4'],['8.8.9.0/24'])
    def test_disabled_refresh_updates_cache_without_touching_firewall(self):
        g.write_json(g.CONFIG,policy(False))
        with patch.object(g,'collect_rir',return_value=cache()),patch.object(g,'live_table') as live,patch.object(g,'replace_table') as publish:
            g.scheduled_update()
        live.assert_not_called();publish.assert_not_called()
    def test_failed_download_keeps_prior_cache(self):
        before=g.CACHE.read_bytes()
        with patch.object(g,'collect_rir',side_effect=RuntimeError('download failed')),patch.object(g,'replace_table') as publish:
            with self.assertRaisesRegex(RuntimeError,'download failed'):g.scheduled_update()
        self.assertEqual(g.CACHE.read_bytes(),before);publish.assert_not_called()
    def test_large_shrink_is_rejected_without_changing_active_rules(self):
        before=g.CACHE.read_bytes()
        with patch.object(g,'collect_rir',return_value=cache('8.8.8.0/26')),patch.object(g,'replace_table') as publish:
            with self.assertRaisesRegex(ValueError,'50%'):g.scheduled_update()
        self.assertEqual(g.CACHE.read_bytes(),before);publish.assert_not_called()
    def test_cache_write_failure_restores_previous_table(self):
        original=g.write_json;attempts=[]
        def fail_once(path,value):
            if path==g.CACHE and not attempts:attempts.append(path);raise OSError('disk full')
            return original(path,value)
        with patch.object(g,'collect_rir',return_value=cache('8.8.9.0/24')),patch.object(g,'validate_table'),patch.object(g,'live_table',return_value='old table'),patch.object(g,'replace_table') as publish,patch.object(g,'write_json',side_effect=fail_once):
            with self.assertRaisesRegex(OSError,'disk full'):g.scheduled_update()
        self.assertEqual(publish.call_args_list[-1].args,('old table',));self.assertEqual(g.read_json(g.CACHE),cache())
    def test_pending_other_action_prevents_unattended_refresh(self):
        g.write_json(g.ROOT.parent/'backups'/'pending'/'manifest.json',{'status':'awaiting-confirmation'})
        with patch.object(g,'collect_rir') as fetch:
            with self.assertRaisesRegex(ValueError,'Another change'):g.scheduled_update()
        fetch.assert_not_called()
    def test_schedule_plan_has_no_confirmation_timer_and_retains_state_for_undo(self):
        with patch.object(geoip.system,'command',return_value=(1,'','')):
            plan=geoip.schedule_plan(policy(),'daily')
        self.assertFalse(plan.critical);self.assertTrue(plan.persist_runner)
        self.assertIn('OnCalendar=daily',plan.writes['/etc/systemd/system/'+g.UPDATE_TIMER])
        self.assertIn('Persistent=true',plan.writes['/etc/systemd/system/'+g.UPDATE_TIMER])
        self.assertIn('schedule-restore',str(plan.rollback_commands));self.assertIn('schedule-stop',str(plan.rollback_before))
        self.assertNotIn('--on-active=180s',str(plan.commands))
    def test_invalid_schedule_is_refused(self):
        with self.assertRaises(ValueError):g.config({**policy(),'update_schedule':'*;shell'})
    def test_selection_while_disabled_does_not_enable_filtering(self):
        plan=geoip.selection_plan(policy(False));self.assertFalse(json.loads(plan.writes[str(g.CONFIG)])['enabled']);self.assertFalse(plan.commands)
    def test_status_does_not_label_missing_runtime_as_active(self):
        with patch.object(g,'live_table',return_value=None),patch.object(geoip.shutil,'which',return_value='/sbin/nft'):
            self.assertIn('NOT ACTIVE',geoip.access_summary())
    def test_status_includes_selected_countries_and_explicit_exceptions(self):
        value={**policy(),'countries':['GR','RU'],'expanded':['GR','RU'],'trusted':['10.1.0.0/16']}
        g.write_json(g.CONFIG,value)
        with patch.object(g,'live_table',return_value='owned table'),patch.object(geoip.shutil,'which',return_value='/sbin/nft'):
            result=geoip.access_summary()
        self.assertIn('SSH Allowed from GR, RU',result);self.assertIn('Trusted exceptions: 1',result)
    def test_legacy_nft_json_without_table_comment_uses_text_marker(self):
        result=Mock(returncode=0,stdout=json.dumps({'nftables':[{'table':{'family':'inet','name':g.TABLE}}]}))
        text='table inet '+g.TABLE+' {\n comment "'+g.MARKER+'"\n}\n'
        with patch.object(g.subprocess,'run',return_value=result),patch.object(g,'command',return_value=text):self.assertEqual(g.live_table(),text)
    def test_unmarked_existing_table_remains_protected(self):
        result=Mock(returncode=0,stdout=json.dumps({'nftables':[{'table':{'name':g.TABLE}}]}))
        with patch.object(g.subprocess,'run',return_value=result),patch.object(g,'command',return_value='table inet '+g.TABLE+' {}'):
            with self.assertRaisesRegex(ValueError,'Unmanaged'):g.live_table()
    def test_browser_return_has_no_extra_pause(self):
        spec=importlib.util.spec_from_file_location('aegis_main_for_geo_tests',Path(__file__).parents[1]/'aegis.py');main=importlib.util.module_from_spec(spec);spec.loader.exec_module(main)
        ui=Mock(language='en',theme='slate');ui.t.side_effect=lambda en,el:en
        with patch.object(main,'call_root'),patch.object(main,'pause') as pause,patch.object(main.console,'section'):
            main.do(ui,{'kind':'geoip-browser'})
        pause.assert_not_called()


if __name__=='__main__':unittest.main()
