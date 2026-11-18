"""GeoIP policy boundaries, scoped rollback and bulk sets / Έλεγχοι GeoIP και SSH."""
import contextlib
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
from aegis import geoip,geoip_engine as g,selection
from aegis.geodata import COUNTRIES,CONTINENTS


def cfg(**updates):
    return {**geoip.defaults(),'enabled':True,'ports':[22],'trusted':['192.168.5.10/32'],**updates}


def cache(**updates):
    return {'schema':1,'updated':'2026-11-18T12:00:00+00:00','source':'rir',
            'countries':{'GR':{'4':['8.8.8.0/24'],'6':['2001:4860::/32']}},'sources':[],'warnings':[],**updates}


class Data(unittest.TestCase):
    def test_continents_cover_every_country_once(self):
        codes=[c for group in CONTINENTS.values() for c in group['countries']]
        self.assertEqual(set(codes),set(COUNTRIES));self.assertEqual(len(codes),len(set(codes)));self.assertEqual(len(COUNTRIES),250)
    def test_normalized_cache_remains_valid_after_adjacent_large_merges(self):
        values=g.collapse(['6.0.0.0/8','7.0.0.0/8'],4)
        self.assertEqual(values,['6.0.0.0/8','7.0.0.0/8'])
        data=cache(countries={'GR':{'4':values,'6':[]}})
        text,rows=g.render(cfg(trusted=[]),data)
        self.assertEqual(rows['4'],['6.0.0.0/7'])
        self.assertIn('6.0.0.0/7',text)
    def test_expansion_is_union_not_overlapping_duplicate_rules(self):
        result=geoip.expand(['GR'],['eu']);self.assertEqual(result.count('GR'),1);self.assertIn('DE',result)
        with self.assertRaises(ValueError):geoip.expand(['ZZ'],[])
    def test_rir_range_is_summarized_and_ipv6_supported(self):
        raw=b'ripencc|GR|ipv4|8.8.8.0|384|20260101|allocated\nripencc|GR|ipv6|2001:4860::|32|20260101|assigned\n'
        rows=g.parse_rir(raw,COUNTRIES)['GR'];self.assertEqual(rows['4'],['8.8.8.0/24','8.8.9.0/25']);self.assertEqual(rows['6'],['2001:4860::/32'])
    def test_invalid_and_empty_rir_fails(self):
        for raw in (b'<html>error</html>',b'ripencc|GR|ipv4|8.8.8.0|0|20260101|allocated'):
            with self.assertRaises(ValueError):g.parse_rir(raw,COUNTRIES)
    def test_default_private_multicast_and_overbroad_prefixes_rejected(self):
        for value in ('0.0.0.0/0','10.0.0.0/8','224.0.0.0/4','::/0','2001:db8::/32','fc00::/7','2000::/3','8.8.8.1/24'):
            with self.assertRaises(ValueError):g.safe_network(value)
        self.assertEqual(str(g.safe_network('10.0.0.0/8',trusted=True)),'10.0.0.0/8')
    def test_ripe_api_ranges_and_families(self):
        raw=json.dumps({'data':{'resources':{'ipv4':['8.8.8.0-8.8.8.255'],'ipv6':['2001:4860::/32']}}}).encode()
        self.assertEqual(g.parse_gr_api(raw)['4'],['8.8.8.0/24'])
    def test_invalid_zone_feed_urls_rejected(self):
        for value in ('file:///etc/shadow','ftp://example.com','http://u:p@example.com','https://host/?x=1','https://host/#f','http://host:invalid'):
            with self.assertRaises(ValueError):g.base_url(value)
        self.assertEqual(g.base_url('https://feed.example.org/'),'https://feed.example.org')
    def test_download_rejects_protocol_redirect_and_size(self):
        response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        response.geturl.return_value='http://elsewhere.invalid/feed';response.read.return_value=b'abc'
        with patch.object(g.urllib.request,'urlopen',return_value=response):
            with self.assertRaises(ValueError):g.download('https://example.invalid/feed')
            response.geturl.return_value='https://example.invalid/feed';response.read.return_value=b'abcd'
            with self.assertRaises(ValueError):g.download('https://example.invalid/feed',3)
    def test_selection_rejects_missing_data_and_wrong_source(self):
        for data in (cache(countries={}),cache(source='other'),cache(countries={'GR':{'4':['0.0.0.0/0'],'6':[]}})):
            with self.assertRaises(ValueError):g.selected_networks(cfg(),data)
    def test_empty_territory_does_not_break_continent_selection(self):
        data=cache(countries={'GR':{'4':['8.8.8.0/24'],'6':[]},'AX':{'4':[],'6':[]}})
        value=cfg(countries=['AX','GR'],expanded=['AX','GR'])
        self.assertEqual(g.selected_networks(value,data)['4'],['8.8.8.0/24'])
        with self.assertRaises(ValueError):g.selected_networks(cfg(countries=['AX'],expanded=['AX']),data)
    def test_provider_paths_and_dual_stack(self):
        value=cfg(source='zone-feed',base_url='https://feed.example.org')
        with patch.object(g,'download',side_effect=[b'8.8.8.0/24\n',b'2001:4860::/32\n']) as fetch:
            result=g.collect_feed(value)
        self.assertEqual([call.args[0] for call in fetch.call_args_list],['https://feed.example.org/feeds/gr.zone','https://feed.example.org/feeds/gr-v6.zone'])
        self.assertEqual(len(result['countries']['GR']['6']),1)
    def test_bad_custom_list_is_not_silently_accepted(self):
        with patch.object(g,'download',return_value=b'<html>403</html>'):
            with self.assertRaises(ValueError):g.collect_feed(cfg(source='zone-feed',base_url='https://feed.invalid'))
    def test_shrink_guard_compares_address_coverage(self):
        small=cache(countries={'GR':{'4':['8.8.8.0/26'],'6':['2001:4860::/34']}})
        self.assertEqual(len(geoip.shrink_warnings(cache(),small,cfg())),2)
    def test_bad_port_input_rejected(self):
        self.assertEqual(geoip.parse_ports('22, 2222 22'),[22,2222])
        for text in ('','0','65536','22;flush ruleset','-1'):
            with self.assertRaises(ValueError):geoip.parse_ports(text)


class Rules(unittest.TestCase):
    def test_two_interval_sets_and_five_rules_for_thousands_of_prefixes(self):
        values=[str(ipaddress.ip_network((int(ipaddress.IPv4Address('8.0.0.0'))+i*512,24))) for i in range(10000)]
        data=cache(countries={'GR':{'4':values,'6':['2001:4860::/32']}})
        text,networks=g.render(cfg(),data)
        self.assertEqual(text.count('    set allowed_v'),2);self.assertEqual(text.count('counter'),3)
        self.assertEqual(text.count(' return\n'),4);self.assertEqual(text.count(' drop\n'),1)
        self.assertNotIn('flush ruleset',text);self.assertNotIn('ignoreip',text);self.assertNotIn('f2b',text)
        self.assertIn('flags interval; auto-merge;',text);self.assertEqual(len(networks['4']),10001)
    def test_empty_ipv6_country_list_still_has_final_ssh_drop(self):
        data=cache(countries={'GR':{'4':['8.8.8.0/24'],'6':[]}})
        text,_=g.render(cfg(),data);self.assertIn('ip6 saddr @allowed_v6',text);self.assertIn('tcp dport { 22 } counter drop',text)
    def test_whitelist_and_existing_session_paths_are_present(self):
        text,rows=g.render(cfg(),cache());self.assertIn('192.168.5.10/32',rows['4'])
        self.assertIn('ct state established,related return',text);self.assertIn('iifname "lo" return',text)
        self.assertNotIn(' accept\n',text) # Never claim an allow overrides other chains' drop verdicts.
    def test_atomic_table_replacement_is_scoped_and_checked(self):
        with patch.object(g,'live_table',return_value='old table'),patch.object(g,'command') as command:
            g.replace_table('new owned table\n')
        self.assertEqual(command.call_args_list[0].args[0],['nft','-c','-f','-'])
        self.assertEqual(command.call_args_list[1].args[0],['nft','-f','-'])
        self.assertEqual(command.call_args_list[1].args[1],'delete table inet aegis_geoip_ssh\nnew owned table\n')
    def test_validation_failure_never_runs_apply(self):
        with patch.object(g,'live_table',return_value=None),patch.object(g,'command',side_effect=RuntimeError('syntax')) as command:
            with self.assertRaises(RuntimeError):g.replace_table('bad')
        self.assertEqual(command.call_count,1)
    def test_unmanaged_table_is_refused(self):
        result=Mock(returncode=0,stdout=json.dumps({'nftables':[{'table':{'name':g.TABLE,'comment':'unmanaged'}}]}))
        with patch.object(g.subprocess,'run',return_value=result):
            with self.assertRaisesRegex(ValueError,'Unmanaged'):g.live_table()
    def test_snapshot_ids_cannot_escape_state_dir(self):
        for token in ('../../etc/shadow','x'*32,'a'*31):
            with self.assertRaises(ValueError):g.snapshot_path(token)


class Plans(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();root=Path(self.temp.name)
        self.patches=[patch.object(g,key,value) for key,value in {'ROOT':root/'state','CONFIG':root/'config.json','CACHE':root/'cache.json','RULES':root/'rules.nft','RUNTIME':root/'engine.py'}.items()]
        self.patches += [patch.object(geoip,'UNIT_PATH',root/'unit.service'),patch.object(geoip,'ports_detected',return_value=[22]),patch.object(geoip.shutil,'which',return_value='/usr/sbin/nft'),patch.object(g,'live_table',return_value=None),patch.object(geoip.system,'ssh_connection',return_value='192.168.5.10 40000 192.168.5.20 22')]
        for p in self.patches:p.start()
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def test_enable_is_permanent_backed_up_and_has_no_ruleset_flush(self):
        plan=geoip.policy_plan(cfg(),cache())
        self.assertFalse(plan.critical);self.assertTrue(plan.persist_runner)
        self.assertIn(str(g.CONFIG),plan.writes);self.assertIn(str(g.RUNTIME),plan.writes)
        self.assertIn(str(g.CACHE),plan.write_summaries);self.assertIn(str(g.RULES),plan.write_summaries)
        self.assertIn('capture',plan.before[0]);self.assertIn('restore',plan.rollback_commands[-1])
        self.assertNotIn('flush ruleset',plan.preview());self.assertNotIn('8.8.8.0/24',plan.preview())
        self.assertIn('Before=ssh.service sshd.service ssh.socket',plan.writes[str(geoip.UNIT_PATH)])
        self.assertNotIn('ExecStop=',plan.writes[str(geoip.UNIT_PATH)])
    def test_management_source_cannot_be_locked_out(self):
        with self.assertRaisesRegex(ValueError,'excluded'):geoip.policy_plan(cfg(trusted=[]),cache())
    def test_all_detected_ssh_ports_must_be_covered(self):
        with patch.object(geoip,'ports_detected',return_value=[22,2222]):
            with self.assertRaisesRegex(ValueError,'all detected'):geoip.policy_plan(cfg(),cache())
    def test_guard_rejects_concurrent_file_edits(self):
        plan=geoip.policy_plan(cfg(),cache());g.CONFIG.write_text('{}')
        with self.assertRaisesRegex(ValueError,'files changed'):plan.guard()
    def test_cache_update_does_not_touch_firewall_when_disabled(self):
        plan=geoip.cache_plan(cache());self.assertFalse(plan.critical);self.assertFalse(plan.commands);self.assertEqual(list(plan.writes),[str(g.CACHE)])
    def test_disable_only_removes_own_table_and_retains_rollback(self):
        plan=geoip.policy_plan(cfg(enabled=False))
        self.assertFalse(plan.critical);self.assertIn('disable',plan.commands[-1]);self.assertFalse(plan.package_change)
    def test_restore_replays_only_owned_runtime_snapshot(self):
        token='a'*32;snapshot={'schema':1,'table':'prior table','unit':{'enabled':False,'active':False}}
        g.write_json(g.snapshot_path(token),snapshot)
        with patch.object(g,'replace_table') as replace,patch.object(g,'command'),patch.object(g.subprocess,'run',return_value=Mock(returncode=0)):
            g.restore(token)
        replace.assert_called_once_with('prior table')
    def test_snapshot_captures_table_and_boot_state(self):
        token='b'*32
        with patch.object(g,'live_table',return_value='owned prior table'),patch.object(g,'unit_state',return_value={'active':True,'enabled':True}):g.capture(token)
        self.assertEqual(g.read_json(g.snapshot_path(token))['table'],'owned prior table')
        with self.assertRaises(ValueError):g.capture(token)


if __name__=='__main__':unittest.main()
