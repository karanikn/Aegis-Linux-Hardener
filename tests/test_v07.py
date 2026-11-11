"""Update trust boundary and exact-row public-key removal / Όρια ενημέρωσης και SSH."""
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch,Mock
from aegis import users,selfupdate,console


def key(comment='demo'):
    name=b'ssh-ed25519';blob=len(name).to_bytes(4,'big')+name+(32).to_bytes(4,'big')+b'a'*32
    return 'ssh-ed25519 '+base64.b64encode(blob).decode()+' '+comment


class PublicKeys(unittest.TestCase):
    def home(self,folder):
        account=types.SimpleNamespace(pw_dir=folder,pw_uid=1000,pw_gid=1000)
        path=Path(folder)/'.ssh/authorized_keys';path.parent.mkdir();return account,path
    def test_restricted_options_are_parsed_without_losing_comment(self):
        row=users.parse_public_key('command="echo hello",restrict '+key('laptop test'))
        self.assertTrue(row['restricted']);self.assertEqual(row['comment'],'laptop test');self.assertTrue(row['fingerprint'].startswith('SHA256:'))
    def test_comment_blank_and_private_material_are_not_key_rows(self):
        for line in ('','# comment','-----BEGIN OPENSSH PRIVATE KEY-----','invalid ssh-rsa xyz'):
            self.assertIsNone(users.parse_public_key(line))
    def test_fingerprint_ignores_options_and_comment(self):
        self.assertEqual(users.parse_public_key(key())['fingerprint'],users.parse_public_key('restrict '+key('other'))['fingerprint'])
    def test_exact_row_removal_preserves_other_rows_and_crlf(self):
        with tempfile.TemporaryDirectory() as folder:
            account,path=self.home(folder)
            content='# note\r\n'+key('one')+'\r\nrestrict '+key('two')+'\r\n\r\n'
            path.write_bytes(content.encode());path.chmod(0o640)
            with patch.object(users,'local_user',return_value=account),patch.object(users.system,'ssh_connection',return_value='192.0.2.1 1 192.0.2.2 22'):
                p,text,rows=users.ssh_keys('demo');plan=users.remove_ssh_key_plan('demo','authorized_keys',1,text);plan.guard()
            self.assertEqual([r['index'] for r in rows],[1,2]);self.assertEqual(plan.writes[str(path)],'# note\r\nrestrict '+key('two')+'\r\n\r\n')
            self.assertTrue(plan.critical);self.assertEqual(plan.modes[str(path)],0o640)
    def test_newer_key_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            account,path=self.home(folder);path.write_text(key()+'\n')
            with patch.object(users,'local_user',return_value=account):
                plan=users.remove_ssh_key_plan('demo','authorized_keys',0,path.read_text());path.write_text(key('changed')+'\n')
                with self.assertRaisesRegex(ValueError,'changed'):plan.guard()
    def test_mismatched_expected_content_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            account,path=self.home(folder);path.write_text(key())
            with patch.object(users,'local_user',return_value=account):
                with self.assertRaises(ValueError):users.remove_ssh_key_plan('demo','authorized_keys',0,'old')
    def test_symlink_and_unknown_filename_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            account,path=self.home(folder);path.symlink_to(Path(folder)/'other')
            with patch.object(users,'local_user',return_value=account):
                with self.assertRaises(ValueError):users.ssh_keys('demo')
                with self.assertRaises(ValueError):users.ssh_keys('demo','../../shadow')
    def test_nonkey_row_cannot_be_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            account,path=self.home(folder);path.write_text('# preserve\n'+key())
            with patch.object(users,'local_user',return_value=account):
                with self.assertRaises(ValueError):users.remove_ssh_key_plan('demo','authorized_keys',0,path.read_text())


class Updates(unittest.TestCase):
    def record(self,data=None):
        data=data or b'#!/usr/bin/env bash\n# Aegis release: 0.7.0\nexit 0\n'
        return data,{'schema':1,'version':'0.7.0','installer_url':selfupdate.INSTALL_URL,'sha256':hashlib.sha256(data).hexdigest()}
    def test_metadata_rejects_external_installer_and_invalid_version(self):
        _,record=self.record()
        for field,value in [('installer_url','https://evil.invalid/a'),('version','../../bad'),('sha256','missing'),('schema',2)]:
            altered={**record,field:value}
            with self.assertRaises(ValueError):selfupdate.metadata(json.dumps(altered).encode())
    def test_checksum_mismatch_and_marker_mismatch_reject(self):
        data,record=self.record()
        with self.assertRaises(ValueError):selfupdate.verify(data+b'bad',record)
        data,record=self.record(b'#!/usr/bin/env bash\necho no marker\n')
        with self.assertRaises(ValueError):selfupdate.verify(data,record)
    def test_no_code_executes_before_approval(self):
        data,record=self.record()
        with patch.object(selfupdate,'fetch',return_value=json.dumps(record).encode()) as fetch,patch.object(selfupdate.subprocess,'run') as execute,contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(selfupdate.run(lambda label:False,'0.6.0'));execute.assert_not_called();self.assertEqual(fetch.call_count,1)
    def test_no_downgrade_or_reinstall(self):
        _,record=self.record()
        for current in ('0.7.0','0.8.0'):
            with patch.object(selfupdate,'fetch',return_value=json.dumps(record).encode()),patch.object(selfupdate.subprocess,'run') as execute,contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(selfupdate.run(Mock(side_effect=AssertionError('No prompt')),current));execute.assert_not_called()
    def test_corrupt_installer_never_executes(self):
        _,record=self.record()
        with patch.object(selfupdate,'fetch',side_effect=[json.dumps(record).encode(),b'corrupt']),patch.object(selfupdate.subprocess,'run') as execute,contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):selfupdate.run(lambda label:True,'0.6.0')
            execute.assert_not_called()
    def test_verified_installer_check_then_install_and_temp_cleanup(self):
        data,record=self.record();seen=[]
        def execute(args,**kw):
            seen.append((args,Path(args[1]).stat().st_mode & 0o777));self.assertEqual(Path(args[1]).read_bytes(),data)
        with patch.object(selfupdate,'fetch',side_effect=[json.dumps(record).encode(),data]),patch.object(selfupdate.os,'geteuid',return_value=0),patch.object(selfupdate.subprocess,'run',side_effect=execute),patch.object(selfupdate,'installed_version',return_value='0.7.0'),contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(selfupdate.run(lambda label:True,'0.6.0'))
        self.assertEqual([x[0][-1] for x in seen],['--check','--install']);self.assertEqual(seen[0][1],0o600);self.assertFalse(Path(seen[0][0][1]).exists())
    def test_installer_cancel_is_not_reported_as_updated(self):
        data,record=self.record()
        with patch.object(selfupdate,'fetch',side_effect=[json.dumps(record).encode(),data]),patch.object(selfupdate.os,'geteuid',return_value=0),patch.object(selfupdate.subprocess,'run'),patch.object(selfupdate,'installed_version',return_value='0.6.0'),contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(selfupdate.run(lambda label:True,'0.6.0'))
    def test_redirect_and_unapproved_download_are_rejected(self):
        with self.assertRaises(ValueError):selfupdate.fetch('http://karanik.gr/installer',100)
        with self.assertRaises(ValueError):selfupdate.NoRedirect().redirect_request(None,None,302,'moved',{},'https://elsewhere.invalid')
    def test_oversized_download_rejected(self):
        response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        response.geturl.return_value=selfupdate.MANIFEST_URL;response.read.return_value=b'x'*11
        opener=Mock();opener.open.return_value=response
        with patch.object(selfupdate.urllib.request,'build_opener',return_value=opener):
            with self.assertRaises(ValueError):selfupdate.fetch(selfupdate.MANIFEST_URL,10)
    def test_confirmation_aliases_and_invalid_choice(self):
        with patch('builtins.input',side_effect=['garbage','NO']),patch.object(console.sys.stdin,'isatty',return_value=False),contextlib.redirect_stdout(io.StringIO()):self.assertFalse(console.confirm())


if __name__=='__main__':unittest.main()
