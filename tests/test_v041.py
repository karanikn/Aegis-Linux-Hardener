"""Install-on-demand guards. No package manager runs in these tests."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
from aegis import actions,catalog,dependencies,lynis,system

spec=importlib.util.spec_from_file_location('entry_v041',Path(__file__).resolve().parents[1]/'aegis.py')
app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)

class DependenciesV041(unittest.TestCase):
    def test_present_dependency_does_not_prompt_or_install(self):
        with patch.object(dependencies,'available',return_value=True),patch.object(actions,'apply') as apply:
            self.assertTrue(dependencies.ensure({'kind':'lynis-control','control':'audit-watches'}))
        apply.assert_not_called()
    def test_cancel_missing_dependency_stops_original_action(self):
        with patch.object(dependencies,'available',return_value=False),patch.object(lynis,'install_profile',return_value=actions.Plan('audit')),patch.object(actions,'apply',return_value=None),contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(dependencies.ensure({'kind':'lynis-control','control':'audit-watches'}))
    def test_success_rechecks_and_preserves_original_request(self):
        request={'kind':'security-inspect','check':'audit'};before=dict(request)
        plan=actions.Plan('audit')
        with patch.object(dependencies,'available',side_effect=[False,True]),patch.object(lynis,'install_profile',return_value=plan) as profile,patch.object(actions,'apply',return_value='id') as apply,contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(dependencies.ensure(request,'ssh-origin'))
        profile.assert_called_once_with('auditd');apply.assert_called_once_with(plan,'ssh-origin')
        self.assertEqual(before,request)
    def test_installed_but_still_missing_does_not_retry_forever(self):
        with patch.object(dependencies,'available',return_value=False),patch.object(lynis,'install_profile',return_value=actions.Plan('audit')),patch.object(actions,'apply',return_value='id') as apply,contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError,'still unavailable'):dependencies.ensure({'kind':'security-inspect','check':'audit'})
        self.assertEqual(apply.call_count,1)
    def test_password_quality_uses_managed_pam_profile(self):
        row=dependencies.requirements({'kind':'lynis-control','control':'password-quality'})[0]
        self.assertEqual(row['profile'],'pwquality');self.assertEqual(row['packages'],['libpam-pwquality'])
    def test_optional_ccze_cancellation_keeps_plain_logs_available(self):
        with patch.object(dependencies,'available',return_value=False),patch.object(catalog,'app_plan',return_value=actions.Plan('ccze')),patch.object(actions,'apply',return_value=None),contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(dependencies.ensure({'kind':'logs-browser','user':'demo'}))
    def test_unknown_requests_cannot_supply_install_commands(self):
        self.assertEqual(dependencies.requirements({'kind':'unknown','commands':['rm','-rf','/']}),[])
    def test_important_diagnostics_mapped(self):
        for check in ('needrestart','debsums','deleted','audit','versions','aide','vulnerabilities'):
            self.assertTrue(dependencies.requirements({'kind':'security-inspect','check':check}),check)
    def test_interactive_cancellation_prevents_plan_construction(self):
        with patch.object(system,'debian_based',return_value=True),patch.object(dependencies,'ensure',return_value=False),patch.object(lynis,'plan') as plan:
            self.assertIs(app.dispatch({'kind':'lynis-control','control':'audit-watches','interactive':True},''),False)
        plan.assert_not_called()
    def test_action_resumes_exactly_once_after_success(self):
        plan=actions.Plan('original action')
        with patch.object(system,'debian_based',return_value=True),patch.object(dependencies,'ensure',return_value=True) as ensure,patch.object(lynis,'plan',return_value=plan) as construct,patch.object(actions,'apply') as apply:
            app.dispatch({'kind':'lynis-control','control':'audit-watches','interactive':True},'origin')
        ensure.assert_called_once();construct.assert_called_once();apply.assert_called_once_with(plan,'origin')
    def test_password_quality_q_cancels_cleanly_after_dependency_step(self):
        with patch.object(system,'debian_based',return_value=True),patch.object(dependencies,'ensure',return_value=True),patch.object(app.console,'ask',return_value='q'),patch.object(lynis,'plan') as plan,contextlib.redirect_stdout(io.StringIO()):
            self.assertIs(app.dispatch({'kind':'lynis-control','control':'password-quality','prompt_minlen':True,'interactive':True},''),False)
        plan.assert_not_called()
    def test_declined_ui_prepare_does_not_ask_policy_questions(self):
        ui=Mock();ui.language='en';ui.choose.side_effect=['password-quality',None]
        with patch.object(app,'prepare_dependencies',return_value=False):app.lynis_menu(ui)
        ui.prompt.assert_not_called()

if __name__=='__main__':unittest.main()
