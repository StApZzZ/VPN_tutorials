"""The real installer parser and controller with SSH/deployment substituted."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("quickstart", ROOT/"deploy/quickstart.py")
qs=importlib.util.module_from_spec(spec)
spec.loader.exec_module(qs)


class QuickstartTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.key=self.root/"ssh-key";self.key.write_text("fake private test key")
        self.env=self.root/"quickstart.env"
        self.calls=[]
        self.settings={"SERVER_A_IP":"203.0.113.10","SSH_USER":"root","SSH_KEY":str(self.key)}
        self.remote_token=""
        self.run_code=0
        self.patchers=[patch.object(qs,"HERE",self.root),patch.dict(os.environ,{"QS_ENV":str(self.env)}),patch.object(sys,"argv",["quickstart.py"]),patch.object(qs.subprocess,"run",side_effect=self.command)]
        for obj in self.patchers:obj.start();self.addCleanup(obj.stop)

    def command(self,*args,**kwargs):
        command=args[0];self.calls.append(command)
        if command[0]=="ssh":return subprocess.CompletedProcess(command,0,self.remote_token+"\n","")
        if self.run_code:raise subprocess.CalledProcessError(self.run_code,command)
        return subprocess.CompletedProcess(command,0)

    def invoke(self,**settings):
        self.settings.update(settings)
        self.env.write_text("\n".join(key+"="+qs.shlex.quote(value) for key,value in self.settings.items())+"\n")
        return qs.main()

    def generated(self,name):
        return json.loads((self.root/"ansible/group_vars"/name).read_text())

    def test_first_install_uses_neutral_defaults_and_protected_files(self):
        self.assertEqual(self.invoke(),0)
        variables=self.generated("all.yml")
        self.assertEqual(variables["vpn_panel_tls_mode"],"selfsigned")
        self.assertEqual(variables["vpn_panel_xray_client_reality_server_name"],"www.cloudflare.com")
        self.assertEqual(variables["vpn_panel_enabled_protocols"],["wg","awg","vless"])
        token=self.generated("all.secrets.yml")["panel_secret_token"]
        self.assertGreaterEqual(len(token),40)
        for file in [self.env,*self.root.glob("ansible/group_vars/*.yml")]:
            self.assertEqual(file.stat().st_mode&0o777,0o600)
        self.assertEqual(self.calls[-1][0],"bash")
        self.assertNotIn(token," ".join(self.calls[-1]))

    def test_rerun_reuses_admin_token(self):
        self.invoke();token=self.generated("all.secrets.yml")["panel_secret_token"]
        self.calls.clear();self.invoke()
        self.assertEqual(self.generated("all.secrets.yml")["panel_secret_token"],token)
        self.assertEqual(len(self.calls),1)  # no remote probe when controller has its token

    def test_lost_controller_files_recover_token_with_sudo(self):
        self.remote_token="test-host-admin-token-2026"
        self.invoke(SSH_USER="ubuntu")
        self.assertEqual(self.generated("all.secrets.yml")["panel_secret_token"],self.remote_token)
        self.assertIn("sudo -n python3 -c",self.calls[0][-1])

    def test_quotes_comments_padding_and_substitutions_are_data(self):
        attack="$(touch /tmp/installer-should-not-execute) ${HOME} `id` # quoted"
        f=self.root/"parser.env";f.write_text('VALUE="'+attack+'"\nPAD=abc== # comment\nEMPTY=\n')
        self.assertEqual(qs.read_env(f),{"VALUE":attack,"PAD":"abc==","EMPTY":""})
        self.invoke(PANEL_SECRET_TOKEN=attack)
        self.assertEqual(self.generated("all.secrets.yml")["panel_secret_token"],attack)

    def test_split_connector_runs_after_gateway(self):
        self.invoke(SERVER_B_IP="192.0.2.5",CORP_CIDRS="10.20.0.0/16",CORP_DNS="10.20.0.53")
        self.assertEqual(len(self.calls),3)
        self.assertEqual(self.calls[-1][-2:],["--playbook","site-connector.yml"])
        self.assertEqual(self.generated("all.yml")["vpn_panel_dns_servers"],["10.20.0.53"])

    def test_oidc_and_ldap_can_both_be_enabled(self):
        self.invoke(AUTH_MODE="oidc",OIDC_DISCOVERY_URL="https://sso.example.com/.well-known/openid-configuration",OIDC_CLIENT_ID="vpn",OIDC_CLIENT_SECRET="dummy-secret",LDAP_ENABLED="true",LDAP_URL="ldaps://dc.example.com",LDAP_BIND_DN="CN=VPN,DC=example,DC=com",LDAP_BIND_PASSWORD="dummy-pass",LDAP_USER_BASE_DN="DC=example,DC=com")
        variables=self.generated("all.yml")
        self.assertTrue(variables["vpn_panel_oidc_enabled"] and variables["vpn_panel_ldap_enabled"])
        self.assertNotIn("vpn_panel_ldap_bind_password",variables)

    def test_bad_settings_fail_before_deploy(self):
        for settings in [{"SERVER_A_IP":"host;id"},{"SSH_USER":"root;id"},{"PROTOCOLS":"wg,typo"},{"TLS_MODE":"typo"},{"TLS_MODE":"custom"},{"TLS_MODE":"letsencrypt"},{"CORP_CIDRS":"fd00::/8"},{"CORP_DNS":"::1"},{"SERVER_B_IP":"192.0.2.5"},{"AUTH_MODE":"typo"},{"AUTH_MODE":"oidc"}]:
            previous=self.settings.copy()
            with self.subTest(settings=settings),self.assertRaises(ValueError):self.invoke(**settings)
            self.settings=previous
        self.assertEqual(self.calls,[])

    def test_http_requires_trusted_tls_proxy(self):
        with self.assertRaises(ValueError):self.invoke(TLS_MODE="none")
        self.assertEqual(self.calls,[])
        self.invoke(TRUSTED_PROXY_CIDRS="192.0.2.10/32",PANEL_PUBLIC_URL="https://vpn.example.com")
        self.assertEqual(self.generated("all.yml")["vpn_panel_public_url"],"https://vpn.example.com")

    def test_deploy_failure_is_not_reported_as_success(self):
        self.run_code=1
        with self.assertRaises(subprocess.CalledProcessError):self.invoke()


if __name__=="__main__":unittest.main()
