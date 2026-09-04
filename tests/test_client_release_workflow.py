import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class ClientReleaseWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (
            ROOT / ".github" / "workflows" / "client-release.yml"
        ).read_text(encoding="utf-8")

    def test_release_is_manual_and_publication_is_disabled_by_default(self):
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("publish:\n", self.workflow)
        self.assertIn("default: false", self.workflow)
        self.assertNotIn("push:\n", self.workflow)

    def test_ci_uses_only_ci_secrets_and_official_publish_script(self):
        self.assertIn("CLIENT_SIGNING_PFX_BASE64", self.workflow)
        self.assertIn("CLIENT_RELEASE_SSH_KEY", self.workflow)
        self.assertIn("CLIENT_RELEASE_KNOWN_HOSTS", self.workflow)
        self.assertIn("publish_client_release.ps1 -PublishExisting", self.workflow)
        self.assertNotIn("git clone", self.workflow.lower())

    def test_untrusted_inputs_are_passed_through_environment_variables(self):
        self.assertIn("RELEASE_NOTES: ${{ inputs.notes }}", self.workflow)
        self.assertIn("-Notes', $env:RELEASE_NOTES", self.workflow)
        self.assertNotIn("'${{ inputs.notes }}'", self.workflow)
        self.assertIn('$expectedTag = "client-v$clientVersion"', self.workflow)

    def test_release_payload_contains_browser_extension(self):
        builder = (ROOT / "tools" / "build_client_release.py").read_text(
            encoding="utf-8"
        )
        extension = ROOT / "browser_extension"
        self.assertIn('BROWSER_EXTENSION_DIRNAME = "browser-extension"', builder)
        self.assertIn('ROOT / "browser_extension"', builder)
        self.assertTrue((extension / "options.html").is_file())
        self.assertTrue((extension / "options.js").is_file())

    def test_release_payload_uses_the_stable_executable_name(self):
        builder = (ROOT / "tools" / "build_client_release.py").read_text(
            encoding="utf-8"
        )
        candidate = (ROOT / "tools" / "build_v2_candidate.py").read_text(
            encoding="utf-8"
        )
        launcher = (ROOT / "tools" / "install_client_launcher.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('update_root / "usage-guard.exe"', builder)
        self.assertIn('"--name", "usage-guard"', candidate)
        self.assertIn('root / "usage-guard.exe"', launcher)
        self.assertNotIn('update_root / "usage-guard-v2.exe"', builder)

    def test_installers_bundle_translations_and_ci_audits_them(self):
        builder = (ROOT / "tools" / "build_client_release.py").read_text(
            encoding="utf-8"
        )
        setup = (ROOT / "tools" / "setup_client_qt.py").read_text(
            encoding="utf-8"
        )
        launcher = (ROOT / "tools" / "install_client_launcher.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("ROOT / 'locales'", builder)
        self.assertIn("from i18n import _", setup)
        self.assertIn("from i18n import _", launcher)
        self.assertIn("python .\\tools\\audit_i18n.py", self.workflow)
        self.assertIn("node .\\tools\\check_pwa_i18n.js", self.workflow)

    def test_powershell_five_does_not_abort_on_pyinstaller_information(self):
        publisher = (
            ROOT / "tools" / "publish_client_release.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("$ErrorActionPreference = 'Continue'", publisher)
        self.assertIn("$buildExitCode = $LASTEXITCODE", publisher)
        self.assertIn("if ($buildExitCode -ne 0)", publisher)

    def test_publisher_has_no_personal_infrastructure_defaults(self):
        publisher = (
            ROOT / "tools" / "publish_client_release.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[string]$Server = ''", publisher)
        self.assertIn("[string]$RemoteUser = ''", publisher)
        self.assertIn("[string]$RemoteDirectory = ''", publisher)
        self.assertNotIn("nicolas.sindelar.fr", publisher)
        self.assertNotIn("/home/nicklaus", publisher)


if __name__ == "__main__":
    unittest.main()
