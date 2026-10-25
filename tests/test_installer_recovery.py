"""Mocked macOS/Windows failure lifecycles; no native service execution."""
import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import install
import relay

SCRATCH = Path.home() / ".hermes/cache/scratch"
SCRATCH.mkdir(parents=True, exist_ok=True)


class RecoveryTests(unittest.TestCase):
    @contextlib.contextmanager
    def lifecycle(self, platform):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory, contextlib.ExitStack() as stack:
            home = Path(directory)
            (home / "pythonw.exe").touch()
            self.registered = False
            self.fail_at = None
            self.removal_error = None
            self.probe_code = 3
            self.commands = []
            stack.enter_context(patch.object(install.Path, "home", return_value=home))
            stack.enter_context(patch.object(install.sys, "platform", platform))
            stack.enter_context(patch.object(install.sys, "executable", str(home / "python.exe")))
            stack.enter_context(patch.object(relay, "tailscale_ip", return_value="100.90.80.70"))
            data, service = install.paths(home, platform)
            # Use a real retained file, not a mock credential, to check rollback.
            data.mkdir(parents=True)
            (data / "token").write_text("test-only-retained-token")
            stack.enter_context(patch.object(relay, "token", return_value="test-only-retained-token"))
            stack.enter_context(patch.object(install.subprocess, "run", side_effect=self.mock_run))
            yield data, service

    def mock_run(self, command, check, **kwargs):
        self.commands.append(command)
        action = command[1] if len(command) > 1 else command[0]
        code = 0
        if command[0] == "powershell.exe":
            code = 0 if self.registered else self.probe_code
            self.assertIn("-2147024894", command[-1])
            self.assertIn("InnerException", command[-1])
        elif action in ("bootstrap", "/Create"):
            if self.fail_at == action:
                code = 5
            else:
                self.registered = True
        elif action == "/Run":
            code = 5 if self.fail_at == action else 0
        elif action in ("bootout", "/Delete"):
            if self.removal_error is not None:
                code = self.removal_error
            elif not self.registered:
                code = 3 if action == "bootout" else 1
            else:
                self.registered = False
        elif action == "/End":
            code = 1  # An already stopped task must not block Delete.
        if code and check:
            raise subprocess.CalledProcessError(code, command)
        return subprocess.CompletedProcess(command, code, stdout="HOME\\owner\n")

    def invoke(self, action):
        output = io.StringIO()
        with patch.object(install.sys, "argv", ["install.py", action]), contextlib.redirect_stdout(output):
            try:
                install.main()
            finally:
                self.output = output.getvalue()

    def test_failed_initial_registration_rolls_back_and_retry_works(self):
        for platform, failure in (("darwin", "bootstrap"), ("win32", "/Create"), ("win32", "/Run")):
            with self.subTest(platform=platform, failure=failure), self.lifecycle(platform) as (data, service):
                self.fail_at = failure
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke("install")
                self.assertFalse(service.exists())
                self.assertFalse(self.registered)
                self.assertNotIn("Startup registered.", self.output)
                self.assertEqual((data / "token").read_text(), "test-only-retained-token")
                self.assertTrue((data / "relay.py").is_file())
                self.fail_at = None
                self.invoke("install")
                self.assertTrue(service.exists())
                self.assertTrue(self.registered)
                self.invoke("uninstall")
                self.assertFalse(service.exists())
                self.assertFalse(self.registered)

    def test_macos_bootstrap_error_after_job_creation_is_rolled_back(self):
        with self.lifecycle("darwin") as (_, service):
            original = self.mock_run
            def run(command, **kwargs):
                if command[:2] == ["launchctl", "bootstrap"]:
                    self.registered = True
                    raise subprocess.CalledProcessError(5, command)
                return original(command, **kwargs)
            with patch.object(install.subprocess, "run", side_effect=run):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke("install")
            self.assertFalse(self.registered)
            self.assertFalse(service.exists())
            self.invoke("install")
            self.assertTrue(self.registered)

    def test_legacy_definition_without_job_can_be_uninstalled_then_reinstalled(self):
        for platform in ("darwin", "win32"):
            with self.subTest(platform=platform), self.lifecycle(platform) as (_, service):
                service.parent.mkdir(parents=True, exist_ok=True)
                service.write_text("left by failed registration")
                self.invoke("uninstall")
                self.assertFalse(service.exists())
                self.assertIn("Startup registration removed.", self.output)
                self.invoke("install")
                self.assertTrue(self.registered)

    def test_failed_rollback_retains_definition_for_explicit_recovery(self):
        for platform, failure in (("darwin", "bootstrap"), ("win32", "/Run")):
            with self.subTest(platform=platform), self.lifecycle(platform) as (_, service):
                self.fail_at = failure
                self.removal_error = 5
                with self.assertRaisesRegex(RuntimeError, "rollback could not be confirmed"):
                    self.invoke("install")
                self.assertTrue(service.exists())
                self.assertNotIn("Startup registered.", self.output)
                self.fail_at = None
                self.removal_error = None
                self.invoke("uninstall")
                self.assertFalse(service.exists())
                self.invoke("install")
                self.assertTrue(self.registered)

    def test_arbitrary_deregistration_errors_never_claim_uninstall(self):
        for platform in ("darwin", "win32"):
            for registered in (False, True):
                for probe_code in (0, 1):
                    with self.subTest(platform=platform, registered=registered, probe_code=probe_code), self.lifecycle(platform) as (_, service):
                        service.parent.mkdir(parents=True, exist_ok=True)
                        service.write_text("retained definition")
                        self.registered = registered
                        self.removal_error = 5
                        self.probe_code = probe_code
                        with self.assertRaises(subprocess.CalledProcessError):
                            self.invoke("uninstall")
                        self.assertTrue(service.exists())
                        self.assertNotIn("Startup registration removed.", self.output)

    def test_missing_windows_probe_executable_fails_closed(self):
        with self.lifecycle("win32") as (_, service):
            service.write_text("retained definition")
            original = self.mock_run
            def run(command, **kwargs):
                if command[0] == "powershell.exe":
                    raise FileNotFoundError("powershell.exe")
                return original(command, **kwargs)
            with patch.object(install.subprocess, "run", side_effect=run):
                with self.assertRaises(FileNotFoundError):
                    self.invoke("uninstall")
            self.assertTrue(service.exists())
            self.assertNotIn("Startup registration removed.", self.output)


if __name__ == "__main__":
    unittest.main()
