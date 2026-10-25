import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import socket
import stat
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import relay
import install
import private_store

SCRATCH = Path.home() / ".hermes/cache/scratch"
SCRATCH.mkdir(parents=True, exist_ok=True)


class SecurityTests(unittest.TestCase):
    def test_domain_boundaries(self):
        for host in ("youtube.com", "r1.googlevideo.com", "YOUTUBE.COM."):
            self.assertTrue(relay.allowed(host), host)
        for host in ("youtube.com.evil.test", "evilyoutube.com", "127.0.0.1", "::1", "",
                     "foo..youtube.com", "a\x00.youtube.com", "x/youtube.com", "-a.youtube.com",
                     "é.youtube.com", "a.youtube.com..", "a" * 64 + ".youtube.com"):
            self.assertFalse(relay.allowed(host), repr(host))

    @patch("relay.shutil.which", return_value="/fake/tailscale")
    @patch("relay.Path.is_file", return_value=True)
    @patch("relay.subprocess.run")
    def test_binding_override_must_match_local_tailscale(self, run, *_):
        run.return_value = Mock(returncode=0, stdout="100.90.80.70\n")
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(relay.tailscale_ip(), "100.90.80.70")
            for host in ("0.0.0.0", "127.0.0.1", "192.168.1.3", "8.8.8.8", "100.90.80.71", "::", "hostname"):
                with patch.dict(os.environ, {"WIZARD_RELAY_HOST": host}):
                    with self.assertRaises(ValueError):
                        relay.tailscale_ip()
            with patch.dict(os.environ, {"WIZARD_RELAY_HOST": "100.90.80.70"}):
                self.assertEqual(relay.tailscale_ip(), "100.90.80.70")
            run.return_value.stdout = "192.168.1.3\n"
            with self.assertRaises(ValueError):
                relay.tailscale_ip()

    def test_secret_storage_export_and_no_stdout(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            home = Path(directory) / "private"
            with patch.object(relay, "HOME", home):
                secret = relay.token()
                self.assertEqual(relay.token(), secret)
                self.assertEqual(stat.S_IMODE((home / "token").stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(home.stat().st_mode), 0o700)
                destination = home / "pairing/connection.json"
                out = io.StringIO()
                with patch.object(relay, "tailscale_ip", return_value="100.90.80.70"), contextlib.redirect_stdout(out):
                    relay.pairing(destination)
                    with self.assertRaises(FileExistsError):
                        relay.pairing(destination)
                    with self.assertRaises(ValueError):
                        relay.pairing(home / "wrong.json")
                self.assertNotIn(secret, out.getvalue())
                record = json.loads(destination.read_text())
                self.assertEqual(record["password"], secret)
                self.assertEqual(record["schema"], "wizard-home-relay-pairing-v1")
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
                (home / "token").chmod(0o644)
                with self.assertRaises(ValueError):
                    relay.token()

    def test_links_refused(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            root = Path(directory)
            (root / "target").mkdir()
            (root / "link").symlink_to(root / "target", target_is_directory=True)
            with self.assertRaises(ValueError):
                private_store.private_dir(root / "link")
            (root / "target/file").write_text("not-a-token")
            (root / "target/link").symlink_to(root / "target/file")
            with self.assertRaises(ValueError):
                private_store.read_private(root / "target/link")

    def test_legacy_address_never_prints_secret(self):
        result = subprocess.run([sys.executable, "relay.py", "address"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("socks5h://", result.stdout + result.stderr)


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.secret = "test-only-not-a-real-credential"
        self.server = await asyncio.start_server(lambda r, w: relay.handle(r, w, self.secret), "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        self.clients = []

    async def asyncTearDown(self):
        for writer in self.clients:
            writer.close()
            await writer.wait_closed()
        self.server.close()
        await self.server.wait_closed()
        await asyncio.sleep(0.02)

    async def client(self, password=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.clients.append(writer)
        writer.write(b"\x05\x01\x02")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x02")
        password = (self.secret if password is None else password).encode()
        writer.write(b"\x01\x06wizard" + bytes([len(password)]) + password)
        await writer.drain()
        status = await reader.readexactly(2)
        return reader, writer, status

    async def request(self, host="youtube.com", port=443, cmd=1, reserved=0):
        reader, writer, status = await self.client()
        self.assertEqual(status, b"\x01\x00")
        encoded = host.encode()
        writer.write(bytes([5, cmd, reserved, 3, len(encoded)]) + encoded + port.to_bytes(2, "big"))
        await writer.drain()
        return reader, writer, await reader.readexactly(10)

    async def test_no_anonymous(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.clients.append(writer)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\xff")

    async def test_wrong_and_unicode_credentials(self):
        for password in ("wrong", "é"):
            _, _, status = await self.client(password)
            self.assertEqual(status, b"\x01\x01")

    async def test_policy_denials_never_connect(self):
        with patch.object(relay, "connect_provider", new_callable=AsyncMock) as upstream:
            for kwargs in ({"host": "example.com"}, {"port": 22}, {"cmd": 2}, {"cmd": 3},
                           {"reserved": 1}, {"host": "127.0.0.1"}, {"host": "a\x00.youtube.com"}):
                _, _, reply = await self.request(**kwargs)  # type: ignore[arg-type]
                self.assertEqual(reply[1], 2)
            upstream.assert_not_awaited()

    async def test_raw_ip_rejected(self):
        for atyp, address in ((1, bytes([8, 8, 8, 8])), (4, bytes(16))):
            reader, writer, _ = await self.client()
            writer.write(bytes([5, 1, 0, atyp]) + address + b"\x01\xbb")
            await writer.drain()
            self.assertEqual((await reader.readexactly(10))[1], 2)

    async def test_upstream_failure(self):
        with patch.object(relay, "connect_provider", side_effect=OSError):
            _, _, reply = await self.request()
            self.assertEqual(reply[1], 4)

    async def test_success_transfers_bytes(self):
        async def echo(reader, writer):
            writer.write(await reader.read(1024))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        async def upstream(host, port):
            self.assertEqual((host, port), ("youtube.com", 443))
            return await asyncio.open_connection("127.0.0.1", echo_server.sockets[0].getsockname()[1])
        try:
            with patch.object(relay, "connect_provider", side_effect=upstream):
                reader, writer, reply = await self.request()
                self.assertEqual(reply[1], 0)
                writer.write(b"protocol-test-payload")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(21), 2), b"protocol-test-payload")
        finally:
            echo_server.close()
            await echo_server.wait_closed()

    async def test_dns_rebinding_and_mixed_answers(self):
        loop = asyncio.get_running_loop()
        for ip in ("127.0.0.1", "192.168.1.1", "100.90.80.70", "169.254.169.254", "::1", "fc00::1"):
            answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
                       (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]
            with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=answers)), patch.object(loop, "sock_connect", new_callable=AsyncMock) as connect:
                with self.assertRaises(OSError):
                    await relay.connect_provider("youtube.com", 443)
                connect.assert_not_awaited()

    async def test_public_dns_pinned_no_second_lookup(self):
        loop = asyncio.get_running_loop()
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
        with patch.object(loop, "getaddrinfo", new=AsyncMock(return_value=answers)) as dns, patch.object(loop, "sock_connect", new_callable=AsyncMock) as connect, patch.object(relay.asyncio, "open_connection", new=AsyncMock(return_value=(None, None))) as opened, patch.object(relay.socket, "socket") as sock:
            await relay.connect_provider("youtube.com", 443)
            dns.assert_awaited_once()
            connect.assert_awaited_once_with(sock.return_value, ("8.8.8.8", 443))
            opened.assert_awaited_once_with(sock=sock.return_value)


class InstallerTests(unittest.TestCase):
    def test_launchd_plist_paths_are_separate_arguments(self):
        data = Path("/Users/Some One/home relay")
        obj = plistlib.loads(install.definition("darwin", "/Python With Space/python3", data).encode())
        self.assertEqual(obj["ProgramArguments"], ["/Python With Space/python3", str(data / "relay.py")])
        self.assertTrue(obj["KeepAlive"])
        self.assertNotIn("EnvironmentVariables", obj)

    def test_windows_task_is_user_logon_not_password_or_admin(self):
        value = install.definition("win32", "C:/Program Files/Python/pythonw.exe", Path("C:/Users/Some One/relay"), "HOME\\owner")
        obj = ET.fromstring(value)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        self.assertEqual(obj.findtext(".//t:LogonType", namespaces=ns), "InteractiveToken")
        self.assertEqual(obj.findtext(".//t:RunLevel", namespaces=ns), "LeastPrivilege")
        self.assertEqual(obj.findtext(".//t:ExecutionTimeLimit", namespaces=ns), "PT0S")
        self.assertEqual(obj.findtext(".//t:Arguments", namespaces=ns), '"C:/Users/Some One/relay/relay.py"')
        self.assertNotIn("Password", value)
        self.assertNotIn("socks5h://", value)

    def test_linux_unit_escapes_service_expansions(self):
        text = install.definition("linux", "/space python%/bin/python3", Path('/home/a$b/"relay"'))
        self.assertIn("python%%", text)
        self.assertIn("a$$b", text)
        self.assertIn('\\"relay\\"', text)
        self.assertIn("UMask=0077", text)

    def test_command_plans_no_ssh_or_elevation(self):
        for platform in ("linux", "darwin", "win32"):
            data, service = install.paths(Path("/home/owner"), platform)
            for action in ("install", "status", "uninstall"):
                commands = install.service_commands(platform, action, service, uid=1000)
                flattened = " ".join(" ".join(c) for c in commands)
                for forbidden in ("sudo", "ssh ", "/RP", "enable-linger"):
                    self.assertNotIn(forbidden, flattened)
            self.assertIn("relay", str(data))
        self.assertIn("gui/1000", install.service_commands("darwin", "install", Path("x"), uid=1000)[0])

    def test_linux_install_status_uninstall_behavior_without_services(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            home = Path(directory)
            with patch.object(install.Path, "home", return_value=home), patch.object(install.sys, "platform", "linux"), patch.object(install.subprocess, "run") as run, patch.object(relay, "tailscale_ip", return_value="100.90.80.70"), patch.object(relay, "token", return_value="test-only"):
                for action in ("install", "status", "uninstall"):
                    with patch.object(install.sys, "argv", ["install.py", action]), contextlib.redirect_stdout(io.StringIO()):
                        install.main()
                    data, service = install.paths(home, "linux")
                    if action == "install":
                        self.assertTrue(service.is_file())
                        self.assertTrue((data / "private_store.py").is_file())
                        self.assertNotIn("test-only", service.read_text())
                    if action == "uninstall":
                        self.assertFalse(service.exists())
                calls = [call.args[0] for call in run.call_args_list]
                self.assertIn(["systemctl", "--user", "enable", "--now", "wizard-home-relay"], calls)
                self.assertIn(["systemctl", "--user", "disable", "--now", "wizard-home-relay"], calls)

    def test_macos_and_windows_install_lifecycle_mocked_on_linux(self):
        for platform in ("darwin", "win32"):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
                home = Path(directory)
                (home / "pythonw.exe").touch()
                with patch.object(install.Path, "home", return_value=home), patch.object(install.sys, "platform", platform), patch.object(install.sys, "executable", str(home / "python.exe")), patch.object(install.subprocess, "run", return_value=Mock(stdout="HOME\\owner\n")) as run, patch.object(relay, "tailscale_ip", return_value="100.90.80.70"), patch.object(relay, "token", return_value="test-only"):
                    for action in ("install", "status", "uninstall"):
                        with patch.object(install.sys, "argv", ["install.py", action]), contextlib.redirect_stdout(io.StringIO()):
                            install.main()
                        data, service = install.paths(home, platform)
                        self.assertEqual(service.exists(), action != "uninstall")
                        self.assertTrue((data / "relay.py").is_file())
                    commands = [call.args[0] for call in run.call_args_list]
                    if platform == "win32":
                        self.assertIn(["schtasks", "/Run", "/TN", "wizard-home-relay"], commands)
                        self.assertIn(["schtasks", "/Delete", "/TN", "wizard-home-relay", "/F"], commands)
                    else:
                        self.assertTrue(any(command[:2] == ["launchctl", "bootstrap"] for command in commands))
                        self.assertTrue(any(command[:2] == ["launchctl", "bootout"] for command in commands))

    def test_failed_deregistration_does_not_claim_uninstall(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            home = Path(directory)
            _, service = install.paths(home, "linux")
            service.parent.mkdir(parents=True)
            service.write_text("unit")
            with patch.object(install.Path, "home", return_value=home), patch.object(install.sys, "platform", "linux"), patch.object(install.sys, "argv", ["install.py", "uninstall"]), patch.object(install.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "systemctl")):
                with self.assertRaises(subprocess.CalledProcessError):
                    install.main()
                self.assertTrue(service.exists())

    def test_windows_private_dacl_plan_fail_closed(self):
        import base64
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            path = Path(directory) / "private"
            with patch.object(private_store, "os", SimpleNamespace(name="nt")), patch.object(private_store.subprocess, "run") as run:
                private_store.private_dir(path)
                command = run.call_args.args[0]
                script = base64.b64decode(command[-1]).decode("utf-16le")
                self.assertIn("SetAccessRuleProtection($true,$false)", script)
                self.assertIn("DirectorySecurity", script)
                self.assertIn("::GetCurrent().User", script)
                self.assertNotIn("Everyone", script)
                self.assertTrue(run.call_args.kwargs["check"])
                run.side_effect = subprocess.CalledProcessError(1, "powershell")
                with self.assertRaises(subprocess.CalledProcessError):
                    private_store.write_private(path / "must-not-exist", "test-only")
                self.assertFalse((path / "must-not-exist").exists())

    def test_install_preflight_failure_creates_no_service(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            home = Path(directory)
            with patch.object(install.Path, "home", return_value=home), patch.object(install.sys, "argv", ["install.py", "install"]), patch.object(relay, "tailscale_ip", side_effect=ValueError("not connected")), patch.object(install.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    install.main()
                run.assert_not_called()
                self.assertFalse(install.paths(home, sys.platform)[1].exists())


if __name__ == "__main__":
    unittest.main()
