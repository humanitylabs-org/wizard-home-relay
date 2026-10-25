#!/usr/bin/env python3
"""Local, current-user installer. No admin, SSH, downloads, or secret output."""
import argparse
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

import xml.etree.ElementTree as ET

from private_store import private_dir

NAME = "wizard-home-relay"
LABEL = "org.wizard.home-relay"
SOURCE = Path(__file__).resolve().parent


def paths(home, platform):
    data = home / ".local/share" / NAME
    if platform == "darwin":
        service = home / "Library/LaunchAgents" / (LABEL + ".plist")
    elif platform == "win32":
        service = data / "task.xml"
    elif platform == "linux":
        service = home / ".config/systemd/user" / (NAME + ".service")
    else:
        raise ValueError("Supported platforms: Linux, macOS, Windows")
    return data, service


def definition(platform, python, data, username=""):
    script = str(data / "relay.py")
    if platform == "darwin":
        return plistlib.dumps({"Label": LABEL, "ProgramArguments": [python, script],
                               "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 10,
                               "StandardOutPath": str(data / "relay.log"),
                               "StandardErrorPath": str(data / "relay.log")}).decode()
    if platform == "win32":
        root = ET.Element("Task", version="1.2", xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task")
        def item(parent, tag, text=None, **attrs):
            node = ET.SubElement(parent, tag, attrs)
            node.text = text
            return node
        trigger = item(item(root, "Triggers"), "LogonTrigger")
        item(trigger, "Enabled", "true")
        item(trigger, "UserId", username)
        principal = item(item(root, "Principals"), "Principal", id="Owner")
        item(principal, "UserId", username)
        item(principal, "LogonType", "InteractiveToken")
        item(principal, "RunLevel", "LeastPrivilege")
        settings = item(root, "Settings")
        for key, value in {"MultipleInstancesPolicy": "IgnoreNew", "DisallowStartIfOnBatteries": "false",
                           "StopIfGoingOnBatteries": "false", "ExecutionTimeLimit": "PT0S"}.items():
            item(settings, key, value)
        restart = item(settings, "RestartOnFailure")
        item(restart, "Interval", "PT1M")
        item(restart, "Count", "999")
        action = item(item(root, "Actions", Context="Owner"), "Exec")
        item(action, "Command", python)
        item(action, "Arguments", subprocess.list2cmdline([script]))
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
    def quote(value):
        # systemd specifiers and environment expansions are not shell quoting.
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'
    return ("[Unit]\nDescription=Wizard Home Relay\nAfter=network-online.target\n"
            "[Service]\nExecStart=" + quote(python) + " " + quote(script) + "\n"
            "Restart=always\nRestartSec=10\nNoNewPrivileges=true\nUMask=0077\n"
            "[Install]\nWantedBy=default.target\n")


def service_commands(platform, action, service, uid=None):
    if platform == "linux":
        prefix = ["systemctl", "--user"]
        return {"install": [prefix + ["daemon-reload"], prefix + ["enable", "--now", NAME]],
                "status": [prefix + ["status", NAME, "--no-pager"]],
                "uninstall": [prefix + ["disable", "--now", NAME]]}[action]
    if platform == "darwin":
        domain = f"gui/{os.getuid() if uid is None else uid}"
        return {"install": [["launchctl", "bootstrap", domain, str(service)]],
                "status": [["launchctl", "print", domain + "/" + LABEL]],
                "uninstall": [["launchctl", "bootout", domain + "/" + LABEL]]}[action]
    return {"install": [["schtasks", "/Create", "/TN", NAME, "/XML", str(service), "/F"],
                        ["schtasks", "/Run", "/TN", NAME]],
            "status": [["schtasks", "/Query", "/TN", NAME, "/V", "/FO", "LIST"]],
            "uninstall": [["schtasks", "/End", "/TN", NAME],
                          ["schtasks", "/Delete", "/TN", NAME, "/F"]]}[action]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["install", "status", "uninstall"])
    args = parser.parse_args()
    platform = sys.platform
    data, service = paths(Path.home(), platform)
    if args.action == "install":
        if sys.version_info < (3, 10):
            parser.error("Python 3.10+ required")
        if service.exists():
            parser.error("Existing installation: uninstall first (pairing token is retained)")
        import relay
        relay.tailscale_ip()  # Fail before creating services if not connected.
        relay.token()
        private_dir(data)
        for name in ("relay.py", "private_store.py"):
            if (data / name).is_symlink():
                raise ValueError("Installed code must not be a symlink")
            shutil.copyfile(SOURCE / name, data / name)
        service.parent.mkdir(parents=True, exist_ok=True)
        python = sys.executable
        if platform == "win32":
            pythonw = Path(python).with_name("pythonw.exe")
            if not pythonw.is_file():
                parser.error("Install standard Python with pythonw.exe for background startup")
            python = str(pythonw)
        username = subprocess.run(["whoami"], check=True, capture_output=True, text=True).stdout.strip() if platform == "win32" else ""
        service.write_text(definition(platform, python, data, username), encoding="utf-8")
        if platform != "win32":
            service.chmod(0o600)
    for command in service_commands(platform, args.action, service):
        # An already stopped Windows task may reject /End. Removal itself must
        # succeed before we delete the definition or report deregistration.
        subprocess.run(command, check=not (platform == "win32" and "/End" in command))
    if args.action == "uninstall":
        service.unlink(missing_ok=True)
        if platform == "linux":
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        print("Startup registration removed. Local code and private token retained; see README for erasure.")
    elif args.action == "install":
        print("Startup registered. Run install.py status and follow PAIRING.md on this computer.")


if __name__ == "__main__":
    main()
