"""Private local storage; Windows ACLs must succeed before writing secrets."""
import os
from pathlib import Path
import stat
import subprocess


def private_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Private directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        # Replace the DACL, not merely add a grant (which could leave an old
        # Everyone/Users explicit ACE). No credential is passed to PowerShell.
        import base64
        quoted = str(path.resolve()).replace("'", "''")
        script = ("$ErrorActionPreference='Stop'; "
                  "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User; "
                  "$acl=New-Object System.Security.AccessControl.DirectorySecurity; "
                  "$acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false); "
                  "$rule=[System.Security.AccessControl.FileSystemAccessRule]::new"
                  "($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); "
                  "$acl.AddAccessRule($rule); "
                  f"Set-Acl -LiteralPath '{quoted}' -AclObject $acl")
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                        base64.b64encode(script.encode("utf-16le")).decode()],
                       check=True, capture_output=True)
    else:
        if path.stat().st_uid != os.getuid():
            raise ValueError("Private directory is not owned by current user")
        path.chmod(0o700)
    return path


def write_private(path, content):
    path = Path(path)
    private_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def read_private(path):
    path = Path(path)
    private_dir(path.parent)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Secret must be a regular file, not a link")
    if os.name != "nt":
        info = path.stat()
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Secret file must be owned by current user with mode 0600")
    else:
        # Reset file inheritance to the already restricted parent directory.
        subprocess.run(["icacls", str(path), "/reset"], check=True, capture_output=True)
    return path.read_text(encoding="utf-8")
