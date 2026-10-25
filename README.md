# Wizard Home Relay

A provider-limited, authenticated SOCKS5 home-network exit for a Wizard on a cloud server. Some providers reject data-center addresses; a home relay **may** help, but is not a promise of playback, no ads, unlimited usage, or bypassing subscriptions, geographic restrictions, rate limits or provider terms. It does not sign in to YouTube or store YouTube cookies. Account connection is a separate connector flow.

## Install locally, not over desktop SSH

On the **home computer**, install Python 3.10+ and Tailscale, sign that computer and the Wizard server into an authorized tailnet, and review a trusted release/checkout of this repository. No remote installer, admin credentials, port forwarding or SSH to a personal laptop is needed. Do not pipe an unreviewed moving `main` URL into a shell.

Run from that checkout:

| OS | Install | Status | Uninstall |
| --- | --- | --- | --- |
| Linux/systemd | `python3 install.py install` | `python3 install.py status` | `python3 install.py uninstall` |
| macOS | `python3 install.py install` | `python3 install.py status` | `python3 install.py uninstall` |
| Windows | `py -3 install.py install` | `py -3 install.py status` | `py -3 install.py uninstall` |

`sh install.sh install` is a Linux/macOS wrapper; Windows also has `install.cmd install`.

- Linux: current-user systemd unit, restart on failure. Login is required unless an administrator separately enables lingering. The installer does **not** silently enable lingering.
- macOS: current-user launchd LaunchAgent (`org.wizard.home-relay`), loaded in the logged-in GUI session. Python must be a persistent installation (not an ephemeral virtualenv); Tailscale's app-bundled CLI is discovered if not on PATH.
- Windows: current-user Task Scheduler task (`wizard-home-relay`), starts at that user's logon using `pythonw.exe`, runs immediately on installation, retries failures every minute. InteractiveToken, LeastPrivilege; no stored logon password and no elevated system service. Requires standard Python with pythonw and Windows PowerShell for filesystem ACLs. Tailscale under Program Files is discovered.

All three are **user-session startup**, not an unattended pre-login system service. Sleep, logout, no home internet or disconnected Tailscale interrupt playback. Configure sleep with the owner's consent. Keep the chosen Python installation available. A status command reports OS registration/process state, **not** end-to-end media readiness. On Windows check Last Run Result (zero or running `0x41301`) and perform a connector probe; a registered task can still fail to bind. On macOS inspect launchctl's last exit status and the private `relay.log`. Linux uses the user journal. No destination URLs or credentials are logged by relay code.

For upgrade, uninstall startup registration, review the new checkout, then install. This retains the token. The installer refuses to replace an existing service definition implicitly. Uninstall leaves local code under `~/.local/share/wizard-home-relay` and secrets under `~/.config/wizard-home-relay` (on Windows `~` is the user profile). After confirming the relay is stopped, delete those two directories to erase local material. Delete any exported pairing files and revoke the connector secret too. To rotate, stop/uninstall first, remove the local `token` plus old pairing exports, install again and pair again. Existing connections must be stopped to revoke them. Never remove another user's directories.

If startup registration fails, the installer attempts to remove any partially created job before removing its definition; the original install still fails, and local code and the pairing token are retained. Retry install after successful rollback. If rollback cannot be confirmed, or an older failed install left a definition behind, run `install.py uninstall` with the same Python command as above before retrying. Uninstall accepts a job proven absent, but permission errors and other unconfirmed removal failures remain errors and retain the definition for recovery.

## Pair safely

Follow [PAIRING.md](PAIRING.md). Installation **never prints a credential URL**. The old `relay.py address` command now refuses. This is a deliberate safety change: do not use the earlier console-copy instructions. Existing private 0600 tokens are retained; fix insecure legacy token permissions locally before reuse. Tokens are plaintext locally protected by permissions/ACL, not encrypted against the logged-in user or administrators.

## Security boundary

- Binds only an IPv4 address actually reported by the local connected Tailscale CLI, within `100.64.0.0/10`. `WIZARD_RELAY_HOST` is not a bypass: any override must match a reported address. Wildcard, LAN, loopback, arbitrary CGNAT and public overrides fail closed. Trust requires an uncompromised local Tailscale CLI/OS.
- SOCKS5 username/password is mandatory; anonymous negotiation, UDP, BIND, raw IP destinations, nonzero reserved fields and ports other than 80/443 are refused.
- Only the explicit YouTube/Google domain suffixes in `relay.py:ALLOW` are allowed. These include broad Google infrastructure domains required by the original relay; this is not a per-account or per-URL policy, and HTTP on port 80 is not end-to-end encrypted. Restrict tailnet access to the Wizard server's identity and TCP 18765 using Tailscale grants/ACLs; do not grant the whole tailnet access unnecessarily.
- Provider DNS is resolved once, all results must be public, and connections use those numeric results (rejects DNS-to-LAN/loopback/Tailscale rebinding). Host syntax and exact suffix boundaries are validated. No local network scanning/general open proxy.
- 64 simultaneous clients, 15-second handshake reads and upstream connection timeout. This is a small trusted-tailnet relay, not an Internet-facing hardened proxy; long-lived authenticated streams can consume capacity.
- Secrets are stored with Unix directory 0700/file 0600, or a Windows protected current-user-only DACL established before writing. Symlink secret files/directories and insecure Unix token files are refused. Do not place secret storage in shared/cloud-synced directories. Environment overrides for home/port are for manual use and are not persisted by the installer.

## Tests and platform acceptance

`python3 -m unittest discover -s tests -v` exercises protocol exchanges with loopback test sockets, mocked upstream/DNS, secret file behavior, generated launchd/task XML and service command plans. No real home relay or user service is changed by tests. Only Linux test execution is claimed. macOS launchctl and Windows Task Scheduler/ACL execution still require owner-driven native smoke tests: install → status → secure pair → connector probe/play → logout/login → status/probe → uninstall → confirm no listener. No remote install on a personal machine is claimed.

MIT licensed.
