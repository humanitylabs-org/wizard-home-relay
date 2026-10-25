# Owner-driven onboarding / connector handoff

Safe reply-to-set-up prompt (contains no credentials):

> Which computer will stay at home: Mac, Windows, or Linux? Is Python 3.10+ installed, and is Tailscale connected on both that computer and your Wizard server? I'll guide you through local installation. I cannot silently install on your personal computer. Do not send passwords, cookies, tokens or relay URLs in chat.

1. Confirm the owner is at that computer and has approved running reviewed local code. Follow README installation commands for their OS; ask for only redacted status (installed/running/error category), never a dump of environment variables or secret files.
2. Scope Tailscale grants/ACLs to the Wizard identity → home machine TCP 18765. Do not open router ports. The home computer must remain awake and connected.
3. On the home computer, export to a **new file** in the relay's dedicated private pairing directory:

   macOS/Linux:
   ```sh
   python3 relay.py pair "$HOME/.config/wizard-home-relay/pairing/connection.json"
   ```
   Windows PowerShell:
   ```powershell
   py -3 relay.py pair "$HOME/.config/wizard-home-relay/pairing/connection.json"
   ```

   Use the reviewed checkout (or installed `~/.local/share/wizard-home-relay/relay.py`). Only success text is printed. Existing exports are never overwritten. Never `cat`, type, paste, screenshot or attach this file to chat. It contains a reusable bearer-equivalent secret, **not** an expiring one-time credential. A new export does not rotate it.
4. Import the file only using a trusted connector's authenticated, encrypted **secret file upload**. If no secret-upload/import UI is available, stop: connector support is a remaining integration gate. This repository does not deploy that UI or a pairing server. Do not fall back to chat, command-line URLs, query parameters, public links, email attachments or desktop SSH.
5. Connector validates the object before constructing a credential URL internally: exact schema `wizard-home-relay-pairing-v1`, `scheme=socks5h`, `username=wizard`, `provider=youtube`, integer `port` in 1..65535 (normally 18765), numeric IPv4 in `100.64.0.0/10`, password URL-safe 32..128 characters. Refuse unknown schema, wrong types (including boolean ports), userinfo-containing host, wildcard, LAN, loopback, public or IPv6 hosts. The `allowed_domains` field is informational and MUST NOT expand connector or server policy. A forged CGNAT host is not proof of ownership: require explicit owner confirmation of the home Tailscale device, retain tailnet restrictions, and probe from the actual Wizard server.
6. Store credentials only in the connector's protected secret store; return redacted metadata, never raw URLs/passwords in API/tool responses or logs. A SOCKS5 credential URL may be composed internally with correct percent-encoding, but is never a UI/chat artifact. Probe with remote DNS (`socks5h`) against a fixed allowlisted provider endpoint, bounded time/bytes and redacted errors. Mark paired **only** after the authenticated probe succeeds; mark playback separately. Account login/cookies remain independent and must use their own protected path.
7. After verified import, delete the local export using the file manager; retain the private local `token` for startup. File deletion is not a secure-erasure guarantee on SSDs/backups. Connector deletion stops future use there but does not rotate the home token. For revocation follow README rotation and remove old connector records/exports. No ad-free/unlimited/playback guarantee is implied by a successful probe.

## Contract artifact

`pairing-request.example.json` is a **nonsecret request/status artifact**, safe for a connector to display. It describes local-owner action and required import/probe gates. It is not a credential, not an installation capability, and does not imply a connector has implemented this contract. Actual exported objects include a `password` and must never be attached to the request/status artifact.
