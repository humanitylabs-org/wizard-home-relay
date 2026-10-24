# Wizard Home Relay

YouTube (and some other providers) block data-center addresses, so a Wizard on a cloud server can search for songs but can't play them. Wizard Home Relay runs on any always-on computer at home and gives your Wizard a home-network exit **only for those providers**, over Tailscale.

```sh
curl -fsSL https://raw.githubusercontent.com/humanitylabs-org/wizard-home-relay/main/install.sh | sh
```

It prints an address like `socks5h://wizard:…@100.x.x.x:18765`. Paste it into Music → Online sources → **Add a home connection**. Keep it private; it contains the relay's token.

## Safety

- Listens only on the computer's Tailscale address, never the LAN or internet.
- Requires the token (SOCKS5 username/password).
- Connects only to YouTube/Google media domains on ports 80/443, by name. Raw IPs and every other site are refused, so it is not a general proxy.
- Linux with systemd, Python 3.10+, Tailscale. Runs as your user. Stop with `systemctl --user disable --now wizard-home-relay`.

`python3 relay.py address` prints the address again.

MIT licensed.
