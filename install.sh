#!/bin/sh
# Install Wizard Home Relay on a computer at home (Linux with systemd, Python 3.10+, Tailscale).
# Runs as the current user; needs no sudo when lingering is already enabled.
set -eu
DIR="$HOME/.local/share/wizard-home-relay"
REF="${WIZARD_RELAY_REF:-main}"
mkdir -p "$DIR" "$HOME/.config/systemd/user"
if [ -f "$(dirname "$0")/relay.py" ]; then
  cp "$(dirname "$0")/relay.py" "$DIR/relay.py"
else
  curl -fsSL "https://raw.githubusercontent.com/humanitylabs-org/wizard-home-relay/$REF/relay.py" -o "$DIR/relay.py"
fi
command -v tailscale >/dev/null || { echo "Install and sign in to Tailscale on this computer first."; exit 1; }
cat > "$HOME/.config/systemd/user/wizard-home-relay.service" <<EOF
[Unit]
Description=Wizard Home Relay (home-network exit for Wizard online music, Tailscale only)
After=network-online.target tailscaled.service
[Service]
ExecStart=$(command -v python3) $DIR/relay.py
Restart=always
RestartSec=5
NoNewPrivileges=true
[Install]
WantedBy=default.target
EOF
loginctl enable-linger "$USER" 2>/dev/null || true
systemctl --user daemon-reload
systemctl --user enable --now wizard-home-relay.service
sleep 2
systemctl --user is-active wizard-home-relay.service
echo "Relay address (give this to your Wizard's Music app; keep it private):"
python3 "$DIR/relay.py" address
