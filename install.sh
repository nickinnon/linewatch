#!/usr/bin/env bash
# Install linewatch as a systemd user service (Linux). It runs whenever you're logged in.
# Any arguments are passed through to linewatch, e.g.:
#   ./install.sh --hop 203.0.113.1 --out ~/linewatch-logs
# Uninstall:
#   systemctl --user disable --now linewatch.service
#   rm ~/.local/bin/linewatch.py ~/.config/systemd/user/linewatch.service
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd not found; run linewatch.py by hand instead" >&2; exit 1; }

if [[ "$(cut -f2 /proc/sys/net/ipv4/ping_group_range 2>/dev/null)" == "0" ]]; then
  echo "Unprivileged ping sockets are disabled on this system. Enable them first:" >&2
  echo "  sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'" >&2
  exit 1
fi

install -Dm755 "$here/linewatch.py" "$HOME/.local/bin/linewatch.py"

# systemd quoting: wrap each argument in double quotes, escape \ and ", double any %.
args=""
for a in "$@"; do
  a="${a//\\/\\\\}"; a="${a//\"/\\\"}"; a="${a//%/%%}"
  args+=" \"$a\""
done

unit="$HOME/.config/systemd/user/linewatch.service"
mkdir -p "$(dirname "$unit")"
cat > "$unit" <<EOF
[Unit]
Description=linewatch connection monitor (records outages only)

[Service]
ExecStart=/usr/bin/env python3 -I %h/.local/bin/linewatch.py run$args
Restart=always
RestartSec=15

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now linewatch.service
sleep 2
systemctl --user --no-pager --lines=5 status linewatch.service || true
echo
echo "Installed. Follow it live with:  journalctl --user -fu linewatch"
