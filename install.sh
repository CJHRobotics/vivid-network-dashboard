#!/usr/bin/env bash
# Install the network monitor on a Vivid Unit (Debian 11/12).
# Run from inside the netmon/ project directory:  bash install.sh
set -euo pipefail

APP_DIR="/opt/netmon"
USER_NAME="${SUDO_USER:-$USER}"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"

echo ">> Installing system packages (python3-tk, arp-scan) ..."
sudo apt-get update
sudo apt-get install -y python3-tk arp-scan iputils-ping

echo ">> Copying app to ${APP_DIR} ..."
sudo mkdir -p "$APP_DIR"
sudo cp -r netmon run.py "$APP_DIR"/
sudo chown -R "$USER_NAME":"$USER_NAME" "$APP_DIR"

echo ">> Granting arp-scan raw-socket capability (so the GUI runs as a normal user) ..."
# Lets arp-scan open raw sockets without sudo. The pure-python fallback works
# without this, but arp-scan gives you MAC vendor names in one pass.
ARP_BIN="$(command -v arp-scan)"
sudo setcap cap_net_raw+ep "$ARP_BIN" || echo "   (setcap failed - the ping-sweep fallback will still work)"

echo ">> Installing desktop autostart entry for user ${USER_NAME} ..."
AUTOSTART_DIR="${USER_HOME}/.config/autostart"
mkdir -p "$AUTOSTART_DIR"
cat > "${AUTOSTART_DIR}/netmon.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Network Monitor
Exec=python3 ${APP_DIR}/run.py
X-GNOME-Autostart-enabled=true
Terminal=false
EOF

echo ""
echo "Done."
echo "  Launch now:      python3 ${APP_DIR}/run.py"
echo "  It will also start automatically on next boot/login."
echo "  Exit fullscreen: press Escape."
