#!/usr/bin/env bash
# Install server-report-card on this server (RHEL/Rocky/Alma 8+, Ubuntu 20.04+, Debian 11+).
#   sudo ./install.sh              install or upgrade (your config is kept)
#   sudo ./install.sh --uninstall  remove the program and timers (keeps config and data)
set -euo pipefail

PREFIX=/opt/server-report-card
CONF_DIR=/etc/server-report-card
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNITS="collect alerts report restore-test"

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
  for u in $UNITS; do systemctl disable --now "server-report-card-$u.timer" 2>/dev/null || true; done
  rm -f /etc/systemd/system/server-report-card-*.{service,timer} /usr/local/bin/server-report-card /usr/sbin/server-report-card
  rm -rf "$PREFIX"
  systemctl daemon-reload
  echo "Removed. Config ($CONF_DIR) and data (/var/lib/server-report-card) were kept."
  exit 0
fi

PY=$(command -v python3 || true)
[ -n "$PY" ] || { echo "python3 is required (dnf install python3 / apt install python3)" >&2; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' || { echo "Python 3.6 or newer is required" >&2; exit 1; }

install -d -m 755 "$PREFIX"
rm -rf "$PREFIX/reportcard"
cp -r "$SRC/reportcard" "$PREFIX/"
find "$PREFIX" -name '__pycache__' -prune -exec rm -rf {} +
cat > /usr/local/bin/server-report-card <<EOF
#!/bin/sh
# -I: never load code from the current folder or user site-packages (this runs as root)
exec $PY -I -c 'import sys; sys.path.insert(0, "$PREFIX"); from reportcard.cli import main; sys.exit(main())' "\$@"
EOF
chmod 755 /usr/local/bin/server-report-card
# sudo on RHEL does not search /usr/local/bin (secure_path), so also link it where sudo looks
ln -sf /usr/local/bin/server-report-card /usr/sbin/server-report-card

install -d -m 700 "$CONF_DIR" /var/lib/server-report-card
if [ ! -f "$CONF_DIR/config.ini" ]; then
  install -m 600 "$SRC/config.example.ini" "$CONF_DIR/config.ini"
  sed -i "s/^server_name = .*/server_name = $(hostname)/; s/^client_name = .*/client_name =/; s|^urls = .*|urls =|; s/^domains = example.com/domains =/; s/^services = nginx/services =/" "$CONF_DIR/config.ini"
  NEW_CONFIG=1
fi

for u in $UNITS; do
  install -m 644 "$SRC/deploy/systemd/server-report-card-$u.service" "$SRC/deploy/systemd/server-report-card-$u.timer" /etc/systemd/system/
done
systemctl daemon-reload
for u in $UNITS; do systemctl enable --now "server-report-card-$u.timer" >/dev/null; done

echo "Installed. First check (this saves today's results):"
echo
/usr/local/bin/server-report-card collect || true
echo
if [ -n "${NEW_CONFIG:-}" ]; then
  echo "Next: edit $CONF_DIR/config.ini (website, email domain, where to send the report),"
else
  echo "Your config was kept: $CONF_DIR/config.ini"
fi
echo "then run:  server-report-card test-notify   and   server-report-card report --send"
echo "Schedule:  daily checks 06:15, hourly alerts, weekly report Monday 08:00, restore test on the 1st."
