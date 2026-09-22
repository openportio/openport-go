#!/bin/sh
# dpkg runs this as root with $1="configure" on install and upgrade.
set -e

# Users listed in users.conf get their sessions restarted by
# "openport restart-sessions" running as root (the openport.service boot
# unit). Same behaviour as the pre-2.2.4 dpkg-built package.
mkdir -p /etc/openport
USERSFILE=/etc/openport/users.conf
touch "$USERSFILE"
if [ -n "${SUDO_USER:-}" ]; then
    grep -sxqF "$SUDO_USER" "$USERSFILE" || echo "$SUDO_USER" >> "$USERSFILE"
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable openport.service || true
    # Restarting the unit kills the sessions running in its cgroup and
    # re-spawns them from the database, so live tunnels move onto the binary
    # that was just installed. --no-block: apt must not wait on the tunnels.
    # Sessions started from a user's shell (not at boot) are outside the
    # cgroup and keep running the old binary until their next restart.
    systemctl restart --no-block openport.service || true
else
    # No systemd (containers, WSL1, sysv systems): old behaviour.
    openport restart-sessions || true
fi
