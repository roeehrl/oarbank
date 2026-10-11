#!/bin/sh
# Oarbank agent package: runs as root after install or upgrade (docs/design/node-enrollment.md, "Linux package
# variables"). The package installs; joining is `oarbank-node join`'s. Whatever happens here the package transaction
# succeeds: a failure prints why and how to finish, and the script exits 0.
#
# Upgrade of a joined node (it holds agent.json): render the service's unit again with the new launcher's settings
# (`oarbank-launcher service refresh`: a 2.8 unit has no TimeoutStopSec) and restart it on the new launcher. The
# agent's own version is the coordinator's to change (self-update), so setup, which installs the package's agent as the
# current one, does not run.
#
# Otherwise (a first install, or an upgrade of a node that never joined): install the system service, which waits for a
# code (`sudo oarbank-node join` stages one later, or /etc/oarbank/policy.json names one). apt and dnf pass the caller's
# environment to this script (sudo keeps it with SETENV, which an ALL rule grants):
#   OARBANK_JOIN_CODE        a join code: staged for the service, which joins with it
#   OARBANK_JOIN_CODE_FILE   or a file holding one
#   OARBANK_COORDINATOR      join by URL instead (device code: the owner approves the node)
#   OARBANK_NAME             the node's name when the code has no label
#   OARBANK_CONTAINERS       container jobs: on Linux they need podman (the package recommends it), nothing else
# The code reaches setup on standard input, written by the shell's builtin printf, so it is never on the command line of
# a program (which any account can read in /proc), and nothing here prints it.
#
# POSIX sh (dash runs it on Debian and Ubuntu). No `set -e`: every step's failure is handled where it happens.
set -u
L=/usr/lib/oarbank/oarbank-launcher
UNIT=dev.codonic.oarbank.agent.service

# the desktop entry's handler for oarbank:// links (distributions' file triggers usually do this too)
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications 2>/dev/null || true
fi

if [ -f /var/lib/oarbank/agent/agent.json ]; then
    "$L" service refresh --system >/dev/null 2>&1 || systemctl try-restart "$UNIT" 2>/dev/null || true
    echo "Oarbank: upgraded; the service restarted on the new launcher"
    exit 0
fi

code="${OARBANK_JOIN_CODE:-}"
code_file="${OARBANK_JOIN_CODE_FILE:-}"
coordinator="${OARBANK_COORDINATOR:-}"
name="${OARBANK_NAME:-}"
unset OARBANK_JOIN_CODE                     # setup and what it starts never find the code in their environment

case "${OARBANK_CONTAINERS:-}" in
    1|[Tt]rue|TRUE|[Yy]es|YES|[Oo]n|ON)
        command -v podman >/dev/null 2>&1 ||
            echo "Oarbank: container jobs need podman: install it (apt install podman, or dnf install podman)" ;;
esac

[ -n "$code" ] && code_file=""             # the code itself wins over a file
if [ -n "$code_file" ] && [ ! -r "$code_file" ]; then
    echo "Oarbank: OARBANK_JOIN_CODE_FILE ($code_file) cannot be read; installing without a code"
    code_file=""
fi

# systemd not running (a container, a chroot, an image build): lay out the node and stage the code, start no service
nosvc=""
[ -d /run/systemd/system ] || nosvc="--no-service"

set --
[ -n "$coordinator" ] && set -- "$@" --coordinator "$coordinator"
[ -n "$name" ] && set -- "$@" --name "$name"
[ -n "$nosvc" ] && set -- "$@" "$nosvc"

staged=""
if [ -n "$code" ]; then
    printf '%s' "$code" | "$L" setup --scope system --join-code-stdin "$@" && staged=code
elif [ -n "$code_file" ]; then
    "$L" setup --scope system --join-code-stdin "$@" < "$code_file" && staged=code
elif [ -n "$coordinator" ]; then
    "$L" setup --scope system "$@" && staged=coordinator
else
    "$L" setup --scope system "$@" && staged=none
fi
if [ -z "$staged" ] && [ -n "$code$code_file$coordinator" ]; then
    # setup checks a code before it writes anything: a malformed or expired one leaves nothing installed. Install the
    # waiting service without it (nor the coordinator), so joining later is one command.
    echo "Oarbank: the node could not be set up with what the environment gave (above); installing it without"
    set --
    [ -n "$name" ] && set -- "$@" --name "$name"
    [ -n "$nosvc" ] && set -- "$@" "$nosvc"
    "$L" setup --scope system "$@" && staged=none
fi
code=""
if [ -z "$staged" ]; then
    echo "Oarbank: setting up the node failed (above). The programs are installed; finish with: sudo oarbank-node join"
    exit 0
fi
if [ -n "$nosvc" ]; then
    echo "Oarbank: systemd is not running here (a container or a chroot?), so no service was started."
    echo "On the running system, start it with: sudo oarbank-launcher setup --scope system"
    [ "$staged" = none ] && echo "and join this machine with: sudo oarbank-node join"
    exit 0
fi
case "$staged" in
    code) echo "Oarbank: installed; the service is joining with the code. Follow it with: oarbank-node status --follow" ;;
    coordinator) echo "Oarbank: installed; the service is asking $coordinator to join (the owner approves it). Follow it with: oarbank-node status --follow" ;;
    *) echo "Installed. Join this machine with: sudo oarbank-node join" ;;
esac
exit 0
