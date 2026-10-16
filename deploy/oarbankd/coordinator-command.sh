#!/bin/sh
# A coordinator command on the PATH, installed by the native packages as `oarbank` and `oarbank-setup` (the macOS pkg
# links /usr/local/bin/<name> to its copy in Oarbank Coordinator.app/Contents/Resources/cli, the deb and rpm link
# /usr/bin/<name> to /usr/lib/oarbank/cli/<name>; Windows has package\cli\oarbank.cmd for the same). It runs that command
# of the build the coordinator's system services run, PROGRAMS/current: install-oarbankd points it at the package's
# build or an archive's, a coordinator self-update at the build it unpacked, and a rollback back
# (docs/design/coordinator-system-service.md, "Self-update"). Before setup, or once the services are removed, there is
# no `current`, and it runs the package's own. So the CLI on the PATH is the running coordinator's version, also after
# a self-update the package did not see.
script="$0"
while [ -L "$script" ]; do
    dir="$(cd "$(dirname "$script")" && pwd -P)"
    script="$(readlink "$script")"
    case "$script" in /*) ;; *) script="$dir/$script" ;; esac
done
name="$(basename "$script")"
case "$(uname -s)" in
    Darwin) current="/Library/Oarbank/Coordinator/current"
            package="/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator" ;;
    *)      current="/opt/oarbank/coordinator-builds/current"
            package="/opt/oarbank/coordinator" ;;
esac
if [ -f "$current/oarbank-coordinator.json" ] && [ -x "$current/bin/$name" ]; then
    exec "$current/bin/$name" "$@"
fi
exec "$package/bin/$name" "$@"
