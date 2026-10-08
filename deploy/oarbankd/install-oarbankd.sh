#!/bin/bash
# Install the Oarbank coordinator for the current user: oarbankd and the console, as LaunchAgents on macOS or systemd
# user units on Linux (run `loginctl enable-linger` once so they start at boot without a login). `--help` lists the
# options. Moves install standbys through the agent's install_coordinator, not this.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
usage() {
    cat <<USAGE
usage: $(basename "$0") (--build <archive> | --installed <directory> | --checkout) --agent-bind <address> [--dry-run]

Install the Oarbank coordinator (oarbankd and the console) for the current user: LaunchAgents on macOS, systemd
user units on Linux. Running it again updates an installation in place.

  --build <archive>        a coordinator build (oarbank-coordinator-<v>-<os>-<arch>.tar.gz from
                           scripts/build-coordinator.sh), unpacked beside earlier ones with \`current\` pointing at it
  --installed <directory>  use the build already installed by a native package (no archive needed)
  --checkout               run this repository's virtualenv instead (developer mode)
  --agent-bind <address>   the address agents reach: a LAN or tailnet address (127.0.0.1 only for a one-machine trial)
  --dry-run                print the commands and service files instead of running and writing them
  -h, --help               show this help

Environment: OARBANK_RELEASE_SIGNING=0 installs developer mode (release signing off; it is on by default).
USAGE
}
fail() { echo "install-oarbankd.sh: $*" >&2; echo "try --help" >&2; exit 2; }
BUILD="" INSTALLED="" CHECKOUT=0 BIND="" DRY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --build|--installed|--agent-bind) [[ $# -ge 2 && "$2" != -* ]] || fail "$1 needs a value"
            case "$1" in --build) BUILD="$2" ;; --installed) INSTALLED="$2" ;; *) BIND="$2" ;; esac; shift 2 ;;
        --checkout) CHECKOUT=1; shift ;;
        --dry-run) DRY=1; shift ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[[ -n "$BIND" ]] || fail "give --agent-bind <address agents reach>"
modes=$CHECKOUT
[[ -z "$BUILD" ]] || modes=$((modes + 1))
[[ -z "$INSTALLED" ]] || modes=$((modes + 1))
[[ $modes == 1 ]] || fail "give exactly one of --build, --installed or --checkout"
[[ "$BIND" != -* && "$BIND" != *[[:space:]]* ]] || fail "invalid agent address"
run() { if [[ $DRY == 1 ]]; then echo "$*"; else "$@"; fi; }

die() { echo "install-oarbankd.sh: $*" >&2; exit 1; }
OS="$(uname -s)"
case "$OS" in
    Darwin) DATA="$HOME/Library/Application Support/Oarbank"
            LA="$HOME/Library/LaunchAgents"
            SYS_PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin ;;
    Linux)  DATA="${XDG_DATA_HOME:-$HOME/.local/share}/oarbank"
            LA="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
            SYS_PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin ;;
    *) die "the coordinator installs on macOS and Linux (install-oarbankd.ps1 on Windows), not $OS" ;;
esac
HOME_DIR="$DATA/coordinator"
SIGNING="${OARBANK_RELEASE_SIGNING:-1}"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi; }

if [[ -n "$BUILD" ]]; then
    manifest="$(tar -xzOf "$BUILD" oarbank-coordinator.json)" || die "$BUILD is not a coordinator build"
    field() {   # a field of the build's one-line manifest (scripts/build-coordinator.sh writes it)
        local re="\"$1\": *\"?([^\",}]+)"
        [[ "$manifest" =~ $re ]] && printf '%s' "${BASH_REMATCH[1]}"
    }
    [[ "$(field format)" == 1 ]] || die "$BUILD: unknown manifest format"
    version="$(field version)" && platform="$(field platform)" || die "$BUILD: the manifest has no version or platform"
    case "$OS-$(uname -m)" in
        Darwin-arm64) want=darwin-arm64 ;; Darwin-x86_64) want=darwin-amd64 ;;
        Linux-aarch64) want=linux-arm64 ;; Linux-x86_64) want=linux-amd64 ;; *) want=unknown ;;
    esac
    [[ "$platform" == "$want" ]] || die "the build is for $platform, this machine is $want"
    sha="$(sha256 "$BUILD" | cut -c1-12)"
    APP="$DATA/coordinator-app/$version-$sha"
    run mkdir -p "$APP"
    run tar -xzf "$BUILD" -C "$APP"
    run ln -sfn "$version-$sha" "$DATA/coordinator-app/current"
    OARBANKD=("$DATA/coordinator-app/current/bin/oarbankd")
    CONSOLE=("$DATA/coordinator-app/current/bin/oarbank-console")
    CLI="$DATA/coordinator-app/current/bin/oarbank"
    # the services' PATH: oarbankd installs module dependencies with the build's own uv
    SVC_PATH="$DATA/coordinator-app/current/bin:$SYS_PATH"
elif [[ -n "$INSTALLED" ]]; then
    [[ -f "$INSTALLED/oarbank-coordinator.json" && -x "$INSTALLED/bin/oarbankd" && -x "$INSTALLED/bin/oarbank-console" ]] \
        || die "$INSTALLED is not an installed coordinator build"
    APP="$(cd "$INSTALLED" && pwd -P)"
    manifest="$(cat "$APP/oarbank-coordinator.json")"
    [[ "$manifest" =~ \"format\":\ *1[,\ }] ]] || die "unknown installed build format"
    case "$OS-$(uname -m)" in Darwin-arm64) want=darwin-arm64 ;; Darwin-x86_64) want=darwin-amd64 ;;
        Linux-aarch64) want=linux-arm64 ;; Linux-x86_64) want=linux-amd64 ;; *) want=unknown ;; esac
    [[ "$manifest" =~ \"platform\":\ *\"$want\" ]] || die "the installed build is not for $want"
    OARBANKD=("$APP/bin/oarbankd")
    CONSOLE=("$APP/bin/oarbank-console")
    CLI="$APP/bin/oarbank"
    SVC_PATH="$APP/bin:$SYS_PATH"
else
    # uv syncs the virtualenv and oarbankd installs module dependencies with it: on PATH, else where its installer
    # ($XDG_BIN_HOME or ~/.local/bin) or Homebrew (macOS, Linux) puts it
    UV="$(command -v uv || true)"
    for c in "${XDG_BIN_HOME:-$HOME/.local/bin}/uv" /opt/homebrew/bin/uv /usr/local/bin/uv /home/linuxbrew/.linuxbrew/bin/uv; do
        [[ -z "$UV" && -x "$c" ]] && UV="$c"
    done
    [[ -n "$UV" ]] || die "uv is not installed (https://docs.astral.sh/uv/getting-started/installation/)"
    SVC_PATH="$SYS_PATH"                                # the services' PATH: oarbankd finds the same uv
    [[ ":$SYS_PATH:" == *":$(dirname "$UV"):"* ]] || SVC_PATH="$(dirname "$UV"):$SYS_PATH"
    (cd "$REPO" && run git submodule update --init -q && run "$UV" sync -q --inexact)
    OARBANKD=("$REPO/.venv/bin/oarbankd")
    CONSOLE=("$REPO/.venv/bin/python" "-m" "oarbank.console")
    CLI="$REPO/.venv/bin/oarbank"
fi

xml() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; printf '%s' "$s"; }
plist() {   # label keepalive-xml log args...
    local label="$1" keep="$2" log="$3"; shift 3
    local args=""
    for a in "$@"; do args+="<string>$(xml "$a")</string>"; done
    cat <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array>$args</array>
  <key>EnvironmentVariables</key><dict>
    <key>OARBANKD_HOME</key><string>$(xml "$HOME_DIR")</string>
    <key>PATH</key><string>$(xml "$SVC_PATH")</string>
    <key>OARBANK_RELEASE_SIGNING</key><string>$SIGNING</string>
  </dict>
  <key>KeepAlive</key>$keep
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Standard</string>
  <key>StandardOutPath</key><string>$(xml "$HOME_DIR/logs/$log")</string>
  <key>StandardErrorPath</key><string>$(xml "$HOME_DIR/logs/$log")</string>
</dict></plist>
PL
}

unit() {   # name exec-args... : a systemd user unit, restarted after a failed exit (oarbankd) or always (console)
    local name="$1" restart="$2"; shift 2
    local q=""
    for a in "$@"; do q+=" \"${a//\"/\\\"}\""; done
    cat <<UNIT
[Unit]
Description=Oarbank $name
After=network-online.target

[Service]
ExecStart=${q# }
Environment="OARBANKD_HOME=$HOME_DIR" "OARBANK_RELEASE_SIGNING=$SIGNING" "PATH=$SVC_PATH"
Restart=$restart
RestartSec=10
StandardOutput=append:$HOME_DIR/logs/$name.log
StandardError=append:$HOME_DIR/logs/$name.log

[Install]
WantedBy=default.target
UNIT
}

run mkdir -p "$HOME_DIR/logs" "$LA"
if [[ "$OS" != Darwin ]]; then
    if [[ "$INSTALLED" == /opt/oarbank/coordinator && $DRY != 1 ]]; then
        # Let native package removal find customized XDG unit directories even
        # after this user's manager has stopped. No service starts before this.
        "$APP/python/bin/python3.12" -I -B -c 'import json, os, pwd, sys; from pathlib import Path; from oarbank.platform import files; p=Path(pwd.getpwuid(os.getuid()).pw_dir)/".local/share/oarbank/coordinator-package.json"; files.private_dir(p.parent); files.write_private(p, json.dumps({"format":1,"root":sys.argv[1],"unit_dir":str(Path(sys.argv[2]).absolute())}))' "$APP" "$LA"
    fi
    for job in oarbankd console; do
        name="dev.codonic.oarbank.$job.service"
        if [[ $job == oarbankd ]]; then body="$(unit oarbankd on-failure "${OARBANKD[@]}" --agent-bind "$BIND")"
        else body="$(unit console always "${CONSOLE[@]}")"; fi
        if [[ $DRY == 1 ]]; then printf '# %s\n%s\n' "$LA/$name" "$body"; else printf '%s\n' "$body" > "$LA/$name"; fi
    done
    run systemctl --user daemon-reload
    run systemctl --user enable --now dev.codonic.oarbank.oarbankd.service dev.codonic.oarbank.console.service
    run systemctl --user restart dev.codonic.oarbank.oarbankd.service dev.codonic.oarbank.console.service   # an update
fi
for job in oarbankd console; do
    [[ "$OS" == Darwin ]] || break
    label="dev.codonic.oarbank.$job"
    if [[ $job == oarbankd ]]; then
        # exit 0 stays stopped (a finalized old coordinator); a crash or exit 75 (a standby's restart) restarts
        body="$(plist "$label" '<dict><key>SuccessfulExit</key><false/></dict>' oarbankd.log "${OARBANKD[@]}" --agent-bind "$BIND")"
    else
        body="$(plist "$label" '<true/>' console.log "${CONSOLE[@]}")"
    fi
    if [[ $DRY == 1 ]]; then
        printf '# %s\n%s\n' "$LA/$label.plist" "$body"
    else
        printf '%s\n' "$body" > "$LA/$label.plist"
    fi
    run launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
    run launchctl bootstrap "gui/$(id -u)" "$LA/$label.plist"
done
cat <<DONE
Oarbank coordinator installed.
  agents:  https://$BIND:7443 (client certificates; give nodes a join code)
  console: http://127.0.0.1:7400   admin API: http://127.0.0.1:7401
Next, on this machine:
  $CLI account create <you> --role admin --password   # a password and a TOTP secret (add a passkey later)
  $CLI join-code --label <node>               # a code for each node's installer
DONE
