#!/bin/bash
# Install the Oarbank coordinator as system services (docs/design/coordinator-system-service.md): oarbankd and the
# console as launchd daemons on macOS or systemd system units on Linux, run by the coordinator's own unprivileged
# account (_oarbankd, oarbankd), from boot. Runs as root. `--help` lists the options.
set -euo pipefail
usage() {
    cat <<USAGE
usage: $(basename "$0") (--build <archive> | --installed <directory>) --agent-bind <address> [options]
       $(basename "$0") --refresh [--dry-run]
       $(basename "$0") --prepare [--owner <user>] [--dry-run]
       $(basename "$0") --uninstall [--keep-programs] [--dry-run]

Install the Oarbank coordinator (oarbankd and the console) as system services run by its own account: launchd
daemons on macOS, systemd system units on Linux. They start at boot, before anyone logs in. Running it again updates
an installation in place. Run as root (sudo).

  --build <archive>        a coordinator build (oarbank-coordinator-<v>-<os>-<arch>.tar.gz from
                           scripts/build-coordinator.sh), unpacked into a root-owned directory beside earlier ones,
                           with \`current\` pointing at it
  --installed <directory>  use the build a native package installed (root-owned; nothing is unpacked or copied)
  --agent-bind <address>   the address agents reach: a LAN or tailnet address (127.0.0.1 only for a one-machine trial)
  --agent-port <port>      the agent listener's port (default 7443)
  --url <url>              this coordinator's agent URL as agents reach it (default https://<agent-bind>:<port>)
  --owner <user>           the person to add to the coordinator's owners' group, whose CLI then uses the local admin
                           channel without a token (default: \$SUDO_USER, else the person at the console)
  --pair <code>            a standby for a move: the pairing code \`oarbank coordinator prepare\` printed,
  --from <url>             the old coordinator's agent URL,
  --from-ca <pin>          and its TLS CA pin
  --archive-home           with --pair: move an existing home aside first (a move back to this machine)
  --refresh                write the services again from the record of the last install and restart them (upgrades)
  --prepare                only the account, the owners' group and the directories, no service (a migration copies
                           the home in before the services start)
  --uninstall              stop and remove the services (the home, the accounts and the group stay)
  --keep-programs          with --uninstall: leave the programs (a native package removes its own)
  --dry-run                print the commands and service files instead of running and writing them
  -h, --help               show this help

Environment: OARBANK_RELEASE_SIGNING=0 installs developer mode (release signing off; it is on by default).
USAGE
}
fail() { echo "install-oarbankd.sh: $*" >&2; echo "try --help" >&2; exit 2; }
die() { echo "install-oarbankd.sh: $*" >&2; exit 1; }
BUILD="" INSTALLED="" BIND="" PORT="" URL="" OWNER="" PAIR="" FROM="" FROMCA="" ARCHIVE=0 REFRESH=0 UNINSTALL=0 KEEP=0 DRY=0
PREPARE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --build|--installed|--agent-bind|--agent-port|--url|--owner|--pair|--from|--from-ca)
            [[ $# -ge 2 && "$2" != -* ]] || fail "$1 needs a value"
            case "$1" in --build) BUILD="$2" ;; --installed) INSTALLED="$2" ;; --agent-bind) BIND="$2" ;;
                --agent-port) PORT="$2" ;; --url) URL="$2" ;; --owner) OWNER="$2" ;; --pair) PAIR="$2" ;;
                --from) FROM="$2" ;; *) FROMCA="$2" ;; esac; shift 2 ;;
        --archive-home) ARCHIVE=1; shift ;;
        --refresh) REFRESH=1; shift ;;
        --prepare) PREPARE=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --keep-programs) KEEP=1; shift ;;
        --dry-run) DRY=1; shift ;;
        *) fail "unknown argument: $1" ;;
    esac
done
run() { if [[ $DRY == 1 ]]; then echo "$*"; else "$@"; fi; }

OS="$(uname -s)"
P="${OARBANK_INSTALL_ROOT:-}"          # a prefix for every system path (tests render a dry run into a scratch tree)
case "$OS" in
    Darwin) DATA="$P/Library/Application Support/Oarbank"
            DEFS="$P/Library/LaunchDaemons"
            PROGRAMS="$P/Library/Oarbank/Coordinator"
            RECORD="$DATA/coordinator-service.json"
            RUNDIR="$DATA/coordinator-run"
            ACCOUNT=_oarbankd GROUP=_oarbankadmin
            SYS_PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin ;;
    Linux)  DATA="$P/var/lib/oarbank"
            DEFS="$P/etc/systemd/system"
            PROGRAMS="$P/opt/oarbank/coordinator-builds"
            RECORD="$P/etc/oarbank/coordinator-service.json"
            RUNDIR="/run/oarbank-coordinator"
            ACCOUNT=oarbankd GROUP=oarbank-admin
            SYS_PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin ;;
    *) die "the coordinator installs on macOS and Linux (install-oarbankd.ps1 on Windows), not $OS" ;;
esac
HOME_DIR="$DATA/coordinator"
LABELS=(dev.codonic.oarbank.oarbankd dev.codonic.oarbank.console)
[[ $DRY == 1 || $(id -u) == 0 ]] || die "run as root (sudo): system services are root's to create"

# ------------------------------------------------------------------------------------------------- uninstall

if [[ $UNINSTALL == 1 ]]; then
    [[ -z "$BUILD$INSTALLED$BIND" && $REFRESH == 0 ]] || fail "--uninstall takes only --keep-programs and --dry-run"
    for label in "${LABELS[@]}"; do
        if [[ "$OS" == Darwin ]]; then
            run /bin/launchctl bootout "system/$label" 2>/dev/null || true
            run rm -f "$DEFS/$label.plist"
        else
            run systemctl disable --now "$label.service" 2>/dev/null || true
            run rm -f "$DEFS/$label.service"
        fi
    done
    [[ "$OS" == Darwin ]] || run systemctl daemon-reload
    [[ $KEEP == 1 ]] || run rm -rf "$PROGRAMS"
    run rm -f "$RECORD"
    echo "Oarbank coordinator services removed. Its home ($HOME_DIR), the $ACCOUNT account and the $GROUP group stay."
    exit 0
fi
[[ $KEEP == 0 ]] || fail "--keep-programs requires --uninstall"
if [[ $PREPARE == 1 ]]; then
    [[ -z "$BUILD$INSTALLED$BIND$PAIR" && $REFRESH == 0 ]] || fail "--prepare takes only --owner and --dry-run"
fi

# ------------------------------------------------------------------------------------------------- the record

json_str() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }
field() {   # a string field of a one-line JSON document: field <name> <document>
    local re="\"$1\": *\"([^\"]*)\""
    [[ "$2" =~ $re ]] && printf '%s' "${BASH_REMATCH[1]}"
}
SIGNING="${OARBANK_RELEASE_SIGNING:-1}"
if [[ $REFRESH == 1 ]]; then
    [[ -z "$BUILD$INSTALLED$BIND$PAIR" ]] || fail "--refresh takes everything from the record of the last install"
    [[ -f "$RECORD" ]] || die "no coordinator installed here ($RECORD is missing): install with --installed or --build"
    rec="$(cat "$RECORD")"
    [[ "$(field format "$rec")" == 1 ]] || die "$RECORD: unknown format"
    INSTALLED="$(field root "$rec")"; BIND="$(field agent_bind "$rec")"; PORT="$(field agent_port "$rec")"
    URL="$(field url "$rec")"; SIGNING="$(field signing "$rec")"; PAIR="$(field pair "$rec")"
    FROM="$(field from "$rec")"; FROMCA="$(field from_ca "$rec")"
fi

if [[ $PREPARE == 0 ]]; then
    [[ -n "$BIND" ]] || fail "give --agent-bind <address agents reach>"
    [[ ( -n "$BUILD" && -z "$INSTALLED" ) || ( -z "$BUILD" && -n "$INSTALLED" ) ]] || fail "give exactly one of --build or --installed"
    [[ "$BIND" != -* && "$BIND" != *[[:space:]\"\\]* ]] || fail "invalid agent address"
    [[ -z "$PORT" || "$PORT" =~ ^[0-9]{1,5}$ ]] || fail "invalid agent port"
    [[ "$URL$PAIR$FROM$FROMCA" != *[[:space:]\"\\]* ]] || fail "invalid URL, pairing code or pin"
    [[ "$SIGNING" == 0 || "$SIGNING" == 1 ]] || fail "OARBANK_RELEASE_SIGNING is 0 or 1"
    if [[ -n "$PAIR" ]]; then [[ -n "$FROM" && -n "$FROMCA" ]] || fail "a standby (--pair) also needs --from and --from-ca"; fi
    if [[ -z "$PAIR" && ( -n "$FROM$FROMCA" || $ARCHIVE == 1 ) ]]; then fail "--from, --from-ca and --archive-home need --pair"; fi
fi
case "$OS-$(uname -m)" in
    Darwin-arm64) want=darwin-arm64 ;; Darwin-x86_64) want=darwin-amd64 ;;
    Linux-aarch64) want=linux-arm64 ;; Linux-x86_64) want=linux-amd64 ;; *) want=unknown ;;
esac
# the person whose CLI may use the local admin channel: an existing account, never root
if [[ -z "$OWNER" ]]; then
    OWNER="${SUDO_USER:-}"
    [[ -n "$OWNER" || "$OS" != Darwin ]] || OWNER="$(/usr/bin/stat -f%Su /dev/console 2>/dev/null || true)"
fi
[[ "$OWNER" != root && "$OWNER" != loginwindow ]] || OWNER=""
[[ -z "$OWNER" || $DRY == 1 ]] || id -u "$OWNER" >/dev/null 2>&1 || die "--owner $OWNER: no such account"

# ------------------------------------------------------------------------------------------------- the programs

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi; }
if [[ $PREPARE == 1 ]]; then
    :                                     # no programs: only the account, the group and the directories below
elif [[ -n "$BUILD" ]]; then
    manifest="$(tar -xzOf "$BUILD" oarbank-coordinator.json)" || die "$BUILD is not a coordinator build"
    [[ "$manifest" =~ \"format\":\ *1[,\ }] ]] || die "$BUILD: unknown manifest format"
    version="$(field version "$manifest")" && platform="$(field platform "$manifest")" || die "$BUILD: the manifest has no version or platform"
    [[ "$platform" == "$want" ]] || die "the build is for $platform, this machine is $want"
    sha="$(sha256 "$BUILD" | cut -c1-12)"
    APP="$PROGRAMS/$version-$sha"
    run install -d -m 0755 "$PROGRAMS" "$APP"
    run tar -xzf "$BUILD" -C "$APP" --no-same-owner
    [[ $DRY == 1 ]] || chmod -R go-w "$APP"
    run ln -sfn "$version-$sha" "$PROGRAMS/current"
    ROOT="$PROGRAMS/current"
else
    [[ -f "$INSTALLED/oarbank-coordinator.json" && -x "$INSTALLED/bin/oarbankd" && -x "$INSTALLED/bin/oarbank-console" ]] \
        || die "$INSTALLED is not an installed coordinator build"
    ROOT="$(cd "$INSTALLED" && pwd -P)"
    manifest="$(cat "$ROOT/oarbank-coordinator.json")"
    [[ "$manifest" =~ \"format\":\ *1[,\ }] ]] || die "unknown installed build format"
    [[ "$manifest" =~ \"platform\":\ *\"$want\" ]] || die "the installed build is not for $want"
    if [[ $DRY != 1 ]]; then
        # what the service account runs must be root's: nobody else may change it
        bad="$(find "$ROOT" -maxdepth 2 \( ! -user 0 -o \( ! -type l \( -perm -0002 -o -perm -0020 \) \) \) -print -quit 2>/dev/null || true)"
        [[ -z "$bad" ]] || die "$ROOT is not root's alone ($bad): the system service runs only a root-owned build"
    fi
fi
ROOT="${ROOT:-}"
OARBANKD=("$ROOT/bin/oarbankd" --agent-bind "$BIND")
[[ -z "$PORT" ]] || OARBANKD+=(--agent-port "$PORT")
[[ -z "$URL" ]] || OARBANKD+=(--url "$URL")
[[ -z "$PAIR" ]] || OARBANKD+=(--standby --pair "$PAIR" --from "$FROM" --from-ca "$FROMCA")
[[ $ARCHIVE == 0 ]] || OARBANKD+=(--archive-home)
CONSOLE=("$ROOT/bin/oarbank-console")
SVC_PATH="$ROOT/bin:$SYS_PATH"            # oarbankd installs module dependencies with the build's own uv
SOCKET="$RUNDIR/admin.sock"

# ------------------------------------------------------------------------------------------------- the account

if [[ "$OS" == Darwin ]]; then
    free_id() {   # a system id below 500 that no user and no group has
        local used
        used="$( { /usr/bin/dscl . -list /Users UniqueID; /usr/bin/dscl . -list /Groups PrimaryGroupID; } | awk '{print $2}')"
        for ((i = 499; i >= 400; i--)); do grep -qx "$i" <<<"$used" || { echo "$i"; return; }; done
        die "no free system id below 500"
    }
    if [[ $DRY == 1 ]]; then
        echo "# ensure group $GROUP, user and group $ACCOUNT (hidden, /usr/bin/false, home $HOME_DIR), $ACCOUNT in $GROUP"
    else
        if ! /usr/bin/dscl . -read "/Groups/$GROUP" >/dev/null 2>&1; then
            gid="$(free_id)"
            /usr/bin/dscl . -create "/Groups/$GROUP"
            /usr/bin/dscl . -create "/Groups/$GROUP" PrimaryGroupID "$gid"
            /usr/bin/dscl . -create "/Groups/$GROUP" RealName "Oarbank coordinator owners"
            /usr/bin/dscl . -create "/Groups/$GROUP" Password '*'
        fi
        if ! /usr/bin/dscl . -read "/Users/$ACCOUNT" >/dev/null 2>&1; then
            uid="$(free_id)"
            /usr/bin/dscl . -create "/Groups/$ACCOUNT"
            /usr/bin/dscl . -create "/Groups/$ACCOUNT" PrimaryGroupID "$uid"
            /usr/bin/dscl . -create "/Groups/$ACCOUNT" Password '*'
            /usr/bin/dscl . -create "/Users/$ACCOUNT"
            /usr/bin/dscl . -create "/Users/$ACCOUNT" UniqueID "$uid"
            /usr/bin/dscl . -create "/Users/$ACCOUNT" PrimaryGroupID "$uid"
            /usr/bin/dscl . -create "/Users/$ACCOUNT" UserShell /usr/bin/false
            /usr/bin/dscl . -create "/Users/$ACCOUNT" NFSHomeDirectory "$HOME_DIR"
            /usr/bin/dscl . -create "/Users/$ACCOUNT" RealName "Oarbank coordinator"
            /usr/bin/dscl . -create "/Users/$ACCOUNT" IsHidden 1
            /usr/bin/dscl . -create "/Users/$ACCOUNT" Password '*'
        fi
        /usr/sbin/dseditgroup -o edit -a "$ACCOUNT" -t user "$GROUP"
    fi
    [[ -z "$OWNER" ]] || run /usr/sbin/dseditgroup -o edit -a "$OWNER" -t user "$GROUP"
else
    run sh -c "getent group $GROUP >/dev/null || groupadd --system $GROUP"
    run sh -c "id -u $ACCOUNT >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir '$HOME_DIR' --shell /usr/sbin/nologin $ACCOUNT"
    run usermod -aG "$GROUP" "$ACCOUNT"
    [[ -z "$OWNER" ]] || run usermod -aG "$GROUP" "$OWNER"
fi
run install -d -m 0755 "$DATA"
run install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0700 "$HOME_DIR"
run install -d -o "$ACCOUNT" -g "$ACCOUNT" -m 0700 "$HOME_DIR/logs"
[[ "$OS" != Darwin ]] || run install -d -o "$ACCOUNT" -g "$GROUP" -m 0750 "$RUNDIR"
if [[ $PREPARE == 1 ]]; then
    echo "The $ACCOUNT account, the $GROUP group${OWNER:+ (with $OWNER)} and the coordinator's directories are ready."
    exit 0
fi

# ------------------------------------------------------------------------------------------------- the services

xml() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; printf '%s' "$s"; }
# AssociatedBundleIdentifiers: Login Items, Allow in the Background lists both daemons as Oarbank Coordinator (the app of
# the coordinator's package), not as the signing team, so switching that off visibly stops the coordinator
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
  <key>UserName</key><string>$ACCOUNT</string>
  <key>GroupName</key><string>$ACCOUNT</string>
  <key>EnvironmentVariables</key><dict>
    <key>HOME</key><string>$(xml "$HOME_DIR")</string>
    <key>OARBANKD_HOME</key><string>$(xml "$HOME_DIR")</string>
    <key>OARBANKD_ADMIN_SOCKET</key><string>$(xml "$SOCKET")</string>
    <key>OARBANKD_ADMIN_GROUP</key><string>$GROUP</string>
    <key>OARBANK_SECRET_STORE</key><string>file</string>
    <key>PATH</key><string>$(xml "$SVC_PATH")</string>
    <key>OARBANK_RELEASE_SIGNING</key><string>$SIGNING</string>
  </dict>
  <key>WorkingDirectory</key><string>$(xml "$HOME_DIR")</string>
  <key>Umask</key><integer>63</integer>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>$keep
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Standard</string>
  <key>AssociatedBundleIdentifiers</key><array><string>dev.codonic.oarbank.coordinator</string></array>
  <key>StandardOutPath</key><string>$(xml "$HOME_DIR/logs/$log")</string>
  <key>StandardErrorPath</key><string>$(xml "$HOME_DIR/logs/$log")</string>
</dict></plist>
PL
}

unit() {   # name restart runtime-dir exec-args... : a systemd system unit run by the coordinator's account
    local name="$1" restart="$2" rundir="$3"; shift 3
    local q=""
    for a in "$@"; do a="${a//\\/\\\\}"; a="${a//\"/\\\"}"; q+=" \"${a//%/%%}\""; done
    cat <<UNIT
[Unit]
Description=Oarbank $name
After=network-online.target
Wants=network-online.target

[Service]
User=$ACCOUNT
Group=$ACCOUNT
SupplementaryGroups=$GROUP
ExecStart=${q# }
Environment="HOME=$HOME_DIR" "OARBANKD_HOME=$HOME_DIR" "OARBANKD_ADMIN_SOCKET=$SOCKET" "OARBANKD_ADMIN_GROUP=$GROUP" "OARBANK_SECRET_STORE=file" "OARBANK_RELEASE_SIGNING=$SIGNING" "PATH=$SVC_PATH"
WorkingDirectory=$HOME_DIR
StateDirectory=oarbank/coordinator
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
UNIT
    [[ -z "$rundir" ]] || printf 'RuntimeDirectory=%s\nRuntimeDirectoryMode=0750\n' "$rundir"
    cat <<UNIT
Restart=$restart
RestartSec=10
StandardOutput=append:$HOME_DIR/logs/$name.log
StandardError=append:$HOME_DIR/logs/$name.log

[Install]
WantedBy=multi-user.target
UNIT
}

write() {   # path body: root's, 0644
    if [[ $DRY == 1 ]]; then printf '# %s\n%s\n' "$1" "$2"; else
        install -d -m 0755 "$(dirname "$1")"
        printf '%s\n' "$2" > "$1.tmp" && chmod 0644 "$1.tmp" && mv -f "$1.tmp" "$1"
    fi
}

if [[ "$OS" == Darwin ]]; then
    for job in oarbankd console; do
        label="dev.codonic.oarbank.$job"
        if [[ $job == oarbankd ]]; then
            # exit 0 stays stopped (a finalized old coordinator); a crash or exit 75 (a standby's restart) restarts
            body="$(plist "$label" '<dict><key>SuccessfulExit</key><false/></dict>' oarbankd.log "${OARBANKD[@]}")"
        else
            body="$(plist "$label" '<true/>' console.log "${CONSOLE[@]}")"
        fi
        write "$DEFS/$label.plist" "$body"
        [[ $DRY == 1 ]] || chown root:wheel "$DEFS/$label.plist"
        run /bin/launchctl bootout "system/$label" 2>/dev/null || true
        # a bootstrap right after a bootout can find the old job still going away (error 5): once more after a moment
        run /bin/launchctl bootstrap system "$DEFS/$label.plist" 2>/dev/null \
            || { sleep 1; run /bin/launchctl bootstrap system "$DEFS/$label.plist"; }
    done
else
    write "$DEFS/dev.codonic.oarbank.oarbankd.service" "$(unit oarbankd on-failure oarbank-coordinator "${OARBANKD[@]}")"
    write "$DEFS/dev.codonic.oarbank.console.service" "$(unit console always "" "${CONSOLE[@]}")"
    run systemctl daemon-reload
    run systemctl enable dev.codonic.oarbank.oarbankd.service dev.codonic.oarbank.console.service
    run systemctl restart dev.codonic.oarbank.oarbankd.service dev.codonic.oarbank.console.service
fi

# the record --refresh reads (root's alone: it may hold a standby's pairing code)
record="{\"format\": \"1\", \"root\": $(json_str "$ROOT"), \"agent_bind\": $(json_str "$BIND"), \"agent_port\": $(json_str "$PORT"), \"url\": $(json_str "$URL"), \"signing\": \"$SIGNING\", \"owner_group\": \"$GROUP\", \"account\": \"$ACCOUNT\", \"pair\": $(json_str "$PAIR"), \"from\": $(json_str "$FROM"), \"from_ca\": $(json_str "$FROMCA")}"
if [[ $DRY == 1 ]]; then printf '# %s\n%s\n' "$RECORD" "$record"; else
    install -d -m 0755 "$(dirname "$RECORD")"
    printf '%s\n' "$record" > "$RECORD.tmp" && chmod 0600 "$RECORD.tmp" && mv -f "$RECORD.tmp" "$RECORD"
fi
if [[ $REFRESH == 1 ]]; then echo "Oarbank coordinator services refreshed and restarted on $ROOT."; exit 0; fi
echo "Oarbank coordinator installed as system services, run by $ACCOUNT from boot."
echo "  agents:  https://$BIND:${PORT:-7443} (client certificates; give nodes a join code)"
echo "  console: http://127.0.0.1:7400   admin API: http://127.0.0.1:7401"
if [[ -n "$OWNER" ]]; then
    echo "  $OWNER is one of the coordinator's owners (group $GROUP): \`oarbank\` uses the local admin channel without a token."
    [[ "$OS" == Darwin ]] || echo "  Group membership takes effect at $OWNER's next login (or run: newgrp $GROUP)."
fi
echo "Next, as the owner:"
echo "  oarbank account create <you> --role admin --password   # a password and a TOTP secret (add a passkey later)"
echo "  oarbank join-code --label <node>                       # a code for each node's installer"
