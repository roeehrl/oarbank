#!/bin/sh
# Install an Oarbank node on macOS or Linux, then join it (docs/design/node-enrollment.md, "Channels", one-liner):
#
#   curl -fsSL https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.sh | sudo sh
#   curl -fsSL .../oarbank-install.sh | sudo sh -s -- --containers --name build-07
#   curl -fsSL .../oarbank-install.sh | sudo --preserve-env=OARBANK_JOIN_CODE sh
#       (scripts: OARBANK_JOIN_CODE exported from a secret store, never typed on a command line)
#
# It downloads this release's package for the machine (macOS pkg; Linux deb where apt is, rpm where dnf or yum is) and
# its SHA256SUMS file from the release, refuses a package whose SHA-256 does not match (and refuses to go on when no
# SHA-256 tool is at hand: it never skips the check) and installs it. Given a code (OARBANK_JOIN_CODE, the console's
# command), it then runs `oarbank-node join` with it: the code is never on a command line, it goes to oarbank-node on
# standard input, written by the shell's builtin printf, and the script exits with oarbank-node's exit code. Without
# one, piped like the lines above, it never asks for the code: it installs and says to run `sudo oarbank-node join`.
# Only a script run as a file (sudo sh oarbank-install.sh) lets oarbank-node ask, on its standard input.
#
#   --containers   container jobs on this node (passed to oarbank-node join)
#   --name NAME    the node's name when the code has no label
#   --no-join      install only; join later with: sudo oarbank-node join
#
# Environment: OARBANK_JOIN_CODE (a code), OARBANK_JOIN_CODE_FILE (a file holding one), OARBANK_COORDINATOR (join by URL:
# device code, the owner approves the node). OARBANK_INSTALL_BASE_URL replaces the release's download URL, for mirrors
# and tests: it must serve the same files.
#
# scripts/package-install-scripts.sh fills in the version. The whole body is one function, called on the last line: a
# download cut short defines nothing it runs.

oarbank_install() {
    set -eu
    OB_VERSION='@OARBANK_VERSION@'
    case "$OB_VERSION" in
        *@*) echo "oarbank-install: this is the unreleased source; use the release's oarbank-install.sh" >&2; return 2 ;;
    esac
    OB_BASE="${OARBANK_INSTALL_BASE_URL:-https://github.com/roeehrl/oarbank/releases/download/v$OB_VERSION}"
    OB_BASE="${OB_BASE%/}"

    containers="" name="" join=1
    # the console's commands set OARBANK_CONTAINERS=1 (the variable the Linux package reads too)
    case "${OARBANK_CONTAINERS:-}" in 1|[Tt]rue|TRUE|[Yy]es|YES|[Oo]n|ON) containers=1 ;; esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --containers) containers=1 ;;
            --name) [ $# -ge 2 ] || { echo "oarbank-install: --name needs a value" >&2; return 2; }; name="$2"; shift ;;
            --name=*) name="${1#--name=}" ;;
            --no-join) join="" ;;
            -h|--help)
                echo "usage: oarbank-install.sh [--containers] [--name NAME] [--no-join]"
                echo "  curl -fsSL https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.sh | sudo sh -s -- [options]"
                return 0 ;;
            *) echo "oarbank-install: unknown option $1 (--containers, --name NAME, --no-join)" >&2; return 2 ;;
        esac
        shift
    done

    if [ "$(id -u)" != 0 ]; then
        echo "oarbank-install: installing a node needs root. Run it with sudo:" >&2
        echo "  curl -fsSL https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.sh | sudo sh" >&2
        return 8
    fi

    # this machine's package: the platform names the SHA256SUMS file, the suffix the package in it
    os="$(uname -s)" arch="$(uname -m)"
    case "$os" in
        Darwin)
            # a shell under Rosetta 2 says x86_64 on Apple silicon: the machine's own architecture decides
            if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then arch=arm64; fi
            case "$arch" in
                arm64) platform=darwin-arm64 ;;
                x86_64) platform=darwin-amd64 ;;
                *) echo "oarbank-install: no Oarbank package for macOS on $arch (arm64 or x86_64)" >&2; return 2 ;;
            esac
            kind=pkg prefix="oarbank-agent-$OB_VERSION-macos-" ;;
        Linux)
            case "$arch" in
                x86_64|amd64) platform=linux-amd64 ;;
                aarch64|arm64) platform=linux-arm64 ;;
                *) echo "oarbank-install: no Oarbank package for Linux on $arch (x86_64 or aarch64)" >&2; return 2 ;;
            esac
            if command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
                kind=deb prefix="oarbank-agent_"
            elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
                kind=rpm prefix="oarbank-agent-"
            else
                echo "oarbank-install: this Linux has neither apt nor dnf/yum. Use the release's oarbank-agent-$OB_VERSION-$platform.tar.gz" >&2
                return 2
            fi ;;
        *) echo "oarbank-install: no Oarbank package for $os (macOS or Linux; Windows: oarbank-install.ps1)" >&2; return 2 ;;
    esac

    # SHA-256 before anything is downloaded: no tool, no install
    if command -v sha256sum >/dev/null 2>&1; then
        sha256() { sha256sum "$1"; }
    elif command -v shasum >/dev/null 2>&1; then
        sha256() { shasum -a 256 "$1"; }
    else
        echo "oarbank-install: neither sha256sum nor shasum is installed, so the package cannot be verified; install one and run this again" >&2
        return 1
    fi
    if command -v curl >/dev/null 2>&1; then
        fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
    elif command -v wget >/dev/null 2>&1; then
        fetch() { wget -q -O "$2" "$1"; }
    else
        echo "oarbank-install: neither curl nor wget is installed" >&2
        return 1
    fi

    OB_TMP="$(mktemp -d "${TMPDIR:-/tmp}/oarbank-install.XXXXXX")"
    trap 'rm -rf "$OB_TMP"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    chmod 700 "$OB_TMP"

    sums="SHA256SUMS-agent-$OB_VERSION-$platform"
    echo "Downloading Oarbank $OB_VERSION for $platform"
    fetch "$OB_BASE/$sums" "$OB_TMP/$sums" || { echo "oarbank-install: could not download $OB_BASE/$sums" >&2; return 1; }
    asset="" want=""
    while read -r h f || [ -n "$h" ]; do
        f="${f#\*}"
        f="${f#./}"
        case "$f" in
            "$prefix"*".$kind")
                [ -z "$asset" ] || { echo "oarbank-install: $sums names more than one .$kind package" >&2; return 1; }
                asset="$f" want="$h" ;;
        esac
    done < "$OB_TMP/$sums"
    [ -n "$asset" ] || { echo "oarbank-install: $sums names no .$kind package for this machine" >&2; return 1; }
    case "$asset" in
        */*|*[!A-Za-z0-9._+~-]*) echo "oarbank-install: $sums names an unexpected file ($asset)" >&2; return 1 ;;
    esac
    fetch "$OB_BASE/$asset" "$OB_TMP/$asset" || { echo "oarbank-install: could not download $OB_BASE/$asset" >&2; return 1; }
    got="$(sha256 "$OB_TMP/$asset")"
    got="${got%% *}"
    if [ -z "$want" ] || [ "$got" != "$want" ]; then
        echo "oarbank-install: $asset does not match its SHA-256 in $sums; nothing was installed" >&2
        return 1
    fi
    echo "Verified $asset (SHA-256 $got)"

    # The package installs only: the join below is this script's, so the package variables stay out of the package
    # manager's environment (the postinstall would otherwise stage the code itself). Its standard input is not the
    # script's.
    echo "Installing $asset"
    if ! (
        unset OARBANK_JOIN_CODE OARBANK_JOIN_CODE_FILE OARBANK_COORDINATOR OARBANK_NAME OARBANK_CONTAINERS
        case "$kind" in
            pkg) installer -pkg "$OB_TMP/$asset" -target / ;;
            deb) DEBIAN_FRONTEND=noninteractive apt-get install -y "$OB_TMP/$asset" ;;
            rpm) if command -v dnf >/dev/null 2>&1; then dnf install -y "$OB_TMP/$asset"; else yum install -y "$OB_TMP/$asset"; fi ;;
        esac
    ) < /dev/null; then
        echo "oarbank-install: installing $asset failed (above)" >&2
        return 1
    fi

    if [ -z "$join" ]; then
        echo "Installed. Join this computer with: sudo oarbank-node join"
        return 0
    fi
    node="$(command -v oarbank-node 2>/dev/null || true)"
    if [ -z "$node" ]; then
        for c in /usr/local/bin/oarbank-node /usr/bin/oarbank-node; do
            [ -x "$c" ] && { node="$c"; break; }
        done
    fi
    [ -n "$node" ] || { echo "oarbank-install: installed, but oarbank-node is not on PATH" >&2; return 1; }

    set -- join
    [ -n "$containers" ] && set -- "$@" --containers
    [ -n "$name" ] && set -- "$@" --name "$name"
    code="${OARBANK_JOIN_CODE:-}"
    unset OARBANK_JOIN_CODE
    # Nothing here asks for the code unless this shell's standard input is a terminal. Piped (curl ... | sudo sh), its
    # standard input is the script, and sudo 1.9.14 and later (use_pty) runs the shell on a pseudo-terminal of its own
    # while it leaves the person's terminal as it was, echoing, because sudo's own standard input is not a terminal: a
    # prompt that hides input on sudo's terminal would show the pasted code on the person's.
    rc=0
    if [ -n "$code" ]; then
        printf '%s' "$code" | "$node" "$@" --code-stdin --no-input || rc=$?
        code=""
    elif [ -n "${OARBANK_JOIN_CODE_FILE:-}" ]; then
        "$node" "$@" --code-file "$OARBANK_JOIN_CODE_FILE" --no-input < /dev/null || rc=$?
    elif [ -n "${OARBANK_COORDINATOR:-}" ]; then
        # device code: no secret is typed, the terminal only answers whether the coordinator's fingerprint is the one
        # the console shows (y/N), so a piped script may ask it on the terminal
        if [ -t 0 ]; then
            "$node" "$@" --coordinator "$OARBANK_COORDINATOR" || rc=$?
        elif (: < /dev/tty) 2>/dev/null; then
            "$node" "$@" --coordinator "$OARBANK_COORDINATOR" < /dev/tty || rc=$?
        else
            "$node" "$@" --coordinator "$OARBANK_COORDINATOR" --no-input < /dev/null || rc=$?
        fi
    elif [ -t 0 ]; then
        # run as a file (sudo sh oarbank-install.sh): sudo's standard input is the terminal, which sudo puts in raw
        # mode while it relays it, so oarbank-node's hidden prompt is hidden
        "$node" "$@" || rc=$?
    else
        echo "Installed. Join this computer with: sudo oarbank-node join"
        echo "(or run the command from the console's Add machine page, which has the code in it)"
        return 0
    fi
    return "$rc"
}

oarbank_install "$@"
