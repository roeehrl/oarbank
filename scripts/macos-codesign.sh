#!/usr/bin/env bash
# macOS code signing shared by scripts/package-macos.sh, scripts/build-coordinator.sh and
# scripts/package-coordinator-macos.sh. Sourced, it defines the functions below; run, it signs a tree:
#
#   scripts/macos-codesign.sh tree IDENTITY DIR     # IDENTITY: "Developer ID Application: …", or - (ad hoc)
#
# A Developer ID signs with the hardened runtime and a secure timestamp (what notarization requires); ad hoc signs
# without either, for local builds. The Python interpreters that run module code (python, python3, python3.N) are
# signed with deploy/macos/python.entitlements either way, so an unsigned CI build carries the entitlements the owner's
# signed build will, and scripts/check-macos-signing.py can check both. Libraries and extension modules carry none.
OARBANK_PYTHON_ENTITLEMENTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/macos/python.entitlements"

macos_is_python() { [[ "$(basename "$1")" =~ ^python(3(\.[0-9]+)?)?$ ]]; }

# macos_sign IDENTITY FILE [codesign option]...: one file or bundle, retried (the timestamp service fails at times)
macos_sign() {
    local id="$1" f="$2" attempt
    shift 2
    local extra=("$@")
    if macos_is_python "$f"; then extra+=(--entitlements "$OARBANK_PYTHON_ENTITLEMENTS"); fi
    if [[ "$id" == "-" ]]; then
        codesign --force ${extra[@]+"${extra[@]}"} --sign - "$f" 2>/dev/null
        return
    fi
    for attempt in 1 2 3; do
        codesign --force --options runtime --timestamp ${extra[@]+"${extra[@]}"} --sign "$id" "$f" && return 0
        [[ $attempt == 3 ]] || sleep 3
    done
    return 1
}

# macos_sign_tree IDENTITY DIR: every Mach-O file under DIR (executables, libraries, extension modules)
macos_sign_tree() {
    local id="$1" f
    find "$2" -type f \( -perm -u+x -o -name '*.so' -o -name '*.dylib' \) -print0 | while IFS= read -r -d '' f; do
        file -b "$f" | grep Mach-O >/dev/null || continue
        macos_sign "$id" "$f"
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -euo pipefail
    case "${1:-}" in
        tree) macos_sign_tree "${2:?macos-codesign.sh tree IDENTITY DIR}" "${3:?macos-codesign.sh tree IDENTITY DIR}" ;;
        *) echo "usage: scripts/macos-codesign.sh tree IDENTITY DIR" >&2; exit 2 ;;
    esac
fi
