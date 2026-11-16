#!/bin/sh
# Starts the Titan Pocket installer. Needs Python 3.9 or later and Google's platform-tools
# (adb and fastboot), looked for next to this file, on PATH and in the usual SDK folders.
cd "$(dirname "$0")" || exit 1

PY=
for p in python3 python; do
    if command -v "$p" >/dev/null 2>&1 &&
        "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
        PY=$(command -v "$p")
        break
    fi
done
if [ -z "$PY" ]; then
    echo "Python 3.9 or later is missing."
    if [ "$(uname)" = Darwin ]; then
        echo "Install it from https://www.python.org/downloads/ and run this again."
    else
        echo "Install it with your package manager (Debian or Ubuntu: sudo apt install python3) and run this again."
    fi
    exit 1
fi

find_tool() {
    for d in ./platform-tools "$HOME/platform-tools" "$HOME/Android/Sdk/platform-tools" \
        "$HOME/Library/Android/sdk/platform-tools"; do
        if [ -x "$d/$1" ]; then
            echo "$d/$1"
            return
        fi
    done
    command -v "$1" 2>/dev/null
}

ADB=$(find_tool adb)
FASTBOOT=$(find_tool fastboot)
if [ -z "$ADB" ] || [ -z "$FASTBOOT" ]; then
    [ -z "$ADB" ] && echo "adb is missing."
    [ -z "$FASTBOOT" ] && echo "fastboot is missing."
    echo "Download Google's platform-tools from"
    echo "  https://developer.android.com/tools/releases/platform-tools"
    echo "and unzip it here, so there is a platform-tools folder next to install.sh, then run this again."
    exit 1
fi

exec "$PY" tools/pocket-install.py --adb "$ADB" --fastboot "$FASTBOOT" "$@"
