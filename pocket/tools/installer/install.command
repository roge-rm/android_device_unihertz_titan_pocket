#!/bin/sh
# macOS: double-click to run the installer in Terminal.
cd "$(dirname "$0")" || exit 1
/bin/sh ./install.sh "$@"
status=$?
echo
echo "You can close this window now."
exit $status
