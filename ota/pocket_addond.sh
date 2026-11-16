#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Keeps backuptool's addon.d scripts and backup across its first restore, which deletes them,
# so the OTA can run restore again after the boot write (releasetools.py).
#
# Usage: pocket_addond.sh save|load|clean
# save links /tmp/addon.d and /tmp/backupdir into /tmp/pocket_addond, load links them back.
# Hard links, so a large backup isn't copied in RAM.

K=/tmp/pocket_addond

case "$1" in
  save)
    rm -rf "$K" && mkdir -p "$K" || exit 1
    for d in addon.d backupdir; do
      [ -d "/tmp/$d" ] && { cp -a -l "/tmp/$d" "$K/$d" || exit 1; }
    done
    touch "$K/saved"
    ;;
  load)
    [ -f "$K/saved" ] || exit 1
    for d in addon.d backupdir; do
      rm -rf "/tmp/$d"
      [ -d "$K/$d" ] && { cp -a -l "$K/$d" "/tmp/$d" || exit 1; }
    done
    ;;
  clean)
    rm -rf "$K"
    ;;
  *)
    echo "usage: $0 save|load|clean"
    exit 2
    ;;
esac
exit 0
