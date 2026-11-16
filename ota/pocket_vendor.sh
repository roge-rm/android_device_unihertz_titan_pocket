#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Applies the Pocket vendor overlay to the phone's vendor partition during an OTA.
#
# Usage: pocket_vendor.sh check|apply TARGET PAYLOAD
#   TARGET   the vendor block device, which this checks with e2fsck and mounts, or a vendor
#            root directory (host tests)
#   PAYLOAD  directory with manifest.txt, files/ and patch/ (tools/prepare-pocket-vendor-ota.py)
#
# check fails unless the filesystem is clean, the stock release is May 2024 or newer, every
# listed file is the overlay version or one the manifest accepts, each edited file rebuilds
# from the phone's copy to the overlay hash, the labels can be set and the write plan fits
# the free blocks and inodes. Nothing is written when check fails.
# apply runs check, then for each step stages the step's files as FILE.pocket-new with owner,
# mode and label set and renames them over the old ones, then removes files, unmounts and
# runs e2fsck -fy. Every file is either its old or its new version at any point, so a retry
# after an interrupted apply finishes the job.
#
# Host tests only: POCKET_VENDOR_META_LOG gets "path uid gid mode label" lines instead of
# setting them, POCKET_VENDOR_FREE="BLOCKS INODES" gives the free counts of the image the
# tree came from, POCKET_VENDOR_OPS_LOG gets each write, rename and remove, and
# POCKET_VENDOR_STOP_AFTER=N exits with 3 after N of them. POCKET_VENDOR_WORK is the scratch
# directory, /tmp/pocket_vendor_work by default.

MODE="$1"
TARGET="$2"
P="$3"
WORK="${POCKET_VENDOR_WORK:-/tmp/pocket_vendor_work}"
MNT="$WORK/mnt"
NEW="$WORK/new"
M="$P/manifest.txt"
E2FSCK=/system/bin/e2fsck
# Shared with tools/prepare-pocket-vendor-ota.py: blocks and inodes kept free at every point,
# and one block per written file for its extent and directory growth.
RESERVE_BLOCKS=8
RESERVE_INODES=1
EXTRA_BLOCKS=1

say() { echo "pocket_vendor: $*"; }

if [ $# -ne 3 ] || [ ! -r "$M" ] || { [ "$MODE" != check ] && [ "$MODE" != apply ]; }; then
  say "usage: $0 check|apply TARGET PAYLOAD"
  exit 2
fi
mkdir -p "$WORK" || exit 2

MOUNTED=
DEV=
unmount_vendor() {
  if [ -n "$MOUNTED" ]; then
    sync
    umount "$MNT" && MOUNTED=
  fi
}
trap unmount_vendor EXIT

# $1: ro or rw
mount_vendor() {
  if [ -d "$TARGET" ]; then
    V="$TARGET"
    return 0
  fi
  if [ ! -b "$TARGET" ]; then
    say "$TARGET is not a block device or directory"
    return 1
  fi
  if [ ! -x "$E2FSCK" ]; then
    say "$E2FSCK is missing"
    return 1
  fi
  DEV=$(readlink -f "$TARGET")
  # Unmount any earlier mount of the device, so e2fsck sees it at rest and a read-write
  # mount gets its own superblock flags.
  for m in $(grep "^$DEV " /proc/mounts | cut -d' ' -f2); do
    umount "$m" || return 1
  done
  # Vendor has no journal, so check it before writing to it.
  if ! "$E2FSCK" -fn "$DEV"; then
    say "vendor has filesystem errors"
    return 1
  fi
  [ "$1" = rw ] && blockdev --setrw "$DEV"
  mkdir -p "$MNT"
  mount -t ext4 -o "$1" "$DEV" "$MNT" || { say "cannot mount $DEV $1"; return 1; }
  MOUNTED=1
  V="$MNT"
}

hash_of() {
  if [ -f "$1" ]; then
    sha256sum "$1" | cut -d' ' -f1
  elif [ -e "$1" ]; then
    echo other
  else
    echo -
  fi
}

# $1 hash, $2 comma-separated list
listed() {
  case ",$2," in
    *",$1,"*) return 0 ;;
  esac
  return 1
}

# Rebuild an edited file from the phone's copy. $1 phone file, $2 ops base name, $3 output
rebuild() {
  : > "$3" || return 1
  while read -r op off n; do
    case "$op" in
      s) from="$1" ;;
      l) from="$2.lit" ;;
      *) return 1 ;;
    esac
    dd if="$from" bs=65536 iflag=skip_bytes,count_bytes skip="$off" count="$n" 2>/dev/null >> "$3" || return 1
  done < "$2.ops"
}

blocks_of() { echo $(( ($1 + BS - 1) / BS )); }

size_of() { stat -c %s "$1"; }

# The file a write copies from.
source_of() {
  if [ "$kind" = patch ]; then
    echo "$NEW/$path"
  else
    echo "$P/files/$path"
  fi
}

# Counts writes, renames and removes for the host tests.
OPS=0
did() {
  [ -n "$POCKET_VENDOR_OPS_LOG" ] && echo "$*" >> "$POCKET_VENDOR_OPS_LOG"
  OPS=$((OPS + 1))
  if [ -n "$POCKET_VENDOR_STOP_AFTER" ] && [ "$OPS" -ge "$POCKET_VENDOR_STOP_AFTER" ]; then
    say "stopped after $OPS writes (test)"
    exit 3
  fi
}

free_counts() {
  if [ -n "$POCKET_VENDOR_FREE" ]; then
    set -- $POCKET_VENDOR_FREE
    FREE=$1 FREE_INODES=$2 BS=4096
  else
    BS=$(stat -f -c %S "$V")
    FREE=$(stat -f -c %f "$V")
    FREE_INODES=$(stat -f -c %d "$V")
  fi
}

check() {
  bad=0
  min=$(grep '^vendor_version_min ' "$M" | cut -d' ' -f2)
  release=$(grep '^ro.vendor.build.custom_version=' "$V/build.prop" | sed 's/^ro.vendor.build.custom_version=Titan_pocket_//')
  case "$release" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) release=0 ;;
  esac
  if [ -z "$min" ] || [ "$release" -lt "$min" ]; then
    say "vendor is from stock release $release, older than $min: update the phone with Unihertz's updater first"
    return 1
  fi
  free_counts
  rm -rf "$NEW" && mkdir -p "$NEW" || return 1
  : > "$WORK/labels"
  last=0
  while read -r kind step path target size mode uid gid label accept; do
    [ "$kind" = vendor_version_min ] && continue
    [ "$step" -gt "$last" ] && last=$step
    f="$V/$path"
    cur=$(hash_of "$f")
    # A stale staged file from an interrupted apply is deleted before the writes.
    if [ -f "$f.pocket-new" ]; then
      FREE=$((FREE + $(blocks_of "$(size_of "$f.pocket-new")")))
      FREE_INODES=$((FREE_INODES + 1))
    fi
    [ "$cur" = "$target" ] && continue
    if ! listed "$cur" "$accept"; then
      [ "$path" = etc/fstab.mt6771 ] && say "This update needs a data wipe: /data is not encrypted. Install with the installer."
      say "$path is $cur, not the overlay $target or one of $accept"
      bad=1
      continue
    fi
    [ "$kind" = remove ] && continue
    [ -d "$(dirname "$f")" ] || { say "$(dirname "$path") is missing"; bad=1; continue; }
    src=$(source_of)
    if [ "$kind" = patch ]; then
      mkdir -p "$(dirname "$src")" || return 1
      if ! rebuild "$f" "$P/patch/$path/$cur" "$src" || [ "$(hash_of "$src")" != "$target" ]; then
        say "$path: the edit does not rebuild the overlay version from $cur"
        bad=1
        continue
      fi
    elif [ "$(hash_of "$src")" != "$target" ]; then
      say "$path: the payload copy is damaged"
      bad=1
      continue
    fi
    grep -qxF "$uid $gid $mode $label" "$WORK/labels" || echo "$uid $gid $mode $label" >> "$WORK/labels"
  done < "$M"
  [ "$bad" = 0 ] || return 1

  # Owners, modes and labels the apply will set, tried on a scratch file first.
  if [ -z "$POCKET_VENDOR_META_LOG" ]; then
    while read -r uid gid mode label; do
      t="$WORK/label-trial"
      rm -f "$t" && touch "$t" && chown "$uid:$gid" "$t" && chmod "$mode" "$t" && chcon "$label" "$t" ||
        { say "cannot set $uid:$gid $mode $label here"; bad=1; }
      rm -f "$t"
    done < "$WORK/labels"
  fi

  # The plan: each step's new files sit beside the old ones until the step's renames.
  low=$FREE
  step=1
  while [ "$step" -lt "$last" ]; do
    back=0 back_inodes=0
    while read -r kind s path target size mode uid gid label accept; do
      [ "$s" = "$step" ] && [ "$kind" != remove ] || continue
      f="$V/$path"
      [ "$(hash_of "$f")" = "$target" ] && continue
      FREE=$((FREE - $(blocks_of "$size") - EXTRA_BLOCKS))
      FREE_INODES=$((FREE_INODES - 1))
      if [ -f "$f" ]; then
        back=$((back + $(blocks_of "$(size_of "$f")")))
        back_inodes=$((back_inodes + 1))
      fi
      if [ "$FREE" -lt "$RESERVE_BLOCKS" ] || [ "$FREE_INODES" -lt "$RESERVE_INODES" ]; then
        say "not enough room in vendor at step $step $path: $FREE blocks and $FREE_INODES inodes would be left"
        return 1
      fi
    done < "$M"
    [ "$FREE" -lt "$low" ] && low=$FREE
    FREE=$((FREE + back))
    FREE_INODES=$((FREE_INODES + back_inodes))
    step=$((step + 1))
  done
  say "space: at least $low blocks stay free"
  return $bad
}

set_meta() {
  if [ -n "$POCKET_VENDOR_META_LOG" ]; then
    echo "$2 $3 $4 $5 $6" >> "$POCKET_VENDOR_META_LOG"
    return 0
  fi
  chown "$3:$4" "$1" && chmod "$5" "$1" && chcon "$6" "$1"
}

apply() {
  while read -r kind step path target rest; do
    [ "$kind" = vendor_version_min ] && continue
    if [ -e "$V/$path.pocket-new" ]; then
      rm -f "$V/$path.pocket-new" || return 1
      did remove "$path.pocket-new"
    fi
  done < "$M"
  step=1
  while [ "$step" -le "$last" ]; do
    : > "$WORK/staged"
    while read -r kind s path target size mode uid gid label accept; do
      [ "$s" = "$step" ] || continue
      f="$V/$path"
      if [ "$kind" = remove ]; then
        if [ -e "$f" ]; then
          rm -f "$f" || return 1
          did remove "$path"
        fi
        continue
      fi
      if [ "$(hash_of "$f")" = "$target" ]; then
        set_meta "$f" "$path" "$uid" "$gid" "$mode" "$label" || return 1
        continue
      fi
      cp "$(source_of)" "$f.pocket-new" || return 1
      did write "$path.pocket-new"
      set_meta "$f.pocket-new" "$path" "$uid" "$gid" "$mode" "$label" || return 1
      echo "$path" >> "$WORK/staged"
    done < "$M"
    sync
    while read -r path; do
      mv -f "$V/$path.pocket-new" "$V/$path" || return 1
      did rename "$path.pocket-new" "$path"
    done < "$WORK/staged"
    step=$((step + 1))
  done
  sync
}

verify() {
  bad=0
  while read -r kind step path target rest; do
    [ "$kind" = vendor_version_min ] && continue
    cur=$(hash_of "$V/$path")
    [ "$cur" = "$target" ] || { say "$path is $cur after apply, not $target"; bad=1; }
    [ -e "$V/$path.pocket-new" ] && { say "$path.pocket-new is left"; bad=1; }
  done < "$M"
  return $bad
}

if [ "$MODE" = check ]; then
  mount_vendor ro || { say "vendor check failed, nothing written"; exit 1; }
  check || { say "vendor check failed, nothing written"; exit 1; }
  say "vendor check passed"
  exit 0
fi

mount_vendor rw || { say "vendor check failed, nothing written"; exit 1; }
check || { say "vendor check failed, nothing written"; exit 1; }
apply || { say "vendor write failed"; exit 1; }
verify || { say "vendor files differ after the write"; exit 1; }
unmount_vendor || { say "cannot unmount vendor"; exit 1; }
if [ -n "$DEV" ]; then
  # 0 is clean, 1 is fixed; anything higher is an error left on the filesystem.
  "$E2FSCK" -fy "$DEV"
  rc=$?
  [ "$rc" -le 1 ] || { say "e2fsck -fy returned $rc"; exit 1; }
fi
say "vendor overlay applied"
exit 0
