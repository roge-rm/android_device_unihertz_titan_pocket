#!/bin/sh
# Rebuild vendor overlay v6 from the current connectivity modules and check it.
# With --modules it first rewrites the kernel Module.symvers and rebuilds the six
# modules, for after a kernel change. Run it through `heavy build`. No device use.
# heavy sets no marker in the environment, so that is not checked. The script takes
# its own lock so two repacks never write v6 at once.
set -eu
cd "$(dirname "$0")/.."
# The overlay folder is private_vendor_overlay in configs/local-paths.json; stop here if it is not set.
OVERLAY_DIR=$(python3 -c "import sys; sys.path.insert(0, 'tools'); import pocket_paths; print(pocket_paths.private_vendor_overlay())")
mkdir -p build
if [ -z "${VENDOR_OVERLAY_LOCKED:-}" ]; then
    VENDOR_OVERLAY_LOCKED=1 flock -n build/.vendor-overlay.lock "$0" "$@" && exit 0
    echo "repack failed, or another vendor overlay repack is running" >&2
    exit 1
fi
if [ "${1:-}" = --modules ]; then
    python3 tools/build-pocket-connectivity-module.py --module wmt_drv --refresh-symvers
    for m in wmt_chrdev_wifi wlan_drv_gen3 bt_drv gps_drv fmradio_drv; do
        python3 tools/build-pocket-connectivity-module.py --module "$m"
    done
fi
python3 tools/prepare-pocket-vendor-overlay.py --version v6 --replace
python3 tools/check-pocket-vendor-overlay.py --version v6 \
    --report "$OVERLAY_DIR/v6/check.json"
