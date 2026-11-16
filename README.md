# android_device_unihertz_titan_pocket

Device tree for the Unihertz Titan Pocket (MT6771) on LineageOS 23.2, as `device/unihertz/titan_pocket`. The tree is at the root of this repo, and the build tools, configs, kernel patches and PocketInput source are under `pocket/`.

Status: unofficial and not complete. See the owner repo `roge-rm/titan-pocket-lineage` for installing, and `android_kernel_unihertz_mt6771` for the 5.10 kernel this builds with.

## Using it

Clone it to `device/unihertz/titan_pocket` in a LineageOS 23.2 tree. The proprietary vendor files are not included and are not redistributable: they come from your own stock image.

The root is the device tree, plus `PocketInput/` (the keyboard settings app and IME hooks, built as part of the device). `pocket/` holds the build tools, configs and kernel patches. It has a `.find-ignore` file, so the Android build does not look inside it. The tools find the device tree as the folder above `pocket/`, so run them from a clone as they are.

Private inputs (stock vendor image, the platform source, the build folder, the release keys) are set in `pocket/configs/local-paths.json`, which is git-ignored. Keys: `build_root`, `platform_source`, `platform_root`, `private_vendor`, `private_vendor_overlay`, `release_keys`, and `lab_host`, `lab_user`, `lab_ssh_key`, `device_serial` for the phone helpers. `POCKET_PATHS` names another file, and `POCKET_BUILD_ROOT` and `POCKET_PLATFORM_SOURCE` override two keys. A tool only looks a path up when it needs it, and stops and says which one is missing.

## Battery level table

The kernel's OCV table (level from the resting cell voltage) is measured on a phone with `battlog/`, a logger that needs no USB connection while it runs. It takes about a day.

Until a measured table is in the kernel, the driver uses a placeholder curve (`oz8806_ocv_generic.h` in patch 0026) and the level is approximate.

1. Charge to full and leave the charger in.
2. Over adb: `adb shell setprop persist.vendor.pocket.battlog 1`, then unplug USB and the charger. The logger starts when the charger is out, and only from 98 % or more.
3. Leave the phone alone with the screen off, at room temperature. It rests for an hour, then runs the CPU for about 5 % of the charge at a time with a 45 minute rest after each, about 20 times, and stops at 3500 mV under load.
4. When `adb shell getprop persist.vendor.pocket.battlog` says `done`, charge it and copy the log: `adb pull /data/misc/pocket_battlog/`. `abort` means the charger went in or it didn't start full; the reason is the last `#` line of the log.
5. `python3 pocket/tools/make-pocket-oz8806-ocv.py pocket_battlog/battlog-*.csv --out KERNEL/drivers/power/supply/oz8806_ocv.h`, with KERNEL the `android_kernel_unihertz_mt6771` clone, then rebuild the kernel. With several logs it takes the newest complete run, and says why it skipped the others.

`setprop persist.vendor.pocket.battlog 0` stops a run. A reboot ends one too, and it doesn't start again by itself.

## Licences

The device tree is Apache-2.0 (`LICENSE`), except files that carry their own header. The kernel patches in `pocket/patches` are GPL-2.0 like the kernel they apply to, and keep the original copyright notices. PocketInput is Apache-2.0 (`PocketInput/LICENSE`).
