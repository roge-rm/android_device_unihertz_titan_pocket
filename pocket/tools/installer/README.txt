LineageOS for the Unihertz Titan Pocket: installer

This puts LineageOS on a Titan Pocket. It erases everything on the phone, so copy off
anything you want to keep first.

What you need
- A Titan Pocket on Unihertz's May 2024 stock release (Titan_pocket_20240514). If yours is
  older, update it with Unihertz's updater first.
- The bootloader unlocked. Unlocking erases the phone too.
- A computer with Linux, macOS or Windows, a USB cable and about 10 GB free: 5 for this
  folder and 5 for the backup.
- Python 3.9 or later: https://www.python.org/downloads/ (on Linux, from your package manager).
- Google's platform-tools (adb and fastboot):
  https://developer.android.com/tools/releases/platform-tools
  Unzip it into this folder, so there is a platform-tools folder next to install.sh, or put it
  on your PATH. On Windows you may also need Google's USB driver for fastboot mode.
- Unihertz's May 2024 firmware zip (2024051420_g66v71c2k_dfl_tee.zip) is good to have. The
  installer only needs it if it has to put stock recovery back.

How to install
1. Charge the phone to at least half.
2. Start it in fastboot mode: with USB debugging on, run "adb reboot bootloader", or let the
   installer do that for you.
3. Run the installer from this folder:
   - Linux: ./install.sh
   - macOS: double-click install.command. If macOS won't open it, right-click it and choose
     Open.
   - Windows: double-click install.bat
4. Follow what it says. It asks before each step that writes to the phone, and before it
   formats data you type "format".
5. When our recovery starts, pick Advanced, then Enable ADB in its menu (the volume keys move,
   the power key picks). The installer waits for that, then goes on by itself. Our recovery
   only lets a computer in over USB after you pick it.

What it does
1. Checks the bootloader is unlocked and that it's a Titan Pocket.
2. Flashes our recovery and starts it. You pick Advanced, Enable ADB there.
3. Checks the stock release. If it isn't May 2024, it stops and puts stock recovery back.
4. Backs up the stock partitions to this computer, in the backups folder. This includes
   nvram, nvdata, nvcfg, protect1, protect2, persist and proinfo, which hold the phone's IMEI,
   Wi-Fi and Bluetooth addresses and calibration. They can't come from anyone else, so keep
   that folder somewhere safe.
5. Changes the phone's own vendor partition for LineageOS. No Unihertz files are in this zip:
   the vendor changes are made to the copy already on your phone.
6. Writes system and product, formats data, then writes boot and vbmeta and restarts. If you
   skip the format, it stops in our recovery instead and says how to finish: format data there
   (Factory reset, Format data/factory reset), go to fastboot mode (Advanced, Reboot to
   bootloader) and run the --finish command it printed.

A log file (.log) is written in the backups folder, next to the backup subfolder. If you
ask for help, send only the log. Never share the backups folder: it holds your IMEI and
calibration data.

If something goes wrong
The installer says what state the phone is in and the command that puts stock back. Run that
command from this folder. The full stock restore, with the phone in our recovery and Advanced,
Enable ADB picked, is:
  python3 tools/pocket-stock-restore.py BACKUP-FOLDER --serial SERIAL --stock-zip PATH/TO/2024051420_g66v71c2k_dfl_tee.zip
(on Windows "py -3" instead of "python3"). If adb and fastboot aren't on your PATH, add
--adb platform-tools/adb --fastboot platform-tools/fastboot. It writes the backup back and
leaves the phone in fastboot mode. Format data in stock recovery before starting stock.

To put only stock recovery back, with the phone in fastboot mode:
  python3 tools/pocket-install.py --put-back-recovery PATH/TO/2024051420_g66v71c2k_dfl_tee.zip
