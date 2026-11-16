# SPDX-License-Identifier: Apache-2.0
"""Titan Pocket OTA steps: full non-A/B OTAs that keep the phone's own vendor partition.

Vendor stays the partition the installer wrote (May 2024 stock plus our overlay). OTAs never
carry vendor.img; they carry our own files and edits of the stock ones
(RADIO/pocket_vendor_overlay.zip, from tools/prepare-pocket-vendor-ota.py) and
ota/pocket_vendor.sh applies them:
  1. InstallBegin, before anything is written: check every overlay file is the overlay
     version or one it accepts (stock or an earlier overlay), the edits rebuild and the stock
     release is May 2024 or newer, else abort. Then write the overlay, before system, since
     the overlay vendor also runs the older system and a new system needs the new vendor
     (the teed shim).
  2. System and product are resized in the phone's super metadata and written as blocks.
     The generic full OTA removes every dynamic partition and adds them again, which would
     lose vendor, so DynamicPartitionsDifference is replaced for this OTA.
  3. InstallEnd: recovery is written here, as there's no recovery patch in vendor, and
     backuptool restore runs again after the boot write, so addon.d scripts like Magisk's
     patch the new boot.
"""
import json
import logging

import common
import non_ab_ota

logger = logging.getLogger(__name__)

PAYLOAD = "RADIO/pocket_vendor_overlay.zip"
SCRIPTS = ("pocket_vendor.sh", "pocket_addond.sh")
TMP = "/tmp/pocket"
# The stock cache partition, in bytes. Block OTAs size their transfers by it. misc_info.txt
# only gets cache_size when a cache image is built, and the product doesn't build one.
CACHE_BYTES = 452984832
_HasRecoveryPatch = non_ab_ota.HasRecoveryPatch


def _HasRecoveryPatchOrOurs(target_files_zip, info_dict):
  # Vendor is prebuilt, so there's no recovery patch in it; FullOTA_InstallEnd writes
  # recovery.img instead.
  return (PAYLOAD in target_files_zip.namelist() or
          _HasRecoveryPatch(target_files_zip, info_dict))


non_ab_ota.HasRecoveryPatch = _HasRecoveryPatchOrOurs


class KeepVendorPartitions(object):
  """Stands in for common.DynamicPartitionsDifference in a full OTA.

  Resizes the partitions it writes in their existing groups and leaves vendor, its group
  and its extents as they are on the phone. The phone's group is stock's "main", not the
  build's, so no group is named.
  """

  def __init__(self, info_dict, block_diffs, progress_dict=None,
               source_info_dict=None):
    assert source_info_dict is None, "full OTAs only"
    self._diffs = list(block_diffs)
    self._progress = progress_dict or {}
    names = set(d.partition for d in self._diffs)
    want = set(info_dict["dynamic_partition_list"].split()) - {"vendor"}
    assert names == want, "block diffs {} for dynamic partitions {}".format(
        sorted(names), sorted(want))
    sizes = sum(self._Size(d) for d in self._diffs) + _vendor_bytes
    for g in info_dict.get("super_partition_groups", "").split():
      limit = int(info_dict["super_%s_group_size" % g])
      assert sizes <= limit, "system, product and vendor need {} bytes, group holds {}".format(
          sizes, limit)

  @staticmethod
  def _Size(diff):
    return diff.tgt.blocksize * diff.tgt.total_blocks

  def WriteScript(self, script, output_zip, write_verify_script=False):
    script.Comment("--- Resize system and product, keep vendor ---")
    # Both go to 0 first, so growing one can use what the other gave back.
    ops = ["# Pocket: vendor is not touched"]
    ops += ["resize %s 0" % d.partition for d in self._diffs]
    ops += ["resize %s %d" % (d.partition, self._Size(d)) for d in self._diffs]
    common.ZipWriteStr(output_zip, "dynamic_partitions_op_list", "\n".join(ops) + "\n")
    # No super_empty fallback: writing fresh metadata would lose vendor.
    script.AppendExtra('assert(update_dynamic_partitions('
                       'package_extract_file("dynamic_partitions_op_list")));')
    for d in self._diffs:
      d.WriteScript(script, output_zip, progress=self._progress.get(d.partition),
                    write_verify_script=write_verify_script)
      if write_verify_script:
        script.AppendExtra('unmap_partition("%s");' % d.partition)


_vendor_bytes = 0


def _Payload(info):
  if PAYLOAD not in info.input_zip.namelist():
    raise ValueError(PAYLOAD + " is missing from target-files")
  for s in SCRIPTS:
    if "RADIO/" + s not in info.input_zip.namelist():
      raise ValueError("RADIO/" + s + " is missing from target-files")
  return common.File(PAYLOAD, info.input_zip.read(PAYLOAD))


def FullOTA_Assertions(info):
  global _vendor_bytes
  import io
  import zipfile
  with zipfile.ZipFile(io.BytesIO(_Payload(info).data)) as z:
    manifest = json.loads(z.read("manifest.json"))
  # The phone's vendor partition is the stock or the overlay image, whichever is larger.
  _vendor_bytes = max(manifest["base"]["bytes"], manifest["overlay"]["bytes"])
  common.DynamicPartitionsDifference = KeepVendorPartitions
  if common.OPTIONS.cache_size is None:
    common.OPTIONS.cache_size = CACHE_BYTES


def _PublicManifest(data):
  """manifest.json without the paths of the private images it was made from.

  Their hashes and sizes stay. The phone script reads manifest.txt, not this.
  """
  manifest = json.loads(data)
  for key in ("base", "overlay"):
    if isinstance(manifest.get(key), dict):
      manifest[key].pop("path", None)
  return json.dumps(manifest, indent=2) + "\n"


def FullOTA_InstallBegin(info):
  import io
  import zipfile
  payload = _Payload(info)
  with zipfile.ZipFile(io.BytesIO(payload.data)) as z:
    for name in z.namelist():
      if name == "manifest.json":
        common.ZipWriteStr(info.output_zip, "pocket/payload/" + name, _PublicManifest(z.read(name)))
      elif not name.endswith("/"):
        common.ZipWriteStr(info.output_zip, "pocket/payload/" + name, z.read(name))
  for s in SCRIPTS:
    common.ZipWriteStr(info.output_zip, "pocket/" + s, info.input_zip.read("RADIO/" + s))

  script = info.script
  script.Print("Checking vendor...")
  script.AppendExtra('package_extract_dir("pocket", "%s");' % TMP)
  for s in SCRIPTS:
    script.AppendExtra('set_metadata("%s/%s", "uid", 0, "gid", 0, "mode", 0755);' % (TMP, s))
  vendor = 'map_partition("vendor")'
  script.AppendExtra(
      'run_program("%s/pocket_vendor.sh", "check", %s, "%s/payload") == "0" || '
      'abort("E3001: vendor is not the May 2024 stock or our overlay, see /tmp/recovery.log");'
      % (TMP, vendor, TMP))
  script.Print("Writing vendor overlay...")
  script.AppendExtra(
      'run_program("%s/pocket_vendor.sh", "apply", %s, "%s/payload") == "0" || '
      'abort("E3002: vendor overlay write failed, see /tmp/recovery.log");'
      % (TMP, vendor, TMP))

  # backuptool restore deletes the addon.d scripts and backup it ran from, so keep links to
  # them for the second restore in FullOTA_InstallEnd.
  run_backup = script.RunBackup

  def RunBackupKeepingState(command, dynamic=False):
    if command == "restore":
      script.AppendExtra(
          'run_program("%s/pocket_addond.sh", "save") == "0" || '
          'abort("E3005: addon.d state could not be kept, boot is not written");' % TMP)
    run_backup(command, dynamic)

  script.RunBackup = RunBackupKeepingState
  script.pocket_run_backup = run_backup


def FullOTA_InstallEnd(info):
  script = info.script
  script.Print("Writing recovery...")
  script.WriteRawImage("/recovery", "recovery.img")
  if common.OPTIONS.backuptool:
    # After the boot write, so addon.d scripts patch the new boot.
    script.AppendExtra(
        'run_program("%s/pocket_addond.sh", "load") == "0" || '
        'abort("E3003: addon.d state was not kept");' % TMP)
    script.pocket_run_backup("restore", info.info_dict.get("use_dynamic_partitions") == "true")
    script.AppendExtra('run_program("%s/pocket_addond.sh", "clean");' % TMP)


def IncrementalOTA_Assertions(info):
  raise ValueError("Titan Pocket builds make full OTAs only")
