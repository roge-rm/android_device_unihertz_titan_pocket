# Pocket policy source integration

`system_ext/private/service_contexts` is an original narrow context addition for
stock IMS publication of `mtkIms`, recovered through REA. Add this directory to
`SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS`; it introduces no allow rule or new domain.
The platform already declares `radio_service`. It does not qualify IMS startup.

Do not restore the old `exec_start wait_for_keymaster` operation or copy its
HMAC-negotiation helper into the Android16 startup sequence. Current vold waits
for keystore2's service and obtains its TEE security level. Current keystore2 is
an early-HAL service and owns shared-secret negotiation, including legacy HIDL
Keymaster4.0/4.1 participants. That negotiation is asynchronous; service publication
alone is not proof that all secure operations are ready. Preserve the actual
modern vold/keystore2 retry and failure behavior and validate encrypted boot.

`compat/30.0` describes the explicit source contract for privately generated
compatibility CIL; generated stock-derived rules and policy binaries remain
outside Git. That interface is not automatically enabled by the context directory.
A successful full intended-product enforcing compile is required before wiring
it into installable policy. Never use the old expanded public snapshot as a
modern platform replacement, or enable permissive/neverallow bypasses.

The private source reconstruction now compiles with every neverallow check
enabled against the actual engineering product's platform CIL. Its install-shaped
composition includes the selected 202504 genfs fragment, API30 mapping/compat,
retained vendor/extension rules, and a thin extended-public interface containing
the eleven stock-proven singleton mappings. It imports no old-public grants.
The generated binary is 1,285,320 bytes; this remains a source checkpoint.

`tools/prepare-pocket-policy-source.py` records each source decision and exact
input/compiler hash. Current-owner directory, mount, DRM-descriptor and VFIO
operations are partitioned by owner, target and permission; all other denial
scope remains. Five generic root-label assertions are reconstructed at their
stock singleton identities instead of expanding into unrelated new descendant
labels through forward mappings. Exact stock/current contexts substantiate
these decisions. Current platform assertions remain untouched.

The port also revokes old blanket core reads of vendor-internal default
properties and the obsolete system-server module-loading capability. Existing
typed property grants remain. A missing named property requires a separate
observed/REA-backed typing and consumer contract before hardware qualification.
MLS compatibility is bounded by the selected APK inventory; no app is promoted
to coredomain and all real domains remain declared. Selecting an excluded old
APK reopens that contract.

Two core-app selectors move from vendor to system_ext seapp contexts, preserving
their exact selectors/domains and passing strict vendor checks. Two exact legacy
property names retain their string/integer value contracts with current
fingerprint/telephony owner labels. No new allow is introduced by either move.

`tools/check-pocket-policy-source.py` passes 47 semantic controls.
`tools/check-pocket-policy-contexts.py` builds upstream validators with Android
label backends and the matching modern libsepol; all 15 retained/context/control
checks pass. Generated contexts, CIL, policy binaries and AOSP tools stay private.

Final product qualification is still open: the actual modern product and
system_ext split CIL and merged modern contexts have not finished building and
are absent from this composition. The generated install tree is not installed
or automatically hooked into Soong. File-label priority, package signatures,
encrypted boot and hardware execution remain unqualified. The modern platform
also requests `functionfs_seclabel`, which the current 5.10 policy-capability
headers do not declare; the target-kernel implementation needs a separate review.

`system_ext/` declares the 116 HAL attributes and 14 types that the stock vendor
policy uses but that only the V14 system_ext policy declared, with their file,
property, service and genfs contexts. `prebuilts/api/30.0` holds the 30.0 public
copy and `private/compat/30.0/30.0.cil` maps the Pocket types for vendor API 30;
the other `compat/*.ignore.cil` lists mark them as new objects. The `genfs_contexts`
paths are the stock 4.14 sysfs ones and still need checking under 5.10.

`patches/android/0003-pocket-sepolicy-30.0-mlsvendorcompat.patch` leaves
`mlsvendorcompat` empty, as `domain.te` forbids any member. `tools/run-pocket-product-build.py`
applies it through `tools/stage-pocket-sepolicy-compat.py`. With vendor overlay v2 the
strict and init-flag compiles are identical and every context check passes.
