#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Stands in for make_recovery_patch in the target-files build (Android.mk). It would put
# recovery.img and install-recovery.sh in vendor, but vendor is a prebuilt image that this build
# doesn't make and OTAs don't write. releasetools.py writes recovery.img in the OTA instead.
exit 0
