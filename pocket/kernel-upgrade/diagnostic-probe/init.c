// SPDX-License-Identifier: GPL-2.0-only
// First 5.10 diagnostic: RAM-only USB log stream and bounded return request.
#define PROBE_LABEL "TP510-RAM"
#define PROBE_PRODUCT "Titan Pocket 5.10 RAM diagnostic"
#define PROBE_RETURN_SECONDS 120
#include "../ram-probe/init.c"
