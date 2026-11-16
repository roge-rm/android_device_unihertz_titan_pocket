// SPDX-License-Identifier: GPL-2.0-only
// Standalone static probe for inclusion in a separately reviewed RAM-only init.
#include <stdio.h>
#include <sys/sysmacros.h>
#include "feature_query.h"
int main(void)
{
    unsigned major_number, minor_number;
    char tail;
    FILE *stream = fopen("/sys/class/misc/tkcoredrv/dev", "re");
    if (!stream) { fprintf(stderr, "TKCORE_QUERY metadata: %s\n", strerror(errno)); return 1; }
    int fields = fscanf(stream, "%u:%u %c", &major_number, &minor_number, &tail);
    fclose(stream);
    if (fields != 2) { fprintf(stderr, "TKCORE_QUERY invalid device metadata\n"); return 1; }
    struct tp_tkcore_query_result result;
    int rc = tp_tkcore_feature_query(makedev(major_number, minor_number), &result);
    fprintf(stderr, "TKCORE_QUERY rc=%d stage=%d error=%d flags=0x%08x\n",
            rc, result.stage, result.error_number, result.feature_flags);
    return rc ? 1 : 0;
}
