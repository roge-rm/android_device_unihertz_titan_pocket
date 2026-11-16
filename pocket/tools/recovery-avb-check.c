// SPDX-License-Identifier: MIT
// Host-only, read-only AvbOps over a local image. Does not execute image code.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libavb/libavb.h"

struct image { unsigned char *bytes; size_t size; bool unlocked; unsigned reads; };

static AvbIOResult read_image(AvbOps *ops, const char *name, int64_t offset,
                             size_t count, void *buffer, size_t *read_count) {
    struct image *image = ops->user_data;
    if (strcmp(name, "recovery")) return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
    if (offset < 0) offset += (int64_t)image->size;
    if (offset < 0 || (uint64_t)offset > image->size)
        return AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
    size_t remaining = image->size - (size_t)offset;
    if (count > remaining) count = remaining;
    memcpy(buffer, image->bytes + offset, count);
    *read_count = count;
    image->reads++;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult image_size(AvbOps *ops, const char *name, uint64_t *size) {
    if (strcmp(name, "recovery")) return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
    *size = ((struct image *)ops->user_data)->size;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult unlocked(AvbOps *ops, bool *value) {
    *value = ((struct image *)ops->user_data)->unlocked;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult rollback(AvbOps *ops, size_t location, uint64_t *value) {
    (void)ops; (void)location; *value = 0; return AVB_IO_RESULT_OK;
}

static AvbIOResult guid(AvbOps *ops, const char *name, char *out, size_t size) {
    (void)ops; (void)name;
    const char *synthetic = "00000000-0000-0000-0000-000000000001";
    if (size <= strlen(synthetic)) return AVB_IO_RESULT_ERROR_IO;
    strcpy(out, synthetic);
    return AVB_IO_RESULT_OK;
}

// Synthetic trust for the signed stock control only. This is not OEM trust validation.
static AvbIOResult trust(AvbOps *ops, const uint8_t *key, size_t key_size,
                         const uint8_t *metadata, size_t metadata_size, bool *trusted) {
    (void)ops; (void)key; (void)key_size; (void)metadata; (void)metadata_size;
    *trusted = true;
    return AVB_IO_RESULT_OK;
}

static AvbIOResult partition_trust(AvbOps *ops, const char *name, const uint8_t *key,
                                   size_t key_size, const uint8_t *metadata,
                                   size_t metadata_size, bool *trusted, uint32_t *location) {
    if (strcmp(name, "recovery")) return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
    *location = 0;
    return trust(ops, key, key_size, metadata, metadata_size, trusted);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct image image = {.size = 33554432, .unlocked = strcmp(argv[2], "locked") != 0};
    image.bytes = malloc(image.size);
    FILE *input = fopen(argv[1], "rb");
    if (!input || !image.bytes || fread(image.bytes, 1, image.size, input) != image.size ||
        fgetc(input) != EOF) return 3;
    fclose(input);
    AvbOps ops = {0};
    ops.user_data = &image;
    ops.read_from_partition = read_image;
    ops.get_size_of_partition = image_size;
    ops.read_is_device_unlocked = unlocked;
    ops.read_rollback_index = rollback;
    ops.validate_vbmeta_public_key = trust;
    ops.validate_public_key_for_partition = partition_trust;
    ops.get_unique_guid_for_partition = guid;
    // Every write callback is NULL; host inputs are opened read-only.
    const char *requested[] = {"recovery", NULL};
    AvbSlotVerifyData *result = NULL;
    AvbSlotVerifyFlags flags = AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION;
    if (image.unlocked) flags |= AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR;
    AvbSlotVerifyResult status = avb_slot_verify(&ops, requested, "", flags,
                                                AVB_HASHTREE_ERROR_MODE_EIO, &result);
    bool equal = false;
    if (result && result->num_loaded_partitions == 1) {
        AvbPartitionData *part = &result->loaded_partitions[0];
        equal = part->data_size <= image.size &&
                !memcmp(part->data, image.bytes, part->data_size);
    }
    printf("{\"status\":\"%s\",\"slot_data\":%s,\"loaded_partitions\":%zu,"
           "\"loaded_bytes_match\":%s,\"reads\":%u,\"write_callbacks\":0}\n",
           avb_slot_verify_result_to_string(status), result ? "true" : "false",
           result ? result->num_loaded_partitions : 0, equal ? "true" : "false", image.reads);
    if (result) avb_slot_verify_data_free(result);
    free(image.bytes);
    return 0;
}
