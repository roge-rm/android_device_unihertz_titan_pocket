// SPDX-License-Identifier: Apache-2.0
// Loaded into /vendor/bin/teed as its first DT_NEEDED (vendor overlay v13).
// teed sends ro.product.brand, ro.product.model and ro.board.platform to TKCore,
// which compares them byte for byte with its licence. Our build's model is
// "Titan Pocket", so this answers the stock "Titan pocket" for ro.product.model
// and passes every other name to libc's __system_property_get.
//
// teed is the main executable and this is its first DT_NEEDED, so this
// definition comes before libc's for teed and every library it loads. LD_PRELOAD
// can't be used: the tee domain has no noatsecure, so bionic drops it.

#include <dlfcn.h>
#include <string.h>
#include <sys/system_properties.h>

#define MODEL_NAME "ro.product.model"
#define STOCK_MODEL "Titan pocket"

typedef int (*get_fn)(const char *, char *);

static get_fn real_get;

// Runs after libc's constructors and before teed's, while teed is single-threaded.
__attribute__((constructor)) static void pocket_teed_init(void)
{
    real_get = (get_fn)dlsym(RTLD_NEXT, "__system_property_get");
    if (real_get == __system_property_get)
        real_get = NULL;
}

struct copy_out {
    char *value;
    int len;
};

static void copy_value(void *cookie, const char *name, const char *value, unsigned serial)
{
    struct copy_out *out = cookie;
    (void)name;
    (void)serial;
    size_t n = strlen(value);
    if (n >= PROP_VALUE_MAX)
        n = PROP_VALUE_MAX - 1;
    memcpy(out->value, value, n);
    out->value[n] = '\0';
    out->len = (int)n;
}

int __system_property_get(const char *name, char *value)
{
    if (strcmp(name, MODEL_NAME) == 0) {
        memcpy(value, STOCK_MODEL, sizeof(STOCK_MODEL));
        return (int)sizeof(STOCK_MODEL) - 1;
    }
    if (real_get)
        return real_get(name, value);
    // Only if dlsym failed: the same lookup libc does.
    struct copy_out out = {value, 0};
    value[0] = '\0';
    const prop_info *pi = __system_property_find(name);
    if (pi)
        __system_property_read_callback(pi, copy_value, &out);
    return out.len;
}
