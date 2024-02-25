#include <stdint.h>

struct wasmlinux_user_module_info {
    const char* modname;
    const char* modid_hex;
    size_t instance_size;
    size_t table_size;
    size_t data_size;
    int modidx;
};

struct wasmlinux_user_bundle_info {
    const struct wasmlinux_user_module_info* mod;
    size_t root_size;
    int modcount;
};

#define WASMLINUX_MODQUERY_CMD_BUNDLEINFO 1
#define WASMLINUX_MODQUERY_CMD_INSTANTIATE 2
#define WASMLINUX_MODQUERY_CMD_RUN_ENTRYPOINT 3
#define WASMLINUX_MODQUERY_CMD_SET_STACK 4
#define WASMLINUX_MODQUERY_CMD_CHECK_TYPE 5

#define WASMLINUX_MODQUERY_TYPE_I_I 0 /* startroutine */
#define WASMLINUX_MODQUERY_TYPE_I_V 1 /* sighandler1 */
#define WASMLINUX_MODQUERY_TYPE_III_V 2 /* sighandler3 */
