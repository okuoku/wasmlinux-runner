#include <stdlib.h>
#include "busybox_base_w2c.h"
#include "glue_modules.h"

struct module_instance__embedded {
    union {
        w2c_busybox__base__w2c i0_busybox_base_w2c;
    } instances;
    const struct wasmlinux_user_module_info* module; /* Sanity */
    const char* types[3];
};

static const struct wasmlinux_user_module_info bundlemods__embedded[] = {
    {"busybox", "xxxxx", 199980, 1024 /* FIXME */, 0}
};

static const struct wasmlinux_user_bundle_info bundleinfo__embedded = {
    bundlemods__embedded,
    sizeof(struct module_instance__embedded),
    1
};

uintptr_t
wasmlinux_modquery__embedded(int cmd, int modidx,
                             uintptr_t ctx, uintptr_t param){
    void* functype;
    struct module_instance__embedded* me;
    me = (struct module_instance__embedded*)(void*)ctx;
    switch(cmd){
        case WASMLINUX_MODQUERY_CMD_BUNDLEINFO:
            return (uintptr_t)&bundleinfo__embedded;
        case WASMLINUX_MODQUERY_CMD_INSTANTIATE:
            me->module = &bundlemods__embedded[modidx];
            switch(modidx){
                case 0:
                    wasm2c_busybox__base__w2c_instantiate(&me->instances.i0_busybox_base_w2c, 0, 0);
                    w2c_busybox__base__w2c_0x5F_wasm_apply_data_relocs(&me->instances.i0_busybox_base_w2c);
                    /* Type extract */
                    me->types[0] = wasm2c_busybox__base__w2c_get_func_type(1, 1, WASM_RT_I32, WASM_RT_I32);
                    me->types[1] = wasm2c_busybox__base__w2c_get_func_type(1, 0, WASM_RT_I32);
                    me->types[2] = wasm2c_busybox__base__w2c_get_func_type(3, 0, WASM_RT_I32, WASM_RT_I32, WASM_RT_I32);
                    break;
                default:
                    abort();
                    break;
            }
            return 0;
        case WASMLINUX_MODQUERY_CMD_RUN_ENTRYPOINT:
            if(me->module->modidx != modidx){
                abort();
            }
            switch(modidx){
                case 0:
                    w2c_busybox__base__w2c_0x5Fstart_c(&me->instances.i0_busybox_base_w2c, param);
                    break;
                default:
                    abort();
                    break;
            }
            return 0;
        case WASMLINUX_MODQUERY_CMD_SET_STACK:
            if(me->module->modidx != modidx){
                abort();
            }
            switch(modidx){
                case 0:
                    me->instances.i0_busybox_base_w2c.w2c_env_0x5F_stack_pointer = (u32*)param;
                    break;
                default:
                    abort();
                    break;
            }
            return 0;
        case WASMLINUX_MODQUERY_CMD_CHECK_TYPE:
            if(me->module->modidx != modidx){
                abort();
            }
            switch(param){
                case WASMLINUX_MODQUERY_TYPE_I_I:
                case WASMLINUX_MODQUERY_TYPE_I_V:
                case WASMLINUX_MODQUERY_TYPE_III_V:
                    return me->types[param];
                default:
                    return -1;
            }
            break;
        default:
            break;
    }
    abort();
    return 0;
}
