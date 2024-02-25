#include <stdlib.h>
#include <stdio.h>

/* Userproc */
#include "wasm-rt.h"
#include "glue_modules.h"
uintptr_t wasmlinux_modquery__embedded(int cmd, int modidx, uintptr_t ctx, uintptr_t param);

struct user_instance;
struct user_context {
    struct user_instance* i;
    void* modulectx;
    /* for wasm2c module */
    uint32_t stack;
};

struct user_instance {
    struct user_context main_context;
    size_t ctxsize;
    /* for wasm2c module */
    wasm_rt_funcref_table_t userfuncs;
    uint32_t userdata;
};

uint32_t usertablebase;
void wasmlinux_tls_set_context(struct user_context* ctx);
struct user_context* wasmlinux_tls_get_context(void);

/* Wasm2c instance data */
uint32_t*
w2c_env_0x5F_table_base(struct w2c_env* bogus){
    return &usertablebase;
}

uint32_t*
w2c_env_0x5F_memory_base(struct w2c_env* bogus){
    struct user_context* cur;
    cur = wasmlinux_tls_get_context();
    return &cur->i->userdata;
}

uint32_t*
w2c_env_0x5F_stack_pointer(struct w2c_env* bogus){
    struct user_context* cur;
    cur = wasmlinux_tls_get_context();
    return &cur->stack;
}

wasm_rt_funcref_table_t*
w2c_env_0x5F_indirect_function_table(struct w2c_env* bogus){
    struct user_context* cur;
    cur = wasmlinux_tls_get_context();
    return &cur->i->userfuncs;
}


void* /* => module */
wasmlinux_user_module_load(void* bogus, unsigned char* modid, size_t len){
    /* UNIMPL */
    return 0;
}


/* type == 0 for admin */
/* 0: w2c_user_0x5Fstart_c(my_user, envblock); */
/* thread start routine */
typedef uint32_t (*startroutine)(void*, uint32_t); /* type 1(I_I) */
/* signal handlers */
typedef void (*sighandler1)(void*, uint32_t); /* type 2(I_V) */
typedef void (*sighandler3)(void*, uint32_t, uint32_t, uint32_t); /* type 3(III_V) */

void
wasmlinux_user_ctx_new32(struct user_context* cur, uint32_t stack){
    struct user_context* me;

    me = (struct user_context*)malloc(sizeof(struct user_context));
    me->modulectx = malloc(cur->i->ctxsize);
    memcpy(me->modulectx, cur->i->main_context.modulectx, cur->i->ctxsize);
    me->i = cur->i;

    /* Override stack pointer */
    me->stack = stack; /* FIXME: is bottom??? */
    wasmlinux_modquery__embedded(WASMLINUX_MODQUERY_CMD_SET_STACK, 0,
                                 (uintptr_t)me->modulectx, (uintptr_t)&me->stack);

    /* Begin user context */
    wasmlinux_tls_set_context(me);
}

uint32_t
wasmlinux_user_ctx_exec32(int type, uint32_t func,
                          uint32_t param0, uint32_t param1, uint32_t param2,
                          uint32_t param3){
    uintptr_t func_type;
    uintptr_t actual_type;
    uintptr_t alt_type;
    struct user_context* cur;
    wasm_rt_funcref_table_t* userfuncs;
    sighandler1 s1;
    sighandler3 s3;
    startroutine st;
    cur = wasmlinux_tls_get_context();
    if(type == 0){
        if(func == 0){
            wasmlinux_modquery__embedded(WASMLINUX_MODQUERY_CMD_RUN_ENTRYPOINT,
                                         0, (uintptr_t)cur->modulectx, param0);
        }else{
            abort();
        }
    }else{
        actual_type = wasmlinux_modquery__embedded(WASMLINUX_MODQUERY_CMD_CHECK_TYPE,
                                                   0, (uintptr_t)cur->modulectx, type - 1);
        userfuncs = &cur->i->userfuncs;
        func_type = (uintptr_t)userfuncs->data[func].func_type;
        switch(type){
            case 1: /* Type 0 */
                st = (startroutine)userfuncs->data[func].func;
                if(func_type != actual_type){
                    printf("WARNING: Func type mismatch st!! %p != %p, %d\n", func_type, actual_type, func);
                }
                st(cur->modulectx, param0);
                break;
            case 2: /* Type 1 */
                s1 = (sighandler1)userfuncs->data[func].func;
                if(func_type != actual_type){
                    printf("WARNING: Func type mismatch s1!! %p != %p, %d (%p)\n", func_type, actual_type, func, s1);
                    alt_type = wasmlinux_modquery__embedded(WASMLINUX_MODQUERY_CMD_CHECK_TYPE,
                                                            0, (uintptr_t)cur->modulectx, WASMLINUX_MODQUERY_TYPE_III_V);
                    if(alt_type == func_type){
                        printf("Calling with alt type %p\n", alt_type);
                        s3 = (sighandler3)userfuncs->data[func].func;
                        s3(cur->modulectx, param0, 0, 0);
                    }else{
                        printf("No match alt type %p\n", alt_type);
                    }
                }else{
                    s1(cur->modulectx, param0);
                }
                break;
            case 3: /* Type 2 */
                s3 = (sighandler3)userfuncs->data[func].func;
                if(func_type != actual_type){
                    printf("WARNING: Func type mismatch s3!! %p != %p, %d\n", func_type, actual_type, func);
                }
                s3(cur->modulectx, param0, param1, param2);
                break;
            default:
                abort();
                break;
        }
    }
    return 0;
}

struct user_instance*
wasmlinux_user_module_instantiate32(void* bogus, 
                                    uint32_t dataptr, uint32_t initial_stack){
    struct user_instance* ui;
    size_t table_size;
    /* FIXME: Resolve this on load */
    const struct wasmlinux_user_bundle_info* bi;
    bi = (const struct wasmlinux_user_bundle_info*)
        wasmlinux_modquery__embedded(WASMLINUX_MODQUERY_CMD_BUNDLEINFO,
                                     0, 0, 0);


    ui = (struct user_instance*)malloc(sizeof(struct user_instance));
    ui->main_context.i = ui;
    ui->ctxsize = bi->mod[0].instance_size;
    ui->main_context.modulectx = malloc(ui->ctxsize);

    /* Fill in initial data */
    ui->main_context.stack = initial_stack;
    ui->userdata = dataptr;

    table_size = bi->mod[0].table_size;
    wasm_rt_allocate_funcref_table(&ui->userfuncs, table_size, table_size);

    usertablebase = 0;

    /* Begin user context */
    wasmlinux_tls_set_context(&ui->main_context);

    /* Initialize storage */
    wasmlinux_modquery__embedded(WASMLINUX_MODQUERY_CMD_INSTANTIATE, 0,
                                 (uintptr_t)ui->main_context.modulectx, 0);

    return ui;
}

