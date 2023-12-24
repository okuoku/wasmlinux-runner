#include <stdlib.h>
#include <stdio.h>

/* Userproc */
#include "user.h"

struct user_instance;
struct user_context {
    struct user_instance* i;
    uint32_t stack;
    w2c_user the_user;
};

struct user_instance {
    struct user_context main_context;
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
typedef uint32_t (*startroutine)(w2c_user*, uint32_t); /* type 1 */
/* signal handlers */
typedef void (*sighandler1)(w2c_user*, uint32_t); /* type 2 */
typedef void (*sighandler3)(w2c_user*, uint32_t, uint32_t, uint32_t); /* type 3 */


void
wasmlinux_user_ctx_new32(struct user_context* cur, uint32_t stack){
    struct user_context* me;

    me = (struct user_context*)malloc(sizeof(struct user_context));
    memcpy(&me->the_user, &cur->i->main_context.the_user, sizeof(w2c_user));
    me->i = cur->i;

    /* Override stack pointer */
    me->stack = stack;
    me->the_user.w2c_env_0x5F_stack_pointer = 
        &me->stack; /* FIXME: is bottom??? */

    /* Begin user context */
    wasmlinux_tls_set_context(me);
}

uint32_t
wasmlinux_user_ctx_exec32(int type, uint32_t func,
                          uint32_t param0, uint32_t param1, uint32_t param2,
                          uint32_t param3){
    struct user_context* cur;
    wasm_rt_funcref_table_t* userfuncs;
    sighandler1 s1;
    sighandler3 s3;
    startroutine st;
    cur = wasmlinux_tls_get_context();
    if(type == 0){
        if(func == 0){
            w2c_user_0x5Fstart_c(&cur->the_user, param0);
        }else{
            abort();
        }
    }else{
        userfuncs = &cur->i->userfuncs;
        switch(type){
            case 1:
                st = (startroutine)userfuncs->data[func].func;
                st(&cur->the_user, param0);
                break;
            case 2:
                s1 = (sighandler1)userfuncs->data[func].func;
                s1(&cur->the_user, param0);
                break;
            case 3:
                s3 = (sighandler3)userfuncs->data[func].func;
                s3(&cur->the_user, param0, param1, param2);
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
    ui = (struct user_instance*)malloc(sizeof(struct user_instance));
    ui->main_context.i = ui;

    ui->main_context.stack = initial_stack;
    ui->userdata = dataptr;

    /* FIXME: calc max size */
    wasm_rt_allocate_funcref_table(&ui->userfuncs, 1024, 1024);

    usertablebase = 0;

    /* Begin user context */
    wasmlinux_tls_set_context(&ui->main_context);

    /* Initialize storage */
    wasm2c_user_instantiate(&ui->main_context.the_user, 0, 0);
    w2c_user_0x5F_wasm_apply_data_relocs(&ui->main_context.the_user);

    return ui;
}

