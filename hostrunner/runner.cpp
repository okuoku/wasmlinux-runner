#define YUNI_W2C_FIXUP_WASMLINUX_USER /* Remove this */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "mplite.h"

#include <setjmp.h>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <semaphore>

/* Pseudo inetd */
#include "miniio.h"
const int TELNET_PORT = 5666;

/* Kernel */
#include "kernel.h"
w2c_kernel the_linux;
thread_local w2c_kernel* my_linux;

/* User */
struct user_instance;
struct user_context;
thread_local struct user_context* my_user;

extern "C" void
wasmlinux_tls_set_context(struct user_context* ctx){
    my_user = ctx;
}

extern "C" struct user_context*
wasmlinux_tls_get_context(void){
    return my_user;
}

extern "C" {
    void wasmlinux_user_ctx_new32(struct user_context* cur, uint32_t stack);
    uint32_t wasmlinux_user_ctx_exec32(int type, uint32_t func, uint32_t param0, uint32_t param1, uint32_t param2, uint32_t param3);
    struct user_instance* wasmlinux_user_module_instantiate32(void* bogus, uint32_t dataptr, uint32_t initial_stack);
};

/* Pool management */
uint8_t* mpool_base;
mplite_t mpool;
std::mutex mtxpool;

static int
pool_acquire(void* bogus){
    (void) bogus;
    mtxpool.lock();
    return 0;
}

static int
pool_release(void* bogus){
    (void) bogus;
    mtxpool.unlock();
    return 0;
}
const mplite_lock_t mpool_lockimpl = {
    .arg = 0,
    .acquire = pool_acquire,
    .release = pool_release,
};

void*
pool_alloc(uintptr_t size){
    return mplite_malloc(&mpool, size);
}

void
pool_free(void* ptr){
    mplite_free(&mpool, ptr);
}

uint32_t
pool_lklptr(void* ptr){
    return (uintptr_t)((uint8_t*)ptr - mpool_base);
}

void*
pool_hostptr(uint32_t offs){
    return mpool_base + (uintptr_t)offs;
}


/* Objmgr */
enum objtype{
    OBJTYPE_DUMMY = 0,
    OBJTYPE_FREE = 1,
    OBJTYPE_SEM = 2,
    OBJTYPE_MUTEX = 3,
    OBJTYPE_RECURSIVE_MUTEX = 4,
    OBJTYPE_THREAD = 5,
    OBJTYPE_TIMER = 6
};

struct hostobj_s {
    enum objtype type;
    int id;
    union {
        std::counting_semaphore<>* sem;
        std::mutex* mtx;
        std::recursive_mutex* mtx_recursive;
        struct {
            uintptr_t func32;
            uintptr_t arg32;
            uintptr_t ret;
            std::thread* thread;
        } thr;
        struct {
            uint64_t wait_for;
            uintptr_t func32;
            uintptr_t arg32;
            std::condition_variable* cv;
            std::mutex* mtx;
            std::thread* thread;
            int running;
        } timer;
    } obj;
};

#define MAX_HOSTOBJ 4096
#define MAX_MYTLS 128
std::mutex objmtx;
struct hostobj_s objtbl[MAX_HOSTOBJ];
thread_local uint32_t mytls[MAX_MYTLS];
thread_local int my_thread_objid;

static int
newobj(objtype type){
    std::lock_guard<std::mutex> NN(objmtx);
    int i;
    for(i=0;i!=MAX_HOSTOBJ;i++){
        if(objtbl[i].type == OBJTYPE_FREE){
            objtbl[i].type = type;
            return i;
        }
    }
    abort();
}

static void
delobj(int idx){
    objtbl[idx].type = OBJTYPE_FREE;
}

/* Kernel TLS */
typedef uint32_t (*funcptr)(w2c_kernel*, uint32_t);
typedef void (*funcptr_void)(w2c_kernel*, uint32_t);
typedef void (*funcptr_cont)(w2c_kernel*);

static funcptr
getfunc(int idx){
    void* p;
    //printf("Converting %d ...", idx);
    if(idx >= the_linux.w2c_T0.size){
        abort();
    }
    p = (void*)the_linux.w2c_T0.data[idx].func;
    //printf(" %p\n", p);
    return (funcptr)p;
}

static funcptr_cont
getfunc_cont(int idx){
    void* p;
    //printf("Converting %d ...", idx);
    if(idx >= the_linux.w2c_T0.size){
        abort();
    }
    p = (void*)the_linux.w2c_T0.data[idx].func;
    //printf(" %p\n", p);
    return (funcptr_cont)p;
}

struct {
    uint32_t func32_destructor;
    int used;
} tlsstate[MAX_MYTLS];

std::mutex tlsidmtx;

static uint32_t /* Key */
thr_tls_alloc(uint32_t destructor){
    std::lock_guard<std::mutex> NN(tlsidmtx);
    int i;
    /* Don't return 0 as TLS key */
    for(i=1;i!=MAX_MYTLS;i++){
        if(tlsstate[i].used == 0){
            tlsstate[i].used = 1;
            tlsstate[i].func32_destructor = destructor;
            return i;
        }
    }
    abort();
    return 0; /* unreachable */
}

static void
thr_tls_free(uint32_t key){
    std::lock_guard<std::mutex> NN(tlsidmtx);
    if(key >= MAX_MYTLS){
        abort();
    }
    tlsstate[key].used = 0;
}

static uint32_t
thr_tls_get(uint32_t key){
    if(key >= MAX_MYTLS){
        abort();
    }
    printf("TLS[%d]: %d -> %x\n",my_thread_objid,key,mytls[key]);
    return mytls[key];
}

static uint32_t
thr_tls_set(uint32_t key, uint32_t data){
    if(key >= MAX_MYTLS){
        abort();
    }
    mytls[key] = data;
    return 0;
}

static void
thr_tls_cleanup(void){
    int i,runloop;
    funcptr f;
    runloop = 1;
    while(runloop){
        runloop = 0;
        for(i=0;i!=MAX_MYTLS;i++){
            if(mytls[i] != 0){
                std::lock_guard<std::mutex> NN(tlsidmtx);
                uint32_t funcid;
                funcid = tlsstate[i].func32_destructor;
                if(funcid != 0){
                    f = getfunc(objtbl[funcid].obj.thr.func32);
                    if(f){
                        (void)f(my_linux, mytls[i]);
                    }else{
                        printf("???: TLS destructor %d did not found.\n", objtbl[funcid].obj.thr.func32);
                    }
                    mytls[i] = 0;
                    runloop = 1;
                }
            }
        }
    }
}


/* Kernel <-> User */
#include "kernel_data/syscalls.h"

#define LKL_SYSCALL_MAX 500

static int syscall_argc_tbl[LKL_SYSCALL_MAX];

static void
init_syscall_argc_table(void){
    int i;
    for(i=0;i!=LKL_SYSCALL_MAX;i++){
        syscall_argc_tbl[i] = -1;
    }
#define SYSCALL_ARGC(sym, argc) syscall_argc_tbl[sym] = argc;
#include "kernel_data/syscall_argc.h"
#include "kernel_data/syscall_argc_fixup.h"
#undef SYSCALL_ARGC
}

const uint64_t WASM_PAGE_SIZE = (64*1024);

#define LKL_SIGCHLD 17
#define LKL_CSIGNAL 0x000000ff
#define LKL_CLONE_NEWTIME 0x00000080
#define LKL_CLONE_VM 0x00000100
#define LKL_CLONE_FS 0x00000200
#define LKL_CLONE_FILES 0x00000400
#define LKL_CLONE_SIGHAND 0x00000800
#define LKL_CLONE_PIDFD 0x00001000
#define LKL_CLONE_PTRACE 0x00002000
#define LKL_CLONE_VFORK 0x00004000
#define LKL_CLONE_PARENT 0x00008000
#define LKL_CLONE_THREAD 0x00010000
#define LKL_CLONE_NEWNS 0x00020000
#define LKL_CLONE_SYSVSEM 0x00040000
#define LKL_CLONE_SETTLS 0x00080000
#define LKL_CLONE_PARENT_SETTID 0x00100000
#define LKL_CLONE_CHILD_CLEARTID 0x00200000
#define LKL_CLONE_DETACHED 0x00400000
#define LKL_CLONE_UNTRACED 0x00800000
#define LKL_CLONE_CHILD_SETTID 0x01000000
#define LKL_CLONE_NEWCGROUP 0x02000000
#define LKL_CLONE_NEWUTS 0x04000000
#define LKL_CLONE_NEWIPC 0x08000000
#define LKL_CLONE_NEWUSER 0x10000000
#define LKL_CLONE_NEWPID 0x20000000
#define LKL_CLONE_NEWNET 0x40000000
#define LKL_CLONE_IO 0x80000000

static void
prepare_newthread(void){
    int idx;
    /* Allocate initial thread */
    memset(mytls, 0, sizeof(mytls));
    idx = newobj(OBJTYPE_THREAD);
    objtbl[idx].obj.thr.func32 = 0;
    objtbl[idx].obj.thr.arg32 = 0;
    objtbl[idx].obj.thr.thread = nullptr;
    my_thread_objid = idx;
}

static uint32_t
newtask_process(void){
    uint32_t flags = LKL_CLONE_VM | LKL_SIGCHLD;
    return w2c_kernel_taskmgmt(my_linux, 4, flags, 0, 0);
}

static uint32_t
newtask_thread(void){
    return w2c_kernel_taskmgmt(my_linux, 2, 0, 0, 0);
}

thread_local uint32_t current_process_ctx;
static void
newtask_apply(uint32_t ctx){
    current_process_ctx = ctx;
    w2c_kernel_taskmgmt(my_linux, 3, ctx, 0, 0);
}

std::mutex instancemtx;
static void
newinstance(){
    wasm_rt_memory_t* mem;
    wasm_rt_funcref_t* newfuncref;
    uint32_t i;
    w2c_kernel* me;
    uint64_t currentpages;
    const uint64_t STACK_PAGES = 10;
    const uint64_t STACK_SIZE = STACK_PAGES * WASM_PAGE_SIZE;
    std::lock_guard<std::mutex> NN(instancemtx);

    /* Allocate thread stack (10 pages = 160KiB) */
    // FIXME: Insert guard page
    // FIXME: Leaks stack memory and instance
    mem = &the_linux.w2c_memory;
    currentpages = wasm_rt_grow_memory(mem, STACK_PAGES);

    /* Allocate new instance */
    me = (w2c_kernel*)malloc(sizeof(w2c_kernel));
    newfuncref = (wasm_rt_funcref_t*)malloc(sizeof(wasm_rt_funcref_t)*the_linux.w2c_T0.size);
    memcpy(newfuncref, the_linux.w2c_T0.data, sizeof(wasm_rt_funcref_t)*the_linux.w2c_T0.size);
    for(i=0;i!=the_linux.w2c_T0.size;i++){
        newfuncref[i].module_instance = me;
    }

    memcpy(me, &the_linux, sizeof(w2c_kernel));
    me->w2c_0x5F_stack_pointer = (currentpages + STACK_PAGES) * WASM_PAGE_SIZE - 256 /* Red zone + 128(unused) */;
    me->w2c_T0.max_size = me->w2c_T0.size;
    me->w2c_T0.data = newfuncref;
    //printf("New stack pointer = %d\n", me->w2c_0x5F_stack_pointer);

    my_linux = me;
}

static void
handlesignal(void){
    int i;
    uint32_t* buf;
    uint32_t sh;
    uint32_t ptr0;
    uint32_t ptr1;
    uint32_t ptr2;
    buf = (uint32_t*)pool_alloc(128*4);
    ptr0 = pool_lklptr(buf);
    memset(buf, 0, 128*4);
    w2c_kernel_taskmgmt(my_linux, 5, ptr0, 0, 0);
    for(i=0;i!=13;i++){
        printf("[%03d]: 0x%08x %d\n", i, buf[i], buf[i]);
    }

    /* Call signal handler */
    ptr1 = ptr0 + 16; /* top of siginfo */
    ptr2 = 0; /* ucontext_t */
    sh = buf[0];
    if(buf[1] & 4 /* SA_SIGINFO */){
        (void) wasmlinux_user_ctx_exec32(3 /* sighandler3 */, sh,
                                         buf[12 /* sig */], ptr1, ptr2, 0);
    }else{
        (void) wasmlinux_user_ctx_exec32(1 /* sighandler1 */, sh,
                                         buf[12 /* sig */], 0, 0, 0);
    }

    pool_free(buf);
}


static uint32_t
create_envblock_frompool(const uint32_t argv[], const uint32_t envp[]){
    size_t argc, envc;
    size_t o, s, arrsize, total, argtotal, envpoff, envptotal;
    int i;
    uint32_t ptr0;
    uint32_t* a;
    const char* x;
    char* buf;
    /* [0] argc = envblock
     * [1] argv(0)
     * [2] argv(1)
     *   :
     * [argc] argv(argc) = 0
     * [argc+1] envp */

    /* Pass1: Calc bufsize */
    i = 0;
    argc = 0;
    argtotal = 0;
    arrsize = 1; /* argc */
    while(argv[i]){
        argc++;
        x = (const char*)pool_hostptr(argv[i]);
        argtotal += strnlen(x, 1024*1024);
        argtotal ++; /* NUL */
        i++;
    }
    arrsize += i+1 /* terminator */;
    envpoff = i+2;
    i = 0;
    envptotal = 0;
    envc = 0;
    while(envp[i]){
        x = (const char*)pool_hostptr(envp[i]);
        envptotal +=strnlen(x, 1024*1024);
        envptotal ++; /* NUL */
        i++;
        envc++;
    }
    arrsize += i+1; /* terminator */

    total = arrsize*4 + argtotal + envptotal;
    buf = (char*)pool_alloc(total);
    ptr0 = pool_lklptr(buf);
    memset(buf, 0, total);

    /* Pass2: Fill buffer */
    o = arrsize*4; /* offset to argv buffer */
    a = (uint32_t*)buf;
    a[0] = argc;
    for(i=0;i!=argc;i++){
        a[i+1] = pool_lklptr(buf + o); /* argv* */
        x = (const char*)pool_hostptr(argv[i]);
        s = strnlen(x, 1024*1024);
        memcpy(buf + o, x, s);
        o += (s + 1); /* NUL */
    }
    a = &a[envpoff];
    for(i=0;i!=envc;i++){
        a[i] = pool_lklptr(buf + o);
        x = (const char*)pool_hostptr(envp[i]);
        s = strnlen(x, 1024*1024);
        memcpy(buf + o, x, s);
        o += (s + 1); /* NUL */
    }
    printf("argc,envc = %ld,%ld\n",argc,envc);
    return ptr0;
}


struct vfork_ctx {
    jmp_buf* jb;
    w2c_kernel* parent_kernel_ctx;
    uint32_t parent_process_ctx;
    uint32_t child_process_ctx;
};

class thr_exit {};

thread_local struct vfork_ctx* vfork_ctx;

static void
thr_user_vfork(w2c_kernel* kern, uint32_t procctx, uint32_t envblock){
    struct user_instance* ui;
    void* puserdata;
    void* puserstack;
    uint32_t userdata, userstack;
    uint32_t ret;
    const size_t STACK_SIZE = 1024*1024;

    /* Instantiate and assign user module */
    puserdata = pool_alloc(199980 /* FIXME */);
    puserstack = pool_alloc(STACK_SIZE);
    userdata = pool_lklptr(puserdata);
    userstack = pool_lklptr(puserstack);
    ui = wasmlinux_user_module_instantiate32(0, userdata, userstack + STACK_SIZE); 

    vfork_ctx = 0;

    /* Allocate linux thread context */
    my_linux = kern;
    prepare_newthread();

    /* Assign process ctx */
    newtask_apply(procctx);

    /* Run usercode */
    try {
        (void) wasmlinux_user_ctx_exec32(0 /* admin */,
                                         0 /* entrypoint */, envblock,
                                         0, 0, 0);
    } catch (thr_exit &req) {
        printf("Exiting thread(main thread).\n");
    }
    thr_tls_cleanup();
    pool_free(puserdata); // FIXME: Should move to module instance
    pool_free(puserstack);
    pool_free(pool_hostptr(envblock));

}

extern "C" int /* exported to w2c user */
wasmlinux_run_to_execve(jmp_buf* jb){
    uint32_t procctx;

    vfork_ctx = (struct vfork_ctx*)malloc(sizeof(struct vfork_ctx));
    vfork_ctx->jb = jb;
    vfork_ctx->parent_kernel_ctx = my_linux;
    vfork_ctx->parent_process_ctx = current_process_ctx;

    procctx = newtask_process();
    printf("procctx = %d\n", procctx);

    /* Switch to new kernel instance */
    newinstance();
    newtask_apply(procctx);

    return 0;
}

uint32_t runsyscall32(uint32_t no, uint32_t nargs, uint32_t in);
uint32_t
emul_execve(uint32_t nargs, uint32_t in){
    jmp_buf* jb;
    uint32_t mypid;
    uint32_t procctx;
    uint32_t stack;
    uint32_t* args;
    uint32_t* argv;
    uint32_t* envp;
    uint32_t envblock;
    w2c_kernel* newkernel;
    std::thread* thr;
    args = (uint32_t*)pool_hostptr(in);

    if(!vfork_ctx){
        /* FIXME: Replace current image */
        printf("not implemented.\n");
        abort();
    }
    mypid = runsyscall32(172 /* __NR_getpid */, 0, 0);

    /* Restore back to parent context */
    newkernel = my_linux;
    my_linux = vfork_ctx->parent_kernel_ctx;
    procctx = current_process_ctx;
    newtask_apply(vfork_ctx->parent_process_ctx);

    /* Instantiate user code */

    /* Spawn new user thread */
    argv = (uint32_t*)pool_hostptr(args[1]);
    envp = (uint32_t*)pool_hostptr(args[2]);
    envblock = create_envblock_frompool(argv, envp);
    thr = new std::thread(thr_user_vfork, newkernel,
                          procctx, envblock);
    thr->detach();

    /* Back to vfork() point */
    jb = vfork_ctx->jb;
    free(vfork_ctx);
    vfork_ctx = 0;
    longjmp(*jb, mypid);
    return -1;
}

static uint32_t /* -errno */
emul_clone(uint32_t nargs, uint32_t in){
    printf("not implemented.\n");
    abort();
}

uint32_t /* -errno */
runsyscall32(uint32_t no, uint32_t nargs, uint32_t in){
    int32_t r;
    int true_argc;
    /* filter emulated syscall */
    switch(no){
        case LKL__NR_clone:
            r = emul_clone(nargs, in);
            break;
        case LKL__NR_execve:
            r = emul_execve(nargs, in);
            break;
        case LKL__NR_execveat:
            printf("not implemented.\n");
            abort();
            break;
        default:
            true_argc = syscall_argc_tbl[no];
            if(true_argc == -1){
                printf("Unknown syscall! (%d)\n", no);
                true_argc = nargs;
            }else{
                if(true_argc != nargs){
                    printf("Override syscall args (%d: %d => %d)\n", no, nargs, true_argc);
                }
            }
            /* Use LKL */
            r = w2c_kernel_syscall(my_linux, no, true_argc, in);
            printf("Thread: %d Call = %d Ret = %d\n", my_thread_objid, no, r);
            break;
    }
    switch(r){
        case -512:
        case -513:
        case -514:
        case -516:
            handlesignal();
            break;
        default:
            /* Do nothing */
            break;
    }
    return r;
}

static uint32_t
debuggetpid(void){
    return runsyscall32(172 /* __NR_getpid */, 0, 0);
}

static uint32_t
debugdup3(uint32_t oldfd, uint32_t newfd, uint32_t flags){
    int32_t* buf;
    uint32_t ptr0;
    int32_t res;
    /* Assume the caller already have Linux context */
    buf = (int32_t*)pool_alloc(4*3);
    ptr0 = pool_lklptr(&buf[0]);
    buf[0] = oldfd;
    buf[1] = newfd;
    buf[2] = flags;
    res = runsyscall32(24 /* __NR_dup3 */, 3, ptr0);
    printf("debug dup3 (%d,%d) = %d\n", oldfd, newfd, res);
    pool_free(buf);
    return res;
}

static void
debugclose(uint32_t fd){
    int32_t* buf;
    uint32_t ptr0;
    int32_t res;
    /* Assume the caller already have Linux context */
    buf = (int32_t*)pool_alloc(4);
    ptr0 = pool_lklptr(&buf[0]);
    buf[0] = fd;
    res = runsyscall32(57 /* __NR_close */, 1, ptr0);
    printf("debug close(%d) = %d\n", fd, res);
    pool_free(buf);
    return;
}

static int kfd_stdout;
static int kfd_stderr;

/* User handlers */
extern "C" wasm_rt_memory_t* 
w2c_env_memory(struct w2c_env* bogus){
    return &the_linux.w2c_memory;
}

extern "C" uint32_t
w2c_env_wasmlinux_syscall32(struct w2c_env* env, uint32_t argc, uint32_t no,
                            uint32_t args){
    printf("(user) syscall = %d\n", no);
    return runsyscall32(no, argc, args);
}

thread_local uint32_t usertls;
extern "C" uint32_t
w2c_env_wasmlinux_tlsrw32(struct w2c_env* env, uint32_t op, uint32_t val){
    if(op == 0){
        printf("USERTLS[%d] := %x\n", my_thread_objid, val);
        usertls = val;
        return 0;
    }else if(op == 1){
        printf("USERTLS[%d] = %x\n", my_thread_objid, usertls);
        return usertls;
    }else{
        abort();
    }
    return -1;
}

static uint32_t
create_envblock(const char* argv[], const char* envp[]){
    size_t argc, envc;
    size_t o, s, arrsize, total, argtotal, envpoff, envptotal;
    int i;
    uint32_t ptr0;
    uint32_t* a;
    char* buf;
    /* [0] argc = envblock
     * [1] argv(0)
     * [2] argv(1)
     *   :
     * [argc] argv(argc) = 0
     * [argc+1] envp */

    /* Pass1: Calc bufsize */
    i = 0;
    argc = 0;
    argtotal = 0;
    arrsize = 1; /* argc */
    while(argv[i]){
        argc++;
        argtotal += strnlen(argv[i], 1024*1024);
        argtotal ++; /* NUL */
        i++;
    }
    arrsize += i+1 /* terminator */;
    envpoff = i+2;
    i = 0;
    envptotal = 0;
    envc = 0;
    while(envp[i]){
        envptotal +=strnlen(envp[i], 1024*1024);
        envptotal ++; /* NUL */
        i++;
        envc++;
    }
    arrsize += i+1; /* terminator */

    total = arrsize*4 + argtotal + envptotal;
    buf = (char*)pool_alloc(total);
    ptr0 = pool_lklptr(buf);
    memset(buf, 0, total);

    /* Pass2: Fill buffer */
    o = arrsize*4; /* offset to argv buffer */
    a = (uint32_t*)buf;
    a[0] = argc;
    for(i=0;i!=argc;i++){
        a[i+1] = pool_lklptr(buf + o); /* argv* */
        s = strnlen(argv[i], 1024*1024);
        memcpy(buf + o, argv[i], s);
        o += (s + 1); /* NUL */
    }
    a = &a[envpoff];
    for(i=0;i!=envc;i++){
        a[i] = pool_lklptr(buf + o);
        s = strnlen(envp[i], 1024*1024);
        memcpy(buf + o, envp[i], s);
        o += (s + 1); /* NUL */
    }
    printf("argc,envc = %ld,%ld\n",argc,envc);
    return ptr0;
}


static void
thr_user(const char* argv[], uint32_t procctx){
    struct user_instance* ui;
    void* puserdata;
    void* puserstack;
    uint32_t userdata, userstack;
    uint32_t envblock;
    uint32_t ret;
    const char* envp[] = {"PATH=/bin", 0};
    const size_t STACK_SIZE = 1024*1024;

    /* Instantiate and assign user module */
    puserdata = pool_alloc(199980 /* FIXME */);
    puserstack = pool_alloc(STACK_SIZE);
    userdata = pool_lklptr(puserdata);
    userstack = pool_lklptr(puserstack);

    ui = wasmlinux_user_module_instantiate32(0, userdata, userstack + (1024*1024));

    vfork_ctx = 0;

    /* Allocate linux context */
    newinstance();
    prepare_newthread();

    /* Assign process ctx */
    newtask_apply(procctx);

    /* Setup initial stdin/out */
    ret = debugdup3(kfd_stdout, 10, 0);
    printf("(user) stdout => 10 : %d\n", ret);
    ret = debugdup3(kfd_stderr, 11, 0);
    printf("(user) stderr => 11 : %d\n", ret);
    debugclose(kfd_stdout);
    debugclose(kfd_stderr);
    ret = debugdup3(10, 1, 0);
    printf("(user) 10 => stdout : %d\n", ret);
    ret = debugdup3(11, 2, 0);
    printf("(user) 11 => stderr : %d\n", ret);


    /* MUSL startup */
    envblock = create_envblock(argv, envp);
    /* Run usercode */
    try {
        wasmlinux_user_ctx_exec32(0, 0, envblock, 0, 0, 0);
    } catch (thr_exit &req) {
        printf("Exiting thread(main thread).\n");
    }
    thr_tls_cleanup();
    pool_free(puserdata);
    pool_free(puserstack);
    pool_free(pool_hostptr(envblock));
}

static void
run_busybox(const char* argv[]){
    uint32_t procctx;
    std::thread* thr;

    /* fork */
    procctx = newtask_process();
    thr = new std::thread(thr_user, argv, procctx);
    thr->join();
    delete thr;
}

static void
startup(void){
    size_t i;
    {
        const char* a[] = { "mkdir", "/tmp", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mkdir", "/proc", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mkdir", "/bin", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mkdir", "/sbin", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mkdir", "-p", "/usr/bin", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mkdir", "-p", "/usr/sbin", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mkdir", "-m", "755", "-p", "/dev/pts", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mknod", "-m", "666", "/dev/ptmx", "c", "5", "2", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mount", "-t",  "proc", "proc", "/proc", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "mount", "-t",  "devpts", "devpts", "/dev/pts", "-onoexec,nosuid", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "ls", "-al", "/", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "ifconfig", "-a", 0 };
        run_busybox(a);
    }
    /*
    {
        const char* a[] = { "ifconfig", "-a", 0 };
        run_busybox(a);
    }
    */
    {
        const char* a[] = { "mount", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "sh", "-c", "echo -n \"#!/usr/bin/env wasmlinux-id-exec\nxxxxxxxx....\n\" > /bin/busybox", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "chmod", "+x", "/bin/busybox", 0 };
        run_busybox(a);
    }
    /* FIXME: Workaround for run_busybox actually run /init (so busybox --install will use it) */
    {
        const char* a[] = { "cp", "/bin/busybox", "/init", 0 };
        run_busybox(a);
    }
    {
        const char* a[] = { "/bin/busybox", "--install", "-s", 0 };
        run_busybox(a);
    }
}

struct userthr_args {
    std::condition_variable* cv;
    std::mutex* mtx;
    uint32_t ctx;
    uint32_t tls;
    uint32_t fn;
    uint32_t stack;
    uint32_t arg;
    uint32_t pid;
};

static void
thr_uthr(struct user_context* prevctx, struct userthr_args* args){
    uint32_t tid;
    uint32_t fn;
    uint32_t arg;
    uint32_t stack;

    fn = args->fn;
    arg = args->arg;
    stack = args->stack;

    /* Allocate linux context */
    newinstance();
    prepare_newthread();

    /* Set TLS */
    printf("USERTLS[%d] := %x (init)\n", my_thread_objid, args->tls);
    usertls = args->tls;

    /* Assign process ctx */
    newtask_apply(args->ctx);

    /* Report back pid */
    tid = runsyscall32(178 /* __NR_gettid */, 0, 0);
    printf("Thread spawn. tid = %d, ctx = %x\n", tid, args->ctx);
    {
        std::unique_lock<std::mutex> NN(*args->mtx);
        args->pid = tid;
        args->cv->notify_one();
    }
    args = 0;


    /* Allocate and assign new instance */
    wasmlinux_user_ctx_new32(prevctx, stack);


    /* Ready to roll, call fn */
    try {
        (void) wasmlinux_user_ctx_exec32(1 /* thread entrypoint */, 
                                         fn, arg, 0, 0, 0);

    } catch (thr_exit &req) {
        printf("Exiting thread(user).\n");
    }
    thr_tls_cleanup();
}


extern "C" uint32_t
w2c_env_wasmlinux_clone32(struct w2c_env* env, 
                          uint32_t fn, uint32_t stack, 
                          uint32_t flags, uint32_t arg,
                          uint32_t ptid, uint32_t tls, uint32_t ctid){
    uint32_t pid;
    std::thread* thr;
    struct userthr_args* thrargs;
    /* FIXME: Detect calling process using env or TLS */
    int myflags = 0;
    if(flags & LKL_CLONE_SETTLS){
        myflags |= LKL_CLONE_SETTLS;
        flags &= ~LKL_CLONE_SETTLS;
    }
    
    if(flags & LKL_CLONE_THREAD){
        /* Thread creation */
        thrargs = (struct userthr_args*)malloc(sizeof(struct userthr_args));
        printf("TLS = %x\n",tls);
        if(myflags & LKL_CLONE_SETTLS){
            thrargs->tls = tls;
        }else{
            thrargs->tls = 0;
        }
        thrargs->cv = new std::condition_variable();
        thrargs->mtx = new std::mutex();
        thrargs->fn = fn;
        thrargs->stack = stack;
        thrargs->arg = arg;
        thrargs->ctx = w2c_kernel_taskmgmt(my_linux, 4, flags, ptid, ctid);
        {
            std::unique_lock<std::mutex> NN(*thrargs->mtx);
            thr = new std::thread(thr_uthr, wasmlinux_tls_get_context(), thrargs);
            thr->detach();
            thrargs->cv->wait(NN);
            pid = thrargs->pid;
        }
        delete thrargs->cv;
        delete thrargs->mtx;
        free(thrargs);
    }else{
        /* Process creation */
        printf("Unimpl.\n");
        abort();
    }
    return pid;
}


/* Kernel handlers */


static void
mod_syncobjects(uint64_t* in, uint64_t* out){
    int idx;
    switch(in[0]){
        case 1: /* sem_alloc [1 1 count] => [sem32] */
            idx = newobj(OBJTYPE_SEM);
            objtbl[idx].obj.sem = new std::counting_semaphore(in[1]);
            out[0] = idx;
            break;
        case 2: /* sem_free [1 2 sem32] => [] */
            idx = in[1];
            if(objtbl[idx].type != OBJTYPE_SEM){
                abort();
            }
            delete objtbl[idx].obj.sem;
            delobj(idx);
            break;
        case 3: /* sem_up [1 3 sem32] => [] */
            idx = in[1];
            if(objtbl[idx].type != OBJTYPE_SEM){
                abort();
            }
            objtbl[idx].obj.sem->release();
            break;
        case 4: /* sem_down [1 4 sem32] => [] */
            idx = in[1];
            if(objtbl[idx].type != OBJTYPE_SEM){
                abort();
            }
            objtbl[idx].obj.sem->acquire();
            break;
        case 5: /* mutex_alloc [1 5 recursive?] => [mtx32] */
            if(in[1] /* recursive? */){
                idx = newobj(OBJTYPE_RECURSIVE_MUTEX);
                objtbl[idx].obj.mtx_recursive = new std::recursive_mutex();
            }else{
                idx = newobj(OBJTYPE_MUTEX);
                objtbl[idx].obj.mtx = new std::mutex();
            }
            out[0] = idx;
            break;
        case 6: /* mutex_free [1 6 mtx32] => [] */
            idx = in[1];
            if(objtbl[idx].type == OBJTYPE_RECURSIVE_MUTEX){
                delete objtbl[idx].obj.mtx_recursive;
            }else if(objtbl[idx].type == OBJTYPE_MUTEX){
                delete objtbl[idx].obj.mtx;
            }else{
                abort();
            }
            delobj(idx);
            break;
        case 7: /* mutex_lock [1 7 mtx32] => [] */
            idx = in[1];
            if(objtbl[idx].type == OBJTYPE_RECURSIVE_MUTEX){
                objtbl[idx].obj.mtx_recursive->lock();
            }else if(objtbl[idx].type == OBJTYPE_MUTEX){
                objtbl[idx].obj.mtx->lock();
            }else{
                abort();
            }
            break;
        case 8: /* mutex_unlock [1 8 mtx32] => [] */
            idx = in[1];
            if(objtbl[idx].type == OBJTYPE_RECURSIVE_MUTEX){
                objtbl[idx].obj.mtx_recursive->unlock();
            }else if(objtbl[idx].type == OBJTYPE_MUTEX){
                objtbl[idx].obj.mtx->unlock();
            }else{
                abort();
            }
            break;
        default:
            abort();
            break;

    }
}

static void
thr_trampoline(int objid){
    funcptr_void f;
    try {
        newinstance();
        memset(mytls, 0, sizeof(mytls));
        my_thread_objid = objid;
        f = (funcptr_void)getfunc(objtbl[objid].obj.thr.func32);
        f(my_linux, objtbl[objid].obj.thr.arg32);
        objtbl[objid].obj.thr.ret = 0;
    } catch (thr_exit &req) {
        printf("Exiting thread.\n");
    }
    thr_tls_cleanup();
}

static void
mod_threads(uint64_t* in, uint64_t* out){
    int idx, idx2;
    uintptr_t res;
    switch(in[0]){
        case 1: /* thread_create [2 1 func32 arg32] => [thr32] */
            idx = newobj(OBJTYPE_THREAD);
            objtbl[idx].obj.thr.func32 = in[1];
            objtbl[idx].obj.thr.arg32 = in[2];
            objtbl[idx].obj.thr.thread = new std::thread(thr_trampoline, idx);
            out[0] = idx;
            break;
        case 2: /* thread_detach [2 2] => [] */
            idx = my_thread_objid;
            if(objtbl[idx].type != OBJTYPE_THREAD){
                abort();
            }
            objtbl[idx].obj.thr.thread->detach();
            break;
        case 3: /* thread_exit [2 3] => [] */
            idx = my_thread_objid;
            if(objtbl[idx].type != OBJTYPE_THREAD){
                abort();
            }
            {
                thr_exit e;
                throw e;
            }
            break;
        case 4: /* thread_join [2 4 thr32] => [result] */
            idx = in[1];
            if(objtbl[idx].type != OBJTYPE_THREAD){
                abort();
            }
            out[0] = objtbl[idx].obj.thr.ret;
            delobj(idx);
            break;
        case 5: /* thread_self [2 5] => [thr32] */
            idx = my_thread_objid;
            if(objtbl[idx].type != OBJTYPE_THREAD){
                abort();
            }
            out[0] = idx;
            break;
        case 6: /* thread_equal [2 6 thr32 thr32] => [equ?] */
            idx = in[1];
            idx2 = in[2];
            if(objtbl[idx].type != OBJTYPE_THREAD){
                abort();
            }
            if(objtbl[idx2].type != OBJTYPE_THREAD){
                abort();
            }
            out[0] = (idx == idx2) ? 1 : 0;
            break;
        case 7: /* gettid [2 7] => [tid] */
            idx = my_thread_objid;
            if(objtbl[idx].type != OBJTYPE_THREAD){
                abort();
            }
            out[0] = idx;
            break;
        case 8: /* tls_alloc [2 8 func32] => [tlskey32] */
            out[0] = thr_tls_alloc(in[1]);
            break;
        case 9: /* tls_free [2 9 tlskey32] => [] */
            thr_tls_free(in[1]);
            break;
        case 10: /* tls_set [2 10 tlskey32 ptr32] => [res] */
            out[0] = thr_tls_set(in[1], in[2]);
            break;
        case 11: /* tls_get [2 11 tlskey32] => [ptr32] */
            out[0] = thr_tls_get(in[1]);
            break;
        default:
            abort();
            break;
    }
}

static void
thr_debugprintthread(uint32_t fd, int ident){
    int32_t* buf;
    uint32_t ptr0, ptr1;
    int32_t res;
    char linebuf[2000];
    int i,r;
    const char* header;
    header = (ident == 0) ? "[stdout]" : "[stderr]";

    /* Allocate linux context */
    newinstance();
    prepare_newthread();

    /* Allocate syscall buffer */
    buf = (int32_t*)pool_alloc(3000);
    ptr0 = pool_lklptr(&buf[0]);
    ptr1 = pool_lklptr(&buf[3]);

    for(;;){
        buf[0] = fd;
        buf[1] = ptr1;
        buf[2] = 2000;
        res = runsyscall32(63 /* __NR_read */, 3, ptr0);
        printf("res = %d (from: %d, %x)\n", res, my_thread_objid, mytls[1]);
        if(res < 0){
            break;
        }
        if(res > 2000){
            printf("???\n");
            abort();
        }
        memcpy(linebuf, (void*)&buf[3], res);
        linebuf[res] = 0;
        r = 0;
        for(i=0;i!=res;i++){
            switch(linebuf[i]){
                case '\n':
                    linebuf[i] = 0;
                    printf("%s: %s\n", header,
                           (char*)&linebuf[r]);
                    r = i+1;
                    break;
                default:
                    break;
            }
        }
        if(r<i){
            printf("%s: %s\n", header, (char*)&linebuf[r]);
        }
    }

    pool_free(buf);
    thr_tls_cleanup();
}

static void
debugwrite(uint32_t fd, const char* data, size_t len){
    int32_t* buf;
    uint32_t ptr0, ptr1;
    int32_t res;
    /* Assume the caller already have Linux context */
    buf = (int32_t*)pool_alloc(4*3+len);
    ptr0 = pool_lklptr(&buf[0]);
    ptr1 = pool_lklptr(&buf[3]);
    memcpy((char*)&buf[3], data, len);
    buf[0] = fd;
    buf[1] = ptr1;
    buf[2] = len;
    res = runsyscall32(64 /* __NR_write */, 3, ptr0);
    printf("write res = %d\n", res);
    pool_free(buf);
}

void
spawn_debugiothread(void){
    int32_t* buf;
    uint32_t ptr0, ptr1;
    int32_t ret;
    /* Allocate syscall buffer */
    buf = (int32_t*)pool_alloc(sizeof(int32_t)*32);

    for(int i=0;i!=2;i++){
        std::thread* thr;
        /* Generate Pipe inside kernel */
        ptr0 = pool_lklptr(&buf[0]);
        ptr1 = pool_lklptr(&buf[2]);
        buf[0] = ptr1; /* pipefd[2] */
        buf[1] = 0; /* flags */

        ret = runsyscall32(59 /* pipe2 */, 2, ptr0);
        printf("Ret: %d, %d, %d\n", ret, buf[2], buf[3]);

        /* Spawn handler */
        thr = new std::thread(thr_debugprintthread, buf[2], i);
        thr->detach();

        if(i == 0){
            kfd_stdout = buf[3];
        }else{
            kfd_stderr = buf[3];
        }
    }
    pool_free(buf);
}

struct pinetd_pair_s {
    pinetd_pair_s* prev; /* Only R/W from main thread */
    pinetd_pair_s* next; /* Only R/W from main thread */
    std::condition_variable cv;
    void* ctx;
    void* handle;
    void* chime;
    uint32_t procctx;
    uint32_t sock_host;
    uint32_t sock_tgt;

    /* Proc id */
    int pid;

    /* Read/Write buffer (Host->Linux) */
    void* read_buffer;
    void* write_buffer;
    int hostwriteflag;

    /* Read buffer (Linux->Host) */
    int kernreadcnt;
#define PINETD_BUF_SIZE (64*1024)
    char readbuf[PINETD_BUF_SIZE];
};

std::mutex pinetd_action_mtx;
static struct pinetd_pair_s* pinetd_pair_first;

static void
thr_reader(struct pinetd_pair_s* param){
    int32_t* buf;
    int32_t* xbuf;
    uint32_t ptr0, ptr1;
    int32_t res;
    int i,r,chimed;

    /* Allocate linux context */
    newinstance();
    prepare_newthread();

    /* Close the other side now */
    debugclose(param->sock_tgt);

    /* Allocate syscall buffer */
    buf = (int32_t*)pool_alloc(64);
    xbuf = (int32_t*)pool_alloc(PINETD_BUF_SIZE);
    ptr0 = pool_lklptr(&buf[0]);
    ptr1 = pool_lklptr(xbuf);

    for(;;){
        chimed = 0;
        buf[0] = param->sock_host;
        buf[1] = ptr1;
        buf[2] = PINETD_BUF_SIZE;
        res = runsyscall32(63 /* __NR_read */, 3, ptr0);
        printf("(inetd read) res = %d (from: %d, %x)\n", res, my_thread_objid, mytls[1]);
        if(res < 0){
            break;
        }
        if(res == 0){
            continue;
        }
        if(res > PINETD_BUF_SIZE){
            printf("???\n");
            abort();
        }
        memcpy(param->readbuf, xbuf, res);
        {
            std::unique_lock<std::mutex> NN(pinetd_action_mtx);
            param->kernreadcnt = res;
            for(;;){
                if(!chimed){
                    if(param->hostwriteflag){
                        /* Previous write is not completed */
                    }else{
                        /* We can trigger write */
                        r = miniio_chime_trigger(param->ctx, param->chime);
                        if(r){
                            abort();
                        }
                        chimed = 1;
                    }
                }else if(!param->kernreadcnt){
                    /* issue next read() */
                    break;
                }
                param->cv.wait(NN);
            }
        }
    }

    pool_free(buf);
    pool_free(xbuf);
    thr_tls_cleanup();
}

static void
thr_pinetd_proc(struct pinetd_pair_s* param){
    uint32_t procctx;
    struct user_instance* ui;
    void* puserdata;
    void* puserstack;
    uint32_t userdata, userstack;
    uint32_t envblock;
    uint32_t ret;
    const char* argv[] = { "telnetd", "-i", "-l", "/bin/sh", 0 };
    const char* envp[] = {"PATH=/bin:/sbin", 0};
    const size_t STACK_SIZE = 1024*1024;


    /* Instantiate and assign user module */
    puserdata = pool_alloc(199980 /* FIXME */);
    puserstack = pool_alloc(STACK_SIZE);
    userdata = pool_lklptr(puserdata);
    userstack = pool_lklptr(puserstack);

    ui = wasmlinux_user_module_instantiate32(0, userdata, userstack + (1024*1024));
    if(vfork_ctx){
        abort();
    }
    vfork_ctx = 0;

    /* Allocate linux context */
    newinstance();
    prepare_newthread();

    /* Assign process ctx */
    newtask_apply(param->procctx);

    /* Setup initial stdin/out */
    ret = debugdup3(param->sock_tgt, 0, 0);
    printf("(inetd)  stdin => 0 : %d\n", ret);
    ret = debugdup3(0, 1, 0);
    printf("(inetd) stdout => 1 : %d\n", ret);
    ret = debugdup3(0, 2, 0);
    printf("(inetd) stderr => 2 : %d\n", ret);
    debugclose(param->sock_tgt);
    debugclose(param->sock_host);

    /* MUSL startup */
    envblock = create_envblock(argv, envp);
    /* Run usercode */
    try {
        wasmlinux_user_ctx_exec32(0, 0, envblock, 0, 0, 0);
    } catch (thr_exit &req) {
        printf("Exiting thread(inetd process main thread).\n");
    }
    thr_tls_cleanup();
    pool_free(puserdata);
    pool_free(puserstack);
    pool_free(pool_hostptr(envblock));
}

static void
pinetd_alloc(void* ctx, void* handle){ /* ACTION LOCKED */
    int i,r;
    uint32_t ptr0, ptr1;
    int32_t ret;
    int32_t* buf;
    void* sock;
    struct pinetd_pair_s* pair;
    std::thread* reader;
    std::thread* proc;
    std::thread* debugprinter;

    pair = new pinetd_pair_s();
    pair->next = pinetd_pair_first;
    pair->prev = 0;
    pair->kernreadcnt = 0;
    pair->hostwriteflag = 0;
    if(pair->next){
        pair->next->prev = pair;
    }
    pinetd_pair_first = pair;

    pair->ctx = ctx;
    pair->handle = miniio_tcp_accept(ctx, handle, pair);
    pair->chime = miniio_chime_new(ctx, pair);
    pair->write_buffer = miniio_buffer_create(ctx, PINETD_BUF_SIZE, pair);

    /* Allocate syscall buffer */
    buf = (int32_t*)pool_alloc(sizeof(int32_t)*32);

    /* Generate Socket pair */
    ptr0 = pool_lklptr(&buf[0]);
    ptr1 = pool_lklptr(&buf[4]);
    buf[0] = 1; /* Domain(UNIX) */
    buf[1] = 1; /* Type(STREAM) */
    buf[2] = 0; /* Protocol */
    buf[3] = ptr1; /* Pair */

    ret = runsyscall32(199 /* socketpair */, 2, ptr0);
    printf("SOCKPAIR: %d, %d, %d\n", ret, buf[4], buf[5]);
    pair->sock_host = buf[4];
    pair->sock_tgt = buf[5];

    /* Fork process state */
    pair->procctx = newtask_process();

    /* Spawn stdout-reader */
    reader = new std::thread(thr_reader, pair);
    reader->detach();


    /* Spawn process */
    proc = new std::thread(thr_pinetd_proc, pair);
    proc->detach();

    /* Start read */
    r = miniio_start_read(ctx, pair->handle);
    if(r){
        abort();
    }

    pool_free(buf);
}

static void
thr_pinetd_main(void){
    int r;
    void* ctx;
    void* param;
    void* listen_sock;
    void* mio_buf;
    void* mio_data;
    uintptr_t mio_size;
    int32_t* buf;
    uint32_t buf_ptr;
    int32_t* xbuf;
    uint32_t xbuf_ptr;
    struct pinetd_pair_s* pair;
#define EVBUF_SIZE 512
    uintptr_t evbuf[EVBUF_SIZE];
    uint32_t evsiz, evcur;
    uint32_t cev, cev_size, cev_code;
    uintptr_t* cev_param;
    int32_t res;

    pinetd_pair_first = 0;

    ctx = miniio_ioctx_create();

#if 0 // FIXME: moved to main thread
    /* Allocate linux context */
    newinstance();
    prepare_newthread();
#endif

    /* Allocate syscall bounce buffers */
    buf = (int32_t*)pool_alloc(sizeof(int32_t)*32);
    xbuf = (int32_t*)pool_alloc(PINETD_BUF_SIZE);
    buf_ptr = pool_lklptr(buf);
    xbuf_ptr = pool_lklptr(xbuf);


    /* Add listen port */
    param = miniio_net_param_create(ctx, 0);
    miniio_net_param_hostname(ctx, param, "127.0.0.1");
    miniio_net_param_port(ctx, param, TELNET_PORT);
    miniio_net_param_name_resolve(ctx, param);

    for(;;){
        r = miniio_ioctx_process(ctx);
        /* FIXME: Exit loop if no event triggered */
        pinetd_action_mtx.lock();
        r = miniio_get_events(ctx, evbuf, EVBUF_SIZE, &evsiz, &evcur);
        if(r){
            abort();
        }
        if(evcur >= EVBUF_SIZE){
            /* Too large event queued: something wrong */
            abort();
        }
        evcur = 0;
        cev = 0;
        for(;;){
            if(cev >= evsiz){
                break;
            }
            cev_size = evbuf[cev];
            for(int i=0;i!=cev_size;i++){
                printf("MINIIO[%d]: %ld\n", i, evbuf[cev+i]);
            }
            printf("\n");
            cev_code = evbuf[cev+1];
            cev_param = &evbuf[cev+2];
            cev += cev_size;
            switch(cev_code){
                case MINIIO_EVT_NETRESOLVE:
                    if(cev_param[0] != (uintptr_t)param){
                        /* stray event..? */
                        abort();
                    }
                    listen_sock = miniio_tcp_create(ctx, param, 0, 0);
                    if(! listen_sock){
                        abort();
                    }
                    r = miniio_tcp_listen(ctx, listen_sock);
                    if(r){
                        abort();
                    }
                    break;

                case MINIIO_EVT_CONNECT_INCOMMING:
                    if(cev_param[0] != (uintptr_t)listen_sock){
                        /* stray event..? */
                        abort();
                    }
                    pinetd_alloc(ctx, listen_sock);
                    break;

                case MINIIO_EVT_HANDLE_CLOSE:
                case MINIIO_EVT_SHUTDOWN:
                case MINIIO_EVT_READ_EOF:
                case MINIIO_EVT_READ_STOP:
                case MINIIO_EVT_READ_ERROR:
                    printf("FIXME: Free resources! %d\n", cev_code);
                    break;

                case MINIIO_EVT_WRITE_COMPLETE:
                    pair = (struct pinetd_pair_s*)cev_param[1];
                    pair->hostwriteflag = 0;
                    pair->cv.notify_one();
                    break;

                case MINIIO_EVT_READ_COMPLETE:
                    /* Host => Linux proxy */
                    pair = (struct pinetd_pair_s*)cev_param[1];
                    mio_buf = (void*)cev_param[2];
                    mio_size = cev_param[4];
                    mio_data = miniio_buffer_lock(ctx, mio_buf,
                                                  cev_param[3],
                                                  mio_size);
                    memcpy(xbuf, mio_data, mio_size);
                    miniio_buffer_unlock(ctx, mio_buf);
                    miniio_buffer_destroy(ctx, mio_buf);

                    buf[0] = pair->sock_host;
                    buf[1] = xbuf_ptr;
                    buf[2] = mio_size;
                    res = runsyscall32(64 /* __NR_write */, 3, buf_ptr);
                    printf("(inetd) PROXY OUT %d\n",res);
                    break;

                case MINIIO_EVT_CHIME:
                    /* Linux => Host proxy */
                    pair = (struct pinetd_pair_s*)cev_param[1];
                    if(pair->hostwriteflag){
                        /* Overwrapped write request */
                        abort();
                    }
                    pair->hostwriteflag = 1;
                    mio_data = miniio_buffer_lock(ctx, 
                                                  pair->write_buffer,
                                                  0, pair->kernreadcnt);
                    memcpy(mio_data, pair->readbuf, pair->kernreadcnt);
                    r = miniio_write(ctx, pair->handle, pair->write_buffer,
                                     0, pair->kernreadcnt);
                    pair->kernreadcnt = 0;
                    pair->cv.notify_one();
                    break;

                    /* Unused, shoud not happen */
                case MINIIO_EVT_CONNECT_OUTGOING:
                case MINIIO_EVT_TIMER:
                case MINIIO_EVT_PROCESS_EXIT:
                    abort();
                    break;

                default:
                    printf("Warning: Unknown miniio event %ld\n",
                           cev_code);
                    break;
            }
        }
        pinetd_action_mtx.unlock();
    }
    pool_free(buf);
    pool_free(xbuf);
}

void
spawn_pinetd(void){
    std::thread* thr;
    thr = new std::thread(thr_pinetd_main);
    thr->detach();
}

void
mod_memorymgr(uint64_t* in, uint64_t* out){
    void* ptr;
    switch(in[0]){
        case 1: /* mem_alloc [3 1 size] => [ptr32] */
            ptr = pool_alloc(in[1]);
            out[0] = pool_lklptr(ptr);
            printf("malloc: %p (offs: %p) %ld\n", ptr, out[0], in[1]);
            break;
        case 2: /* mem_free [3 2 ptr32] => [] */
            pool_free(pool_hostptr(in[1]));
            break;
        default:
            abort();
            break;
    }
}

void
mod_admin(uint64_t* in, uint64_t* out){
    char* buf;
    wasm_rt_memory_t* mem;
    switch(in[0]){
        case 1: /* print [0 1 str len] => [] */
            mem = &the_linux.w2c_memory;
            buf = (char*)malloc(in[2] + 1);
            buf[in[2]] = 0;
            memcpy(buf, mem->data + in[1], in[2]);
            puts(buf);
            break;
        case 2: /* panic [0 2] => HALT */
            printf("panic.\n");
            abort();
        default:
            abort();
            break;
    }
}

static uint64_t
current_ns(void){
    std::chrono::nanoseconds ns;
    ns = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch());
    return ns.count();
}

static void
thr_timer(int objid){
    funcptr_void f;
    uint32_t arg32;
    uint64_t wait_for;
    std::mutex* mtx;
    std::condition_variable* cv;

    newinstance();
    prepare_newthread();

    f = (funcptr_void)getfunc(objtbl[objid].obj.timer.func32);
    arg32 = objtbl[objid].obj.timer.arg32;

    cv = objtbl[objid].obj.timer.cv;
    mtx = objtbl[objid].obj.timer.mtx;

    {
        std::unique_lock<std::mutex> NN(*mtx);
        for(;;){
            wait_for = objtbl[objid].obj.timer.wait_for;
            objtbl[objid].obj.timer.wait_for = UINT64_MAX-1;
            if(wait_for == UINT64_MAX){
                /* Dispose timer */
                break;
            }else if(wait_for == (UINT64_MAX-1)){
                /* No request at this time. */
                cv->wait(NN);
            }else{
                std::cv_status s;
                /* wait and fire */
                //printf("Wait: %ld\n",wait_for);
                s = cv->wait_for(NN, std::chrono::nanoseconds(wait_for));
                if(s == std::cv_status::timeout){
                    //printf("Fire: %d\n",objtbl[objid].obj.timer.func32);
                    mtx->unlock();
                    f(my_linux, arg32);
                    mtx->lock();
                    //printf("Done: %d\n",objtbl[objid].obj.timer.func32);
                }else{
                    if(objtbl[objid].obj.timer.wait_for == UINT64_MAX-1){
                        printf("Spurious wakeup!: %ld again\n", wait_for);
                        objtbl[objid].obj.timer.wait_for = wait_for;
                    }else{
                        printf("Rearm: %ld\n", objtbl[objid].obj.timer.wait_for);
                    }
                }
            }
        }
    }

    printf("Dispose timer %d\n", objid);
    delete mtx;
    delete cv;
    delobj(objid);
    // FIXME: Free instance
    return;
}

static void
mod_timer(uint64_t* in, uint64_t* out){
    int idx;
    uint64_t delta;
    switch(in[0]){

        case 1: /* time [4 1] => [time64] */
            out[0] = current_ns();
            break;
        case 2: /* timer_alloc [4 2 func32 arg32] => [timer32] */
            idx = newobj(OBJTYPE_TIMER);
            objtbl[idx].obj.timer.func32 = in[1];
            objtbl[idx].obj.timer.arg32 = in[2];
            objtbl[idx].obj.timer.thread = new std::thread(thr_timer, idx);
            objtbl[idx].obj.timer.mtx = new std::mutex();
            objtbl[idx].obj.timer.cv = new std::condition_variable();
            objtbl[idx].obj.timer.wait_for = UINT64_MAX-1;
            objtbl[idx].obj.timer.running = 0;
            objtbl[idx].obj.timer.thread->detach();
            out[0] = idx;
            break;
        case 3: /* timer_set_oneshot [4 3 timer32 delta64] => [res] */
            idx = in[1];
            if(objtbl[idx].type != OBJTYPE_TIMER){
                abort();
            }
            //printf("Oneshot timer: %d %ld\n",idx, in[2]);
            {
                std::unique_lock<std::mutex> NN(*objtbl[idx].obj.timer.mtx);
                objtbl[idx].obj.timer.wait_for = in[2];
                objtbl[idx].obj.timer.cv->notify_one();
            }
            out[0] = 0;
            break;
        case 4: /* timer_free [4 4 timer32] => [] */
            idx = in[1];
            if(objtbl[idx].type != OBJTYPE_TIMER){
                abort();
            }
            {
                std::unique_lock<std::mutex> NN(*objtbl[idx].obj.timer.mtx);
                objtbl[idx].obj.timer.wait_for = UINT64_MAX;
                objtbl[idx].obj.timer.cv->notify_one();
            }
            break;
        default:
            abort();
            break;
    }
}

class guardian {public: uintptr_t ident;};

static void
mod_ctx(uint64_t* in, uint64_t* out){
    guardian* gp;
    uintptr_t* p;
    funcptr_cont f;
    switch(in[0]){
        case 1: /* jmp_buf_set [5 1 ptr32 func32 sizeof_jmpbuf] => [] */
            gp = new guardian();
            gp->ident = (uintptr_t)gp;
            p = (uintptr_t*)pool_hostptr(in[1]);
            *p = (uintptr_t)(gp);
            f = getfunc_cont(in[2]);
            try {
                //printf("Run: %lx %p\n", in[1], gp);
                f(my_linux);
            } catch (guardian& gg) {
                if(gg.ident != (uintptr_t)gp){
                    throw gg;
                }else{
                    delete gp;
                }
            }
            break;
        case 2: /* jmp_buf_longjmp [5 2 ptr32 val32] => NORETURN */
            p = (uintptr_t*)pool_hostptr(in[1]);
            gp = (guardian*)(*p);
            //printf("Throw: %lx %p\n", in[1], gp);
            throw *gp;
        default:
            abort();
            break;
    }
}

void
w2c_env_nccc_call64(struct w2c_env* env, u32 inptr, u32 outptr){
    uint8_t* inp;
    uint8_t* outp;
    uint64_t* in;
    uint64_t* out;
    uint64_t mod, func;
    wasm_rt_memory_t* mem;
    mem = &the_linux.w2c_memory;

    inp = mem->data + inptr;
    outp = mem->data + outptr;
    in = (uint64_t*)inp;
    out = (uint64_t*)outp;

    mod = in[0];
    func = in[1];
    //printf("CALL: %ld %ld \n", mod, func);

    switch(mod){
        case 0: /* Admin */
            mod_admin(&in[1], out);
            break;
        case 1: /* syncobjects */
            mod_syncobjects(&in[1], out);
            break;
        case 2: /* threads */
            mod_threads(&in[1], out);
            break;
        case 3: /* memory mgr */
            mod_memorymgr(&in[1], out);
            break;
        case 4: /* timer */
            mod_timer(&in[1], out);
            break;
        case 5: /* context */
            mod_ctx(&in[1], out);
            break;
        default:
            printf("Unkown request: %ld %ld \n", mod, func);
            abort();
            return;
    }
}

int
main(int ac, char** av){
    int i;
    int idx;
    wasm_rt_memory_t* mem;
    uint64_t startpages;
    uint64_t maxpages;
    uint32_t mpool_start;

    init_syscall_argc_table();
    /* Init objtbl */
    for(i=0;i!=MAX_HOSTOBJ;i++){
        objtbl[i].id = i;
        objtbl[i].type = OBJTYPE_FREE;
    }
    objtbl[0].type = OBJTYPE_DUMMY; /* Avoid 0 idx */
    wasm_rt_init();
    wasm2c_kernel_instantiate(&the_linux, 0);

    /* Init TLS slots */
    for(i=0;i!=MAX_MYTLS;i++){
        tlsstate[i] = { 0 };
    }
    
    my_linux = &the_linux;
    prepare_newthread();

    /* Init memory pool */
    mem = &the_linux.w2c_memory;
    startpages = wasm_rt_grow_memory(mem, 2048);
    maxpages = startpages + 2048;

    printf("memmgr region = ptr: %p pages: %ld - %ld\n", mem->data, 
           startpages, maxpages);

    mpool_start = (startpages * WASM_PAGE_SIZE);
    mpool_base = mem->data;
    mplite_init(&mpool, mem->data + mpool_start,
                (maxpages - startpages) * WASM_PAGE_SIZE,
                64, &mpool_lockimpl);
    
    /* Initialize kernel */
    w2c_kernel_init(&the_linux);

    /* Create debug I/O thread */
    spawn_debugiothread();

    printf("(init) pid = %d\n", debuggetpid());

    /* Early startup */
    startup();

    /* FIXME: Enter pinetd loop directly, as it seems we cannot use
     *        procctx from another thread */
    thr_pinetd_main();

#if 0
    /* Create pseudo inetd thread */
    spawn_pinetd();

    /* Sleep */
    for(;;){
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
#endif

    return 0;
}
