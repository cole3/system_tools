/*
 * Np need kernel config
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/time.h>

#include <asm/bug.h>
#include <asm/signal.h>
#include <asm/cputype.h>
#include <asm/hw_breakpoint.h>



#define CONFIG_TEST

#define RED                 "\033[0;32;31m"
#define NEND                "\033[m\n"

#define CS_LAR_KEY          0xc5acce55
#define REENABLE_DELAY      10 //ms

#define MODULE_NAME         "HW_BP"
#define DBG_PRINT(fmt...)   do { printk("[%s]", MODULE_NAME); printk(fmt); } while(0)

#define IS_EXE_BP()         (bp_attr.type == TYPE_X)

#define ARM_DBG_READ(N, M, OP2, VAL) do {\
       asm volatile("mrc p14, 0, %0, " #N "," #M ", " #OP2 : "=r" (VAL));\
       } while (0)

#define ARM_DBG_WRITE(N, M, OP2, VAL) do {\
           asm volatile("mcr p14, 0, %0, " #N "," #M ", " #OP2 : : "r" (VAL));\
           } while (0)


struct fsr_info {
    int (*fn)(unsigned long addr, unsigned int fsr, struct pt_regs *regs);
    int sig;
    int code;
    const char *name;
};

struct bp_attr {
    unsigned long addr;
#define TYPE_R  (1 << 0)
#define TYPE_W  (1 << 1)
#define TYPE_X  (1 << 2)
    unsigned int type;
} bp_attr;

struct fsr_info *p_fsr_info;
struct fsr_info *p_ifsr_info;

struct perf_event * __percpu *sample_hbp;
unsigned int test_here = 0;
struct timer_list reenable_timer;

//execute addr
static unsigned long eaddr = 0;
module_param(eaddr, ulong, S_IRUGO);
//write addr
static unsigned long waddr = 0;
module_param(waddr, ulong, S_IRUGO);
//read addr
static unsigned long raddr = 0;
module_param(raddr, ulong, S_IRUGO);
//write & read addr
static unsigned long wraddr = 0;
module_param(wraddr, ulong, S_IRUGO);
//execute symbol
static char esym[KSYM_NAME_LEN] = "";
module_param_string(esym, esym, KSYM_NAME_LEN, S_IRUGO);
//write symbol
static char wsym[KSYM_NAME_LEN] = "test_here";
module_param_string(wsym, wsym, KSYM_NAME_LEN, S_IRUGO);
//read symbol
static char rsym[KSYM_NAME_LEN] = "";
module_param_string(rsym, rsym, KSYM_NAME_LEN, S_IRUGO);
//write & read symbol
static char wrsym[KSYM_NAME_LEN] = "";
module_param_string(wrsym, wrsym, KSYM_NAME_LEN, S_IRUGO);
//don't use kernel hw_breakpoint
static unsigned int self = 0;
module_param(self, int, S_IRUGO);
//print cp14 register for debug
static unsigned int debug_regs = 0;
module_param(debug_regs, uint, S_IRUGO);



#ifdef CONFIG_TEST
void hw_break_test_access_memory(int para0, int para1) {
    struct thread_info *info = current_thread_info();

    if (info) {
        DBG_PRINT("cpu = %d\n", info->cpu);
    }
    test_here = 1;
    DBG_PRINT("hw_break_test: test_here = %d\n", test_here);
    ssleep(1);

    info = current_thread_info();
    if (info) {
        DBG_PRINT("cpu = %d\n", info->cpu);
    }

    test_here = 2;
    DBG_PRINT("hw_break_test: test_here = %d\n", test_here);
    ssleep(1);
}

static int hw_break_test(void * unused) {
    ssleep(5);
    DBG_PRINT("hw_break_test: start write this variable.\n");
    hw_break_test_access_memory(0, 0);
    DBG_PRINT("hw_break_test: end write this variable.\n");
    ssleep(1);

    return 0;
}
#endif

static int make_bp_attr(struct bp_attr *p_bp_attr) {
    if (eaddr) {
        p_bp_attr->addr = eaddr;
        p_bp_attr->type = TYPE_X;
    } else if (waddr) {
        p_bp_attr->addr = waddr;
        p_bp_attr->type = TYPE_W;
    } else if (raddr) {
        p_bp_attr->addr = raddr;
        p_bp_attr->type = TYPE_R;
    } else if (wraddr) {
        p_bp_attr->addr = wraddr;
        p_bp_attr->type = TYPE_W | TYPE_R;
    } else if (esym[0]) {
        p_bp_attr->addr = kallsyms_lookup_name(esym);
        p_bp_attr->type = TYPE_X;
    } else if (wsym[0]) {
        p_bp_attr->addr = kallsyms_lookup_name(wsym);
        p_bp_attr->type = TYPE_W;
    } else if (rsym[0]) {
        p_bp_attr->addr = kallsyms_lookup_name(rsym);
        p_bp_attr->type = TYPE_R;
    } else if (wrsym[0]) {
        p_bp_attr->addr = kallsyms_lookup_name(wrsym);
        p_bp_attr->type = TYPE_W | TYPE_R;
    } else {
        DBG_PRINT("Wrong input parameter!\n");
        return -1;
    }

    if (!bp_attr.addr) {
        DBG_PRINT("Wrong sym name or wrong addr!\n");
        return -2;
    }

    DBG_PRINT("addr=[<%x>](%pS), type=0x%x\n",
              (u32)bp_attr.addr, (void *)bp_attr.addr, bp_attr.type);

    return 0;
}

void show_pt_regs(struct pt_regs *regs) {
    DBG_PRINT("PC is at %pS\n", (void *)instruction_pointer(regs));
    DBG_PRINT("LR is at %pS\n", (void *)regs->ARM_lr);
    DBG_PRINT("pc : [<%08lx>]    lr : [<%08lx>]    psr: %08lx\n",
              regs->ARM_pc, regs->ARM_lr, regs->ARM_cpsr);
    DBG_PRINT("sp : %08lx  ip : %08lx  fp : %08lx\n",
              regs->ARM_sp, regs->ARM_ip, regs->ARM_fp);
    DBG_PRINT("r10: %08lx  r9 : %08lx  r8 : %08lx\n",
              regs->ARM_r10, regs->ARM_r9, regs->ARM_r8);
    DBG_PRINT("r7 : %08lx  r6 : %08lx  r5 : %08lx  r4 : %08lx\n",
              regs->ARM_r7, regs->ARM_r6, regs->ARM_r5, regs->ARM_r4);
    DBG_PRINT("r3 : %08lx  r2 : %08lx  r1 : %08lx  r0 : %08lx\n",
              regs->ARM_r3, regs->ARM_r2, regs->ARM_r1, regs->ARM_r0);
}

static unsigned int read_cpsr(int para0) {
    u32 cpsr_val = para0;

    asm volatile("mrs r0, cpsr");
    asm volatile("mov %0, r0" : "=r" (cpsr_val) : : "cc");

    //DBG_PRINT("cpsr = %x\n", cpsr_val);
    if (para0) {
        asm volatile("mrs r0, cpsr");
        asm volatile("and r0, r0, #0xFFFFFEFF");
        asm volatile("msr cpsr, r0");
        asm volatile("mrs r0, cpsr");
        asm volatile("mov %0, r0" : "=r" (cpsr_val) : : "cc");
        //DBG_PRINT("set cpsr = %x\n", cpsr_val);
    }

    return cpsr_val;
}

int run_per_cpu(void (*func)(void *), void *data) {
    int cpu;

    get_online_cpus();
    for_each_online_cpu(cpu) {
        smp_call_function_single(cpu, func, data, 1);
    }
    put_online_cpus();

    return 0;
}

static void print_debug_registers(void) {
    u32 reg;

    if (!debug_regs)
        return;

    DBG_PRINT("\n");
    ARM_DBG_READ(c0, c0, 0, reg);
    DBG_PRINT("DBGDIDR\t\t(ro):\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c1, 0, reg);
    DBG_PRINT("DBGDSCR(i)\t(ro):\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c5, 0, reg);
    DBG_PRINT("DBGDTRTX(i)\t(ro)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c7, 0, reg);
    DBG_PRINT("DBGVCR\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c0, 2, reg);
    DBG_PRINT("DBGDTRRX\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c2, 2, reg);
    DBG_PRINT("DBGDSCR(e)\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c3, 2, reg);
    DBG_PRINT("DBGDTRTX(e)\t(rw)\t 0x%x\n", reg);

    DBG_PRINT("\n");
    DBG_PRINT("Breakpoint register:\n");
    ARM_DBG_READ(c0, c0, 4, reg);
    DBG_PRINT("DBGBVR0\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c0, 5, reg);
    DBG_PRINT("DBGBCR0\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c1, 4, reg);
    DBG_PRINT("DBGBVR1\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c1, 5, reg);
    DBG_PRINT("DBGBCR1\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c2, 4, reg);
    DBG_PRINT("DBGBVR2\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c2, 5, reg);
    DBG_PRINT("DBGBCR2\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c3, 4, reg);
    DBG_PRINT("DBGBVR3\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c3, 5, reg);
    DBG_PRINT("DBGBCR3\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c4, 4, reg);
    DBG_PRINT("DBGBVR4\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c4, 5, reg);
    DBG_PRINT("DBGBCR4\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c5, 4, reg);
    DBG_PRINT("DBGBVR5\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c5, 5, reg);
    DBG_PRINT("DBGBCR5\t\t(rw)\t 0x%x\n", reg);

    DBG_PRINT("\n");
    DBG_PRINT("Watchpoint register:\n");
    ARM_DBG_READ(c0, c0, 6, reg);
    DBG_PRINT("DBGWVR0\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c0, 7, reg);
    DBG_PRINT("DBGWCR0\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c1, 6, reg);
    DBG_PRINT("DBGWVR1\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c1, 7, reg);
    DBG_PRINT("DBGWCR1\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c2, 6, reg);
    DBG_PRINT("DBGWVR2\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c2, 7, reg);
    DBG_PRINT("DBGWCR2\t\t(rw)\t 0x%x\n", reg);

    ARM_DBG_READ(c0, c3, 6, reg);
    DBG_PRINT("DBGWVR3\t\t(rw)\t 0x%x\n", reg);
    ARM_DBG_READ(c0, c3, 7, reg);
    DBG_PRINT("DBGWCR3\t\t(rw)\t 0x%x\n", reg);

    DBG_PRINT("CPSR\t\t(rw)\t 0x%x\n\n", read_cpsr(0));
}

static const char *arch2str[] = {
    "ARM_DEBUG_ARCH_RESERVED",
    "ARM_DEBUG_ARCH_V6",
    "ARM_DEBUG_ARCH_V6_1",
    "ARM_DEBUG_ARCH_V7_ECP14",
    "ARM_DEBUG_ARCH_V7_MM",
    "ARM_DEBUG_ARCH_V7_1",
    "ARM_DEBUG_ARCH_V8",
};

static const char *get_debug_arch(void) {
    unsigned int didr;

    if (((read_cpuid_id() >> 16) & 0xf) != 0xf) {
        return arch2str[ARM_DEBUG_ARCH_V6];
    }

    ARM_DBG_READ(c0, c0, 0, didr);
    return arch2str[(didr >> 16) & 0xf];
}

static void reenable_timer_notify(unsigned long tag) {
    unsigned int reg = (unsigned int)tag;

    if (IS_EXE_BP()) {
        ARM_DBG_WRITE(c0, c0, 5, reg);
    } else {
        ARM_DBG_WRITE(c0, c0, 7, reg);
    }
}

static void start_reenable_timer(struct timer_list *timer, unsigned int timeout, unsigned long tag) {
    unsigned long expires = jiffies + timeout * HZ / 1000;

    if (!timer->function) {
        init_timer(timer);
    }

    timer->expires = expires;
    timer->function = reenable_timer_notify;
    timer->data = tag;
    mod_timer(timer, expires);
}

static void sample_hbp_handler(struct perf_event *bp,
                               struct perf_sample_data *data,
                               struct pt_regs *regs) {
    static unsigned int n = 0;
    unsigned int reg;

    if (IS_EXE_BP()) {
        ARM_DBG_READ(C0, C0, 5, reg);
        ARM_DBG_WRITE(c0, c0, 5, 0);
    } else {
        ARM_DBG_READ(C0, C0, 7, reg);
        ARM_DBG_WRITE(c0, c0, 7, 0);
        //regs->ARM_pc += thumb_mode(regs) ? 2 : 4; // to avoid continual data abort
    }

    DBG_PRINT(RED"----------------------[%d] Hit breakpoint----------------------"NEND, n++);
    print_debug_registers();
    show_pt_regs(regs);
    dump_stack();

    start_reenable_timer(&reenable_timer, REENABLE_DELAY, (unsigned long)reg);
}


int hw_bp_cb_by_self(unsigned long addr, unsigned int fsr, struct pt_regs *regs) {
    int ret = 0;
    u32 dscr;

    preempt_disable();

    if (interrupts_enabled(regs))
        local_irq_enable();

    //DBG_PRINT("[%s][%d] fsr=%d\n", __FUNCTION__, __LINE__, fsr);
    /* We only handle watchpoints and hardware breakpoints. */
    ARM_DBG_READ(c0, c1, 0, dscr);

    /* Perform perf callbacks. */
    switch (ARM_DSCR_MOE(dscr)) {
    case ARM_ENTRY_BREAKPOINT:
    case ARM_ENTRY_ASYNC_WATCHPOINT:
    case ARM_ENTRY_SYNC_WATCHPOINT:
        sample_hbp_handler(NULL, NULL, regs);
        break;
    default:
        ret = 1; /* Unhandled fault. */
    }

    preempt_enable();

    return ret;
}

static void hook_fault_code_by_self(int nr,
                                    int (*fn)(unsigned long, unsigned int, struct pt_regs *),
                                    int sig, int code, const char *name) {
    if (nr < 0)
        return;

    ((struct fsr_info *)(p_fsr_info + nr))->fn   = fn;
    ((struct fsr_info *)(p_fsr_info + nr))->sig  = sig;
    ((struct fsr_info *)(p_fsr_info + nr))->code = code;
    ((struct fsr_info *)(p_fsr_info + nr))->name = name;
}

static void hook_ifault_code_by_self(int nr,
                                     int (*fn)(unsigned long, unsigned int, struct pt_regs *),
                                     int sig, int code, const char *name) {
    if (nr < 0)
        return;

    ((struct fsr_info *)(p_ifsr_info + nr))->fn   = fn;
    ((struct fsr_info *)(p_ifsr_info + nr))->sig  = sig;
    ((struct fsr_info *)(p_ifsr_info + nr))->code = code;
    ((struct fsr_info *)(p_ifsr_info + nr))->name = name;
}

static int hw_bp_supported(void) {
    u32 dscr;

    ARM_DBG_READ(c0, c1, 0, dscr);
    ARM_DBG_WRITE(c0, c2, 2, (dscr | ARM_DSCR_MDBGEN));
    ARM_DBG_READ(c0, c1, 0, dscr);
    return !(dscr & ARM_DSCR_MDBGEN);
}

void register_cb_by_self(void *data) {
    struct bp_attr *p_attr = data;

    //clear the OS lock
    ARM_DBG_WRITE(c1, c0, 4, ~CS_LAR_KEY);
    isb();

    //Clear any configured vector-catch events
    ARM_DBG_WRITE(c0, c7, 0, 0);
    isb();

    p_fsr_info = (struct fsr_info *)kallsyms_lookup_name("fsr_info");
    p_ifsr_info = (struct fsr_info *)kallsyms_lookup_name("ifsr_info");

    hook_fault_code_by_self(FAULT_CODE_DEBUG, hw_bp_cb_by_self, SIGTRAP,
                            TRAP_HWBKPT, "watchpoint debug exception");
    hook_ifault_code_by_self(FAULT_CODE_DEBUG, hw_bp_cb_by_self, SIGTRAP,
                             TRAP_HWBKPT, "breakpoint debug exception");

    ARM_DBG_WRITE(c0, c2, 2, 0x48000);

    if (p_attr->type & TYPE_X) {
        ARM_DBG_WRITE(c0, c0, 4, (u32)p_attr->addr);
        ARM_DBG_WRITE(c0, c0, 5, 0x1E7);
    } else {
        u32 wcr = 0x1E7;

        ARM_DBG_WRITE(c0, c0, 6, (u32)p_attr->addr);
        wcr |= p_attr->type << 3;
        ARM_DBG_WRITE(c0, c0, 7, wcr);
    }

    DBG_PRINT("CPU(%d): register_cb_by_self set @0x%x\n",
              smp_processor_id(), (u32)p_attr->addr);
}

void unregister_cb_by_self(void *data) {
    ARM_DBG_WRITE(c0, c2, 2, 0x40000);

    hook_fault_code_by_self(FAULT_CODE_DEBUG, NULL, SIGTRAP,
                            TRAP_HWBKPT, "watchpoint debug exception");
    hook_ifault_code_by_self(FAULT_CODE_DEBUG, NULL, SIGTRAP,
                             TRAP_HWBKPT, "breakpoint debug exception");

    DBG_PRINT("CPU(%d): unregister_cb_by_self\n", smp_processor_id());
}



static int __init hw_break_module_init(void) {
    DBG_PRINT("sizeof(int)=%d, arch=%s\n", sizeof(int), get_debug_arch());

    if (hw_bp_supported()) {
        DBG_PRINT("IC cannot support hw bp!\n");
        return -1;
    }

    if (make_bp_attr(&bp_attr)) {
        DBG_PRINT("Parameter error!\n");
        return -2;
    }

    if (run_per_cpu(register_cb_by_self, &bp_attr)) {
        DBG_PRINT("Register error\n");
        return -3;
    }

    print_debug_registers();

#ifdef CONFIG_TEST
    {
        struct task_struct *task = kthread_run(hw_break_test, NULL, "hw_break_test");

        if (IS_ERR(task)) {
            DBG_PRINT("HW Breakpoint: unable to create kernel test thread: %ld\n", PTR_ERR(task));
            return -4;
        }
    }
#endif

    return 0;
}

static void __exit hw_break_module_deinit(void) {
    run_per_cpu(unregister_cb_by_self, &bp_attr);
    print_debug_registers();
    DBG_PRINT("HW Breakpoint: exit.\n");
}

module_init(hw_break_module_init);
module_exit(hw_break_module_deinit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("cole3");
MODULE_DESCRIPTION("hw breakpoint");

