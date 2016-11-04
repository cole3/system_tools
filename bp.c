/*
 * kernel need config by:
 * CONFIG_PERF_EVENTS=y
 * CONFIG_HAVE_HW_BREAKPOINT=y
 * CONFIG_HW_PERF_EVENT=y
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

#define CS_LAR_KEY  0xc5acce55
#define REENABLE_DELAY  10 //ms

#define ARM_DBG_READ(N, M, OP2, VAL) do {\
          asm volatile("mrc p14, 0, %0, " #N "," #M ", " #OP2 : "=r" (VAL));\
          } while (0)

#define ARM_DBG_WRITE(N, M, OP2, VAL) do {\
              asm volatile("mcr p14, 0, %0, " #N "," #M ", " #OP2 : : "r" (VAL));\
              } while (0)

#define MODULE_NAME         "HW_BP"
#define DBG_PRINT(fmt...)   do { printk("[%s]", MODULE_NAME); printk(fmt); } while(0)


struct fsr_info {
    int (*fn)(unsigned long addr, unsigned int fsr, struct pt_regs *regs);
    int sig;
    int code;
    const char *name;
};

struct fsr_info *p_fsr_info;
struct fsr_info *p_ifsr_info;


struct perf_event * __percpu *sample_hbp;
unsigned int test_here = 0;
unsigned int execute_bp = 0;
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
static char wsym[KSYM_NAME_LEN] = "";
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

static unsigned int enable_test = 0;
module_param(enable_test, uint, S_IRUGO);

static unsigned int debug_regs = 0;
module_param(debug_regs, uint, S_IRUGO);




#ifdef CONFIG_TEST
void hw_break_test_access_memory(int para0, int para1) {
    test_here = 1;
    DBG_PRINT("hw_break_test: cpu%d test_here = %d\n",
              smp_processor_id(), test_here);
    ssleep(1);

    test_here = 2;
    DBG_PRINT("hw_break_test: cpu%d test_here = %d\n",
              smp_processor_id(), test_here);
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

int run_per_cpu(void (*func)(void *)) {
    int cpu;

    get_online_cpus();
    for_each_online_cpu(cpu) {
        smp_call_function_single(cpu, func, &cpu, 1);
    }
    put_online_cpus();

    return 0;
}

static void print_debug_registers(void) {
    u32 reg;

    if (!debug_regs) {
        return;
    }

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

    if (execute_bp) {
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

    if (execute_bp) {
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

    DBG_PRINT("[%s][%d] fsr=%d\n", __FUNCTION__, __LINE__, fsr);
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

void hook_fault_code_by_self(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
                             int sig, int code, const char *name) {
    if (nr < 0)
        return;

    ((struct fsr_info *)(p_fsr_info + nr))->fn   = fn;
    ((struct fsr_info *)(p_fsr_info + nr))->sig  = sig;
    ((struct fsr_info *)(p_fsr_info + nr))->code = code;
    ((struct fsr_info *)(p_fsr_info + nr))->name = name;
}

void hook_ifault_code_by_self(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
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
    //clear the OS lock
    ARM_DBG_WRITE(c1, c0, 4, ~CS_LAR_KEY);
    isb();

    //Clear any configured vector-catch events
    ARM_DBG_WRITE(c0, c7, 0, 0);
    isb();

    p_fsr_info = (struct fsr_info *)kallsyms_lookup_name("fsr_info");
    p_ifsr_info = (struct fsr_info *)kallsyms_lookup_name("ifsr_info");

    ARM_DBG_WRITE(c0, c2, 2, 0x48000);
    ARM_DBG_WRITE(c0, c0, 6, (u32)&test_here);
    ARM_DBG_WRITE(c0, c0, 7, 0x1F7);

    hook_fault_code_by_self(FAULT_CODE_DEBUG, hw_bp_cb_by_self, SIGTRAP,
                            TRAP_HWBKPT, "watchpoint debug exception");
    hook_ifault_code_by_self(FAULT_CODE_DEBUG, hw_bp_cb_by_self, SIGTRAP,
                             TRAP_HWBKPT, "breakpoint debug exception");

    DBG_PRINT("CPU(%d): register_cb_by_self set @0x%x\n",
              smp_processor_id(), (u32)&test_here);
}

void unregister_cb_by_self(void *data) {
    ARM_DBG_WRITE(c0, c2, 2, 0x40000);

    hook_fault_code_by_self(FAULT_CODE_DEBUG, NULL, SIGTRAP,
                            TRAP_HWBKPT, "watchpoint debug exception");
    hook_ifault_code_by_self(FAULT_CODE_DEBUG, NULL, SIGTRAP,
                             TRAP_HWBKPT, "breakpoint debug exception");

    DBG_PRINT("CPU(%d): unregister_cb_by_self\n", smp_processor_id());
}

static int bp_init(void) {
    int ret;
    struct perf_event_attr attr;

    hw_breakpoint_init(&attr);

    execute_bp = 0;

    if (eaddr) {
        attr.bp_addr = eaddr;
        attr.bp_type = HW_BREAKPOINT_X;
        execute_bp = 1;
    } else if (waddr) {
        attr.bp_addr = waddr;
        attr.bp_type = HW_BREAKPOINT_W;
    } else if (raddr) {
        attr.bp_addr = raddr;
        attr.bp_type = HW_BREAKPOINT_R;
    } else if (wraddr) {
        attr.bp_addr = wraddr;
        attr.bp_type = HW_BREAKPOINT_W | HW_BREAKPOINT_R;
    } else if (esym[0]) {
        attr.bp_addr = kallsyms_lookup_name(esym);
        attr.bp_type = HW_BREAKPOINT_X;
        execute_bp = 1;
    } else if (wsym[0]) {
        attr.bp_addr = kallsyms_lookup_name(wsym);
        attr.bp_type = HW_BREAKPOINT_W;
    } else if (rsym[0]) {
        attr.bp_addr = kallsyms_lookup_name(rsym);
        attr.bp_type = HW_BREAKPOINT_R;
    } else if (wrsym[0]) {
        attr.bp_addr = kallsyms_lookup_name(wrsym);
        attr.bp_type = HW_BREAKPOINT_W | HW_BREAKPOINT_R;
    } else if (enable_test) {
        attr.bp_addr = (unsigned long)&test_here;
        attr.bp_type = HW_BREAKPOINT_W;
    } else {
        DBG_PRINT("Wrong input parameter!\n");
        return -1;
    }

    attr.bp_len = HW_BREAKPOINT_LEN_4;

    sample_hbp = register_wide_hw_breakpoint(&attr, sample_hbp_handler, NULL);
    if (IS_ERR((void __force *)sample_hbp)) {
        ret = PTR_ERR((void __force *)sample_hbp);
        DBG_PRINT("sample_hbp = %d\n", (int)sample_hbp);
        goto fail;
    }

    DBG_PRINT("HW Breakpoint for %x installed\n", (unsigned int)attr.bp_addr);

    return 0;

fail:
    DBG_PRINT("Breakpoint registration failed\n");

    return ret;
}

static void bp_uninit(void) {
    unregister_wide_hw_breakpoint(sample_hbp);
    DBG_PRINT("HW Breakpoint uninstalled\n");
}


static int __init hw_break_module_init(void) {
    DBG_PRINT("sizeof(int)=%d, arch=%s\n", sizeof(int), get_debug_arch());

    if (hw_bp_supported()) {
        DBG_PRINT("IC cannot support hw bp!\n");
        return -1;
    }

    if (self) {
        if (run_per_cpu(register_cb_by_self)) {
            DBG_PRINT("use self hw_breakpoint\n");
            return -1;
        }
    } else {
        if (bp_init()) {
            DBG_PRINT("use kernel hw_breakpoint\n");
            return -1;
        }
    }

    print_debug_registers();

#ifdef CONFIG_TEST
    if (enable_test) {
        struct task_struct *task = kthread_run(hw_break_test, NULL, "hw_break_test");

        if (IS_ERR(task)) {
            DBG_PRINT("HW Breakpoint: unable to create kernel test thread: %ld\n", PTR_ERR(task));
            return -1;
        }
    }
#endif

    return 0;
}

static void __exit hw_break_module_deinit(void) {
    if (self) {
        run_per_cpu(unregister_cb_by_self);
    } else {
        bp_uninit();
    }
    print_debug_registers();
    DBG_PRINT("HW Breakpoint: exit.\n");
}

module_init(hw_break_module_init);
module_exit(hw_break_module_deinit);


MODULE_LICENSE("GPL");
MODULE_AUTHOR("cole3");
MODULE_DESCRIPTION("hw breakpoint");

