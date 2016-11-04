#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

/* kretprobe at exit from func() */
static int kretprobe_func(struct kretprobe_instance *kreti,
                          struct pt_regs *regs) {
    /* The EAX register contains the function return value on x86 system */
    if (regs_return_value(regs)) {
        /* tty_open() failed. Announce the return code */
        printk("tty_open return %d\n", (int)regs_return_value(regs));
    }
    return 0;
}

/* Per-probe structure */
static struct kretprobe kretprobe_eg = {
    .handler = (kretprobe_handler_t)kretprobe_func
};

int my_kretprobe_init(void) {
    int retval;

    kretprobe_eg.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("tty_open"); // FIXME

    if (!kretprobe_eg.kp.addr) {
        printk("Bad Probe Point\n");
        return -1;
    }

    /* Register the kretporbe */
    if ((retval = register_kretprobe(&kretprobe_eg)) < 0) {
        printk("register_kretprobe error, return value=%d\n",
               retval);
        return -1;
    }
    printk("kretprobe registered.\n");
    return 0;
}

void my_kretprobe_deinit(void) {
    unregister_kretprobe(&kretprobe_eg);
    printk("kretprobe unregistered.\n");
}

module_init(my_kretprobe_init);
module_exit(my_kretprobe_deinit);

MODULE_LICENSE("GPL");
