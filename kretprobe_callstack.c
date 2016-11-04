/*
 * usage: insmod kretprobe_callstack.ko func=<func_name>
 * for detect function callstack
 * /sys/kernel/debug/kprobes
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>


static char func_name[NAME_MAX] = "do_fork";
module_param_string(func, func_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(func, "Function to kretprobe; this module will report callstack");


/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    printk(KERN_INFO "[kretprobe_callback] func:%s callstack:\n", func_name);
    return 0;
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    return 0;
}

static struct kretprobe my_kretprobe = {
    .handler                = ret_handler,
    .entry_handler          = entry_handler,
    /* Probe up to 20 instances concurrently. */
    .maxactive              = 20,
};

static int __init kretprobe_init(void) {
    int ret;

    my_kretprobe.kp.symbol_name = func_name;
    ret = register_kretprobe(&my_kretprobe);
    if (ret < 0) {
        printk(KERN_INFO "[kretprobe_callback] register_kretprobe failed, returned %d\n",
               ret);
        return -1;
    }
    printk(KERN_INFO "[kretprobe_callback] Planted return probe at %s: %p\n",
           my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);
    return 0;
}

static void __exit kretprobe_exit(void) {
    unregister_kretprobe(&my_kretprobe);
    printk(KERN_INFO "[kretprobe_callback] kretprobe at %p unregistered\n",
           my_kretprobe.kp.addr);

    /* nmissed > 0 suggests that maxactive was set too low. */
    printk(KERN_INFO "[kretprobe_callback] Missed probing %d instances of %s\n",
           my_kretprobe.nmissed, my_kretprobe.kp.symbol_name);
}

module_init(kretprobe_init)
module_exit(kretprobe_exit)
MODULE_LICENSE("GPL");
