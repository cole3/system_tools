#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>

/* Jprobe the entrance to func */
asmlinkage int jprobe_func(const char *fmt, ...) {
    for (; *fmt; ++fmt) {
        if ((*fmt=='%')&&(*(fmt+1) == 'O')) *(char *)(fmt+1) = 'o';
    }
    jprobe_return();
    return 0;
}

/* Per-probe structure */
static struct jprobe jprobe_eg = {
    .entry = (kprobe_opcode_t *) jprobe_func
};

int my_jprobe_init(void) {
    int retval;

    jprobe_eg.kp.addr = (kprobe_opcode_t*)kallsyms_lookup_name("printk"); // FIXME
    if (!jprobe_eg.kp.addr) {
        printk("Bad probe point\n");
        return -1;
    }

    /* Register the Jprobe */
    if ((retval = register_jprobe(&jprobe_eg)) < 0) {
        printk("register_jprobe error, return value=%d\n",
               retval);
        return -1;
    }

    printk("Jprobe registered.\n");
    return 0;
}

void my_jprobe_deinit(void) {
    unregister_jprobe(&jprobe_eg);
    printk("Jprobe unregistered.\n");
}


module_init(my_jprobe_init);
module_exit(my_jprobe_deinit);

MODULE_LICENSE("GPL");
