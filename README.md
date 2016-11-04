# system-tools

### bp.c 
    use linux kernel config hw_breakpoint to set break point by arm's cp14, include write/read/execute break point
### bp_self.c
    don't use linux kernel config, set break point by arm's cp14, include write/read/execute break point
### kprobe.c
    use linux kernel config kprobe to debug kernel and driver code.
### jprobe.c
    use linux kernel config jprobe to debug kernel and driver code.
### kretprobe.c
    use linux kernel config kretprobe to debug kernel and driver code.
### kretprobe_callstack.c
    use linux kernel config kretprobe to print kernel and driver code call stack.
### kretprobe_time.c
    use linux kernel config kretprobe to print kernel and driver code consume time.
### perf-tools-master
    some tools for debug linux kernel, kprobe, ftrace, and so on
