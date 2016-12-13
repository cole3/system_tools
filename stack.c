//driver:

#include <linux/stacktrace.h>

dump_stack();


//ap:
1..............................................................................................
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void dump_stack(void)
{
    int j, nptrs;
#define SIZE 100
    void *buffer[SIZE];
    char **strings;

    nptrs = backtrace(buffer, SIZE);
    printf("backtrace() returned %d addresses\n", nptrs);

    /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
       would produce similar output to the following: */

    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        printf("backtrace_symbols");
        return;
    }

    for (j = 0; j < nptrs; j++)
        printf("%s\n", strings[j]);

    free(strings);
}



2..............................................................................................
__builtin_return_address:
void * __builtin_return_address( unsigned int level );

level: 0 - ..callstack
1 - ..callstack
......
..addr....addr2line..code...

...
http://gcc.gnu.org/onlinedocs/gcc/Return-Address.html




3..............................................................................................
#if 1

#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>


#define NONE          "\033[m"
#define RED           "\033[0;32;31m"
#define GREEN         "\033[0;32;32m"

struct stack_frame
{
    struct stack_frame *next;
    unsigned int *sp;
    unsigned int *lr;
};

static pid_t gettid(void)
{
    return syscall(SYS_gettid);
}

static void print_comm(UINT32 pid)
{
    char name[32], buf[32];
    FILE *file = NULL;

    sprintf(name, "/proc/%d/comm", gettid());
    file = fopen(name, "r");
    if (!file)
    {
        Printf(RED"[BT]fopen %s error!\n"NONE, name);
        return;
    }

    fgets(buf, sizeof(buf), file);
    Printf(GREEN"[BT]comm: %s"NONE, buf);

    fclose(file);
}

static BOOL get_stack_range(UINT32 *pu4Start, UINT32 *pu4End)
{
    char name[32], buf[128];
    FILE *file = NULL;
    UINT32 start_addr = 0, end_addr = 0, tid = 0, tid_tmp = 0;

    if (!pu4Start || !pu4End)
    {
        return FALSE;
    }
    tid = gettid();
    sprintf(name, "/proc/%d/maps", tid);
    file = fopen(name, "r");
    if (!file)
    {
        Printf(RED"[BT]fopen %s error!\n"NONE, name);
        return FALSE;
    }

    while (fgets(buf, sizeof(buf) - 1, file))
    {
        if (sscanf(buf, "%x-%x %*s %*s %*s %*s [stack:%d]\n", &start_addr, &end_addr, &tid_tmp) != 3)
        {
            continue;
        }
        if (tid == tid_tmp)
        {
            *pu4Start = start_addr;
            *pu4End = end_addr;
            Printf(GREEN"[BT]stack(%d) start_addr = 0x%x, end_addr = 0x%x\n"NONE, tid, start_addr, end_addr);
            break;
        }
    }

    fclose(file);
    return TRUE;
}

#ifdef PROC_METHOD
static char *get_last_string(char *buf)
{
    char *s = buf;

    while (*buf != '\n' && *buf != '\0')
    {
        if (*buf == ' ' || *buf == '\t')
        {
            s = buf + 1;
        }
        buf++;
    }

    *buf = '\0';
    return s;
}

static void print_map(UINT32 u4addr)
{
    char name[32], buf[128];
    FILE *file = NULL;
    UINT32 start_addr = 0, end_addr = 0;

    sprintf(name, "/proc/%d/maps", gettid());
    file = fopen(name, "r");
    if (!file)
    {
        Printf(RED"[BT]fopen %s error!\n"NONE, name);
        return;
    }

    while (fgets(buf, sizeof(buf) - 1, file))
    {
        sscanf(buf, "%x-%x%*s\n", &start_addr, &end_addr);
        if (start_addr <= u4addr && u4addr < end_addr)
        {
            Printf(GREEN"[BT][<%p>] (+0x%x) %s\n"NONE, u4addr, u4addr-start_addr, buf);
            Printf(GREEN"[BT]%s\n"NONE, get_last_string(buf));

            break;
        }
    }

    fclose(file);
}
#else
#include <dlfcn.h>

static void print_map(UINT32 u4addr)
{
    Dl_info info;

    if (dladdr((VOID *)u4addr, &info))
    {
        Printf(GREEN"[BT]***[<%08x>]%s(@0x%x):%s+0x%x\n"NONE, u4addr, info.dli_fname,
                info.dli_fbase, info.dli_sname, u4addr - (UINT32)info.dli_saddr);
    }
    else
    {
        Printf(GREEN"[BT]***[<%08x>]???\n"NONE, u4addr);
    }
}
#endif

static void backtrace(void)
{
    unsigned int fp, ip, sp, lr, pc;
    struct stack_frame *pCurFrame = NULL;
    UINT32 u4StackStartAddr = 0, u4StackEndAddr = 0xFFFFFFFF;
    int cnt = 0;

    if (!(_u4MwIfDbgFlags & 0x1000))
    {
        return;
    }

    asm("mov %[var], r11" : [var] "=r" (fp));
    asm("mov %[var], r12" : [var] "=r" (ip));
    asm("mov %[var], r13" : [var] "=r" (sp));
    asm("mov %[var], r14" : [var] "=r" (lr));
    asm("mov %[var], r15" : [var] "=r" (pc));
    Printf(GREEN"[BT]fp=%08x ip=%08x sp=%08x lr=%08x pc=%08x\n"NONE,
            fp, ip, sp, lr, pc);
    Printf(GREEN"[BT]pid %d, tid %d\n"NONE, getpid(), gettid());
    print_comm(gettid());

    get_stack_range(&u4StackStartAddr, &u4StackEndAddr);
    pCurFrame = (struct stack_frame *)fp - 1;

#define MAX_STACK_FRAME_NUM   20
    while (cnt++ < MAX_STACK_FRAME_NUM)
    {
        if ((unsigned int)pCurFrame < (unsigned int)&cnt ||
                (unsigned int)pCurFrame < u4StackStartAddr ||
                (unsigned int)pCurFrame >= u4StackEndAddr ||
                (unsigned int)pCurFrame >= 0xBF000000)
        {
            break;
        }

        print_map((UINT32)pCurFrame->lr);
        pCurFrame = pCurFrame->next - 1;
    }
}

#define BACKTRACE()  do { \
    Printf(GREEN"[BT]Current Func:%s\n"NONE, __FUNCTION__); \
    backtrace(); \
} while (0)

#endif
)
