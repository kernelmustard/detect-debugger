// Linux-Specific Anti-Debugging Functions
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ptrace.h>

// Attempt to debug parent via child process, if it fails you are being debugged
int trace_self() {
    prctl(PR_SET_PTRACER, (unsigned long)getpid(), 0, 0, 0); // allow attach parent <--> child (default is parent --> child )
    int pid = fork();
    int status;

    if (pid == 0) { // child
        int ppid = getppid();
        if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0) {
            waitpid(ppid, NULL, 0);   // wait for the parent to stop/continue it
            ptrace(PTRACE_CONT, NULL, NULL);
            ptrace(PTRACE_DETACH, ppid, NULL, NULL); // detach
            exit(0);   // not being debugged
        } else {
            exit(1);   // being debugged
        }
    } else {    // parent
        waitpid(pid, &status, 0);
        return WEXITSTATUS(status);
    }
}

// same as above, but try to attach via ptrace twice and modify a variable to detect if one has been patched
int trace_self_withstate() {
    int canary = 2; // this internal state mechanism is incredibly weak

    if (trace_self() == 0) {
        canary = canary * 4;
    } else {    
        return 1;
    }

    if (trace_self() == 0) {
        canary = canary * 2;
    } else {
        return 1;
    }
    
    if (canary == 2 * 4 * 2) {
        return 0;   // not being debugged
    } else {
        return 1;   // a ptrace was patched
    }
}

// open /proc/self/status and find Tracer PID; if you are being traced then that PID is the tracing
// process. Otherwise, it will be 0.
int get_tracer_pid() {
    FILE *fp  = fopen("/proc/self/status", "r");
    char line[1024];

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "TracerPid:\t0") != NULL) {
                fclose(fp);
                return 0;
            }
        }
        fclose(fp);
        return 1;
    } else {
        perror("\x1b[31mERROR\x1b[0m");
        return 1;
    }
}

// read ppid in /proc/self/status, resolve /proc/(ppid)/exe (symlink), compare to known debugger binaries
int match_parent_to_dbg() {
    char *known_dbg[] = {
        "gdb",
        "strace",
        "lldb-server"
    };
    int listlen = sizeof(known_dbg) / sizeof(known_dbg[0]);

    // convert (int)ppid to (char *)ppid_s
    pid_t ppid = getppid();
    int length = snprintf(NULL, 0, "%d", ppid);
    char *ppid_s = malloc(length + 1);
    snprintf(ppid_s, length + 1, "%d", ppid);

    // construct symlink string
    length = snprintf(NULL, 0, "/proc/%s/exe", ppid_s);
    char *symlink = malloc(length + 1);
    snprintf(symlink, length + 1, "/proc/%s/exe", ppid_s);

    // resolve symlink
    char path[PATH_MAX + 1];
    ssize_t _len = readlink(symlink, path, sizeof(path));
    char *token, *name = "", *saveptr;

    // determine name
    token = strtok_r(path, "/", &saveptr);
    while (token != NULL) {
        name = token;
        token = strtok_r(NULL, "/", &saveptr);
    } // now name = last token

    // compare name to list of known debuggers
    for (int i = 0; i < listlen; i++) {
        if (strncmp(name, known_dbg[i], (size_t)listlen) == 0) {
            return 1;
            break;
        }
    }

    free(ppid_s); 
    free(symlink);
    return 0;
}

// measure difference in time at the beginning and end
// if difference exceeds limit then program has been delayed artificially
void breakme() {}   // sample function to set breakpoints
int detect_execution_delay() {
    struct timeval tp;

    gettimeofday(&tp, 0);
    long int start_ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

    breakme();  // will only work if you break on breakme

    gettimeofday(&tp, 0);
    long int end_ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

    if ((end_ms - start_ms) > 0) {  // this value will need to be adjusted
        return 1;                   // really meant to catch breaks
    } else {
        return 0;
    }
}

int bypass_breakpoints() {  // currently doesn't work, instruction is f3 regardless of breakpoint

    // check for int 3 at breakme() function entry
    if ((*(volatile unsigned int *)((uintptr_t)breakme) & 0xff) == 0xcc) {
        printf("breakpoint!\n");
        return 1;
    } else {
        //printf("addr is %x\n", *(volatile unsigned int *)((uintptr_t)breakme) & 0xff);
        return 0;
    }
    breakme();
}

sig_atomic_t g_rval = 1; // detected by default
void bp_handler() { g_rval = 0; }   // set if no debugger that handles SIGTRAP
int fake_breakpoint() {

    signal(SIGTRAP, bp_handler);    // register custy SIGTRAP handler
    asm ("int3");                   // send SIGTRAP

    // there are a couple instructions that can raise a EXCEPTION_BREAKPOINT
    // int 3 is an example
    return g_rval;    
}
