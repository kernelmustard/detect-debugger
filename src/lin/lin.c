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
    unsigned int rval = 0;
    prctl(PR_SET_PTRACER, (unsigned long)getpid(), 0, 0, 0); // allow attach parent <--> child (default is parent --> child )
    int pid = fork();
    int status;

    if (pid == 0) { // child
        int ppid = getppid();
        if (ptrace(PTRACE_ATTACH, ppid, NULL, NULL) == 0) {
            waitpid(ppid, NULL, 0);   // wait for the parent to stop/continue it
            ptrace(PTRACE_CONT, NULL, NULL);
            ptrace(PTRACE_DETACH, ppid, NULL, NULL); // detach
            rval = 0;   // not being debugged
        } else {
            rval = 1;   // being debugged
        }
        exit(rval);
    } else {    // parent
        waitpid(pid, &status, 0);
        rval = WEXITSTATUS(status);
    }
    return rval;
}

// same as above, but try to attach via ptrace twice and modify a variable to detect if one has been patched
int trace_self_withstate() {
    unsigned int rval;
    int canary = 2; // this internal state mechanism is incredibly weak

    if ((rval = trace_self()) == 0) {
        canary = canary * 4;
    } else {    
        rval = 1;
        goto ret;
    }

    if ((rval = trace_self()) == 0) {
        canary = canary * 2;
    } else {
        rval = 1;
        goto ret;
    }
    
    if (canary == 2 * 4 * 2) {
        rval = 0;   // not being debugged
    } else {
        rval = 1;   // a ptrace was patched
    }
ret:
    return rval;
}

// open /proc/self/status and find Tracer PID; if you are being traced then that PID is the tracing
// process. Otherwise, it will be 0.
int get_tracer_pid() {
    unsigned int rval = 1;
    FILE *fp  = fopen("/proc/self/status", "r");
    char line[1024];

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "TracerPid:\t0") != NULL) {
                rval = 0;
            }
        }
        fclose(fp);
    } // should add else statement with error message

    return rval;
}

// read ppid in /proc/self/status, resolve /proc/(ppid)/exe (symlink), compare to known debugger binaries
int match_parent_to_dbg() {
    unsigned int rval = 0;  // honestly this technique sucks just change the name of your debugger lol
    char *known_dbg[] = {   // better malware would obfuscate/encrypt these strings
        "gdb",
        "strace",
        "lldb-server"
    };  // add more later if requested
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
            rval = 1;
            break;
        }
    }

    free(ppid_s); 
    free(symlink);
    return rval;
}

void breakme() {  } // sample function to set breakpoints

// measure difference in time at the beginning and end
// if difference exceeds limit then program has been delayed artificially
int detect_execution_delay() {
    unsigned int rval;
    struct timeval tp;

    gettimeofday(&tp, 0);
    long int start_ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

    breakme();  // will only work if you break on breakme

    gettimeofday(&tp, 0);
    long int end_ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;

    // for your viewing pleasure
    //printf("%ld\n%ld\n", start_ms, end_ms);

    if ((end_ms - start_ms) > 0) {  // this value will need to be adjusted
        rval = 1;                   // really meant to catch breaks
    } else {
        rval = 0;
    }

    return rval;
}

int bypass_breakpoints() {  // currently doesn't work, instruction is f3 regardless of breakpoint
    unsigned int rval;
    
    // check for int 3 at breakme() function entry
    if ((*(volatile unsigned int *)((uintptr_t)breakme) & 0xff) == 0xcc) {
        printf("breakpoint!\n");
        rval = 1;
    } else {
        //printf("addr is %x\n", *(volatile unsigned int *)((uintptr_t)breakme) & 0xff);
        rval = 0;
    }
    breakme();

    return rval;
}

sig_atomic_t g_rval = 1; // detected by default
void bp_handler() { g_rval = 0; }   // set if no debugger that handles SIGTRAP
int fake_breakpoint() {
    unsigned int rval;
    unsigned int handler;

    signal(SIGTRAP, bp_handler);    // register custy SIGTRAP handler
    asm ("int3");                   // send SIGTRAP

    rval = g_rval;  // there are a couple instructions that can raise a EXCEPTION_BREAKPOINT
    return rval;    // int 3 is an example
}
