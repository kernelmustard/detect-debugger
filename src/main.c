/*
    Author:         kernelmustard
    Description:    Validate your anti-anti-debugging techniques against this binary
    Status:         In Development
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

void log_console(char *technique, bool detected) {
    if (detected) {
        printf("[%sFOUND%s]\t\t%s", "\x1b[31m", "\x1b[0m", technique);
    } else {
        printf("[%sNOT FOUND%s]\t%s", "\x1b[32m", "\x1b[0m", technique);
    }
}

// wrap all windows-specific functionality here
#if defined(_WIN64) || defined(_WIN32)
#include "win/win.c"
void windows_tests() {

    printf("---------- DEBUG FLAGS ----------\n");
    log_console(
        "IsDebuggerPresent()\n", 
        is_debugger_present()
    );
    log_console(
        "BeingDebugged flag in PEB\n", 
        beingdebugged_flag_peb()
    );
    log_console(
        "IsDebuggerPresent() in TLS Callback section\n", 
        var_tlscb_is_debugger_present   // access static var set with TLS Callback
    );
    log_console(
        "CheckRemoteDebuggerPresent()\n", 
        check_remote_debugger_present()
    );
    log_console(
        "ZwQueryInformationProcess() for ProcessDebugPort\n", 
        zwqueryinfoproc_processdebugport()
    );
    log_console(
        "ZwQueryInformationProcess() for ProcessDebugFlags\n", 
        zwqueryinfoproc_processdebugflags()
    );
    log_console(
      "ZwQueryInformationProcess() for ProcessDebugHandle\n", 
      zwqueryinfoproc_processdebugobjecthandle()
    );
    log_console(
      "NtGlobalFlag bits in PEB\n", 
      ntgf_in_current_process()
    );
    log_console(
      "RtlQueryProcessHeapInformation() for flags\n",
      qprocheapinfo()
    );
    log_console(
      "Flag and ForceFlags in _HEAP structure\n", 
      heapstruct_flag_forceflags()
    );
    log_console(
      "VM check: < 2 CPUs\n",
      vm_check_cpu()
    );
    log_console(
      "VM check: < 2GB RAM\n",
      vm_check_ram()
    );
    log_console(
      "VM check: < 100GB storage\n",
      vm_check_storage()
    );
}
#endif

// wrap all linux-specific functionality here
#if defined(__linux__)
#include "lin/lin.c"
void linux_tests() {

    log_console(
        "ptrace() parent from child process\n",
        trace_self()
    );
    log_console(
        "ptrace() parent from child process with patch detection\n",
        trace_self_withstate()
    );
    log_console(
        "Tracer PID in /proc/self/status\n",
        get_tracer_pid()
    );
    log_console(
        "Match parent binary to known debuggers\n",
        match_parent_to_dbg()
    );
    log_console(
        "Unusual delay in execution time\n",
        detect_execution_delay()
    );
    log_console(
        "Detect/bypass 0xCC breakpoint\n",
        bypass_breakpoints()
    );
    log_console(
        "Check who handles int3\n",
        fake_breakpoint()
    );
}
#endif

int main() {

    #if defined(__linux__)
    linux_tests();
    return 0;
    #endif

    #if defined(_WIN64) || defined(_WIN32) // should separate 32-bit and 64-bit tests
    windows_tests();
    return 0;
    #endif

    printf("Your platform is currently unsupported.\n");
    return 1;
}