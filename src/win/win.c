// Windows headers
#include <Windows.h>
//#include <winternl.h>
#include <VersionHelpers.h>
// C standard and Compiler headers
#include <intrin.h>
#include <stdbool.h>
// Project files
#include "win.h"
#include "utils.c"

// IsDebuggerPresent() Win32 API call
bool is_debugger_present() {
    return (bool)IsDebuggerPresent();
}

// check val of BeingDebugged flag in PEB
bool beingdebugged_flag_peb() {
    bool rval = false;
    PPEB pPEB = get_peb();

    if (pPEB != NULL) {
        if (pPEB->BeingDebugged == 1) {
            rval = true;
        } else {
            rval = false;
        }
    } else {
        printf("pPEB is NULL!\n");
    }
    return rval;
}

// invoke IsDebuggerPresent() in TLS Callback
static BOOL var_tlscb_is_debugger_present = FALSE;
void WINAPI tlscb_is_debugger_present(   // this function is executed before main
    PVOID DllHandle,
    DWORD Reason,
    PVOID Reserved
) {
    var_tlscb_is_debugger_present = IsDebuggerPresent();  // trivial to patch, should devise some other way 
}
// written with help from Elias Bachaalany <lallousz-x86@yahoo.com>
#if defined(_WIN64)
    #pragma comment (linker, "/INCLUDE:_tls_used")
    #pragma comment (linker, "/INCLUDE:p_tlscb_is_debugger_present")
    #pragma const_seg(push)
    #pragma const_seg(".CRT$XLAAA")
        EXTERN_C const PIMAGE_TLS_CALLBACK p_tlscb_is_debugger_present = tlscb_is_debugger_present;
    #pragma const_seg(pop)
#elif defined(_WIN32)
    #pragma comment (linker, "/INCLUDE:__tls_used")
    #pragma comment (linker, "/INCLUDE:_p_p_tlscb_is_debugger_present")
    #pragma data_seg(push)
    #pragma data_seg(".CRT$XLAAA")
        EXTERN_C PIMAGE_TLS_CALLBACK p_tlscb_is_debugger_present = tlscb_is_debugger_present;
    #pragma data_seg(pop)
#endif

// CheckRemoteDebuggerPresent() Win32 API call
bool check_remote_debugger_present() {
    BOOL rval = FALSE;

    if (! CheckRemoteDebuggerPresent(   // uses ZwQueryInformationProcess under the hood
        GetCurrentProcess(),
        &rval
    )) {
        printf("ERROR %d: CheckRemoteDebuggerPresent() unsuccessful\n", GetLastError());
    }
    return (bool)rval;  // casting bool -> BOOL caused stack corruption; size issue?
}

// ZwQueryInformationProcess syscall for ProcessDebugPort
bool zwqueryinfoproc_processdebugport() {
    bool rval = false;
    HMODULE dll_handle = LoadLibrary("ntdll.dll");
    if (dll_handle) {
        _ZwQueryInformationProcess ZwQueryInformationProcess = (_ZwQueryInformationProcess)GetProcAddress(dll_handle, "ZwQueryInformationProcess"); // unstable kernel function
        if (ZwQueryInformationProcess) {
            ULONG rlength;
            PVOID process_debug_port;
            NTSTATUS status = ZwQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &process_debug_port,
                sizeof(process_debug_port),
                &rlength
            );
            if (NT_SUCCESS(status)) {  // return type is success or info
                if (process_debug_port == (PVOID)-1) {
                    rval = true;
                }
            } else {
                printf("ERROR %x: ZwQueryInformationProcess() failed to query ProcessDebugPort.\n", status);
            }
        } else {
            printf("ERROR %d: Failed to map ZwQueryInformationProcess() from ntdll.dll\n", GetLastError());
        }
        FreeLibrary(dll_handle);
    } else {
        printf("ERROR %d: Failed to obtain handle to ntdll.dll\n", GetLastError());
    } 
    return rval;
}

// ZwQueryProcessInformation() syscall for ProcessDebugFlags
bool zwqueryinfoproc_processdebugflags() {
    bool rval = false;
    HMODULE dll_handle = LoadLibrary("ntdll.dll");
    if (dll_handle) {
        _ZwQueryInformationProcess ZwQueryInformationProcess = (_ZwQueryInformationProcess)GetProcAddress(dll_handle, "ZwQueryInformationProcess"); // unstable kernel function
        if (ZwQueryInformationProcess) {
            ULONG rlength;
            PROCESSINFOCLASS ProcessDebugFlags = 0x1f;   // undocumented flag
            DWORD process_debug_flags;
            NTSTATUS status = ZwQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugFlags,
                &process_debug_flags,
                sizeof(process_debug_flags),
                &rlength
            );
            if (NT_SUCCESS(status)) {
                if (process_debug_flags == 0) {
                    rval = true;
                }
            } else {
                printf("ERROR %x: ZwQueryInformationProcess() failed to query ProcessDebugFlags.\n", status);
            }
        } else {
            printf("ERROR %d: Failed to map ZwQueryInformationProcess() from ntdll.dll\n", GetLastError());
        }
        FreeLibrary(dll_handle);
    } else {
        printf("ERROR %d: Failed to obtain handle to ntdll.dll\n", GetLastError());
    }
    return rval;
}

// ZwQueryProcessInformation() syscall for ProcessDebugHandle
bool zwqueryinfoproc_processdebugobjecthandle() {
    bool rval = false;
    HMODULE dll_handle = LoadLibrary("ntdll.dll");
    if (dll_handle) {
        _ZwQueryInformationProcess ZwQueryInformationProcess = (_ZwQueryInformationProcess)GetProcAddress(dll_handle, "ZwQueryInformationProcess"); // unstable kernel function 
        if (ZwQueryInformationProcess) {
            ULONG rlength;
            HANDLE process_debug_object = 0;
            PROCESSINFOCLASS ProcessDebugObjectHandle = 0x1e;   // undocumented flag
            NTSTATUS status = ZwQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugObjectHandle,
                &process_debug_object,
                sizeof(process_debug_object),
                &rlength
            );
            if (NT_SUCCESS(status)) {
                if (process_debug_object != 0) {
                    rval = true;
                }
            }   // returns fail NTSTATUS if DebugObjectHandle isn't found
        } else {
            printf("ERROR %d: Failed to map ZwQueryInformationProcess() from ntdll.dll\n", GetLastError());
        }
        FreeLibrary(dll_handle);
    } else {
        printf("ERROR %d: Failed to obtain handle to ntdll.dll\n", GetLastError());
    }
    return rval;
}

// check specific flags in NtGlobablFlags section of PEB
bool ntgf_in_current_process() {    
    bool rval = false;
    HMODULE dll_handle = LoadLibrary("ntdll.dll");
    if (dll_handle) {
        _RtlGetNtGlobalFlags RtlGetNtGlobalFlags = (_RtlGetNtGlobalFlags)GetProcAddress(dll_handle, "RtlGetNtGlobalFlags");    // unstable kernel function
        ULONG ntgf = RtlGetNtGlobalFlags(); // in User Mode, (NtGlobalFlag from internal NTDLL variable) < NT 5.0 < (NtGlobalFlag from PEB)
        ULONG FLG_HEAP_ENABLE_TAIL_CHECK = 0x10; 
        ULONG FLG_HEAP_ENABLE_FREE_CHECK = 0x20;
        ULONG FLG_HEAP_VALIDATE_PARAMETERS = 0x40;
        if ((ntgf & (FLG_HEAP_ENABLE_TAIL_CHECK|FLG_HEAP_ENABLE_FREE_CHECK|FLG_HEAP_VALIDATE_PARAMETERS)) == 0x70) {
            rval = true;    // detect if a process was created by a deugger (attaching will not trigger)
        } else {
            rval = false;
        }
        FreeLibrary(dll_handle);
    } else {
        printf("ERROR %d: LoadLibrary() failed to obtain handle to ntdll.dll\n", GetLastError());
    }
    return rval;
}

// use RtlQueryProcessHeapInformation() syscall to read Heap flags from process memory of current process
bool qprocheapinfo() {
    bool rval = false;
    HMODULE dll_handle = LoadLibrary("ntdll.dll");
    if (dll_handle) {
        _RtlCreateQueryDebugBuffer RtlCreateQueryDebugBuffer = (_RtlCreateQueryDebugBuffer)GetProcAddress(dll_handle, "RtlCreateQueryDebugBuffer");
        if (RtlCreateQueryDebugBuffer) {
            PRTL_DEBUG_INFORMATION debug_info = RtlCreateQueryDebugBuffer(0, FALSE);
            if (debug_info) {
                _RtlQueryProcessHeapInformation RtlQueryProcessHeapInformation = (_RtlQueryProcessHeapInformation)GetProcAddress(dll_handle, "RtlQueryProcessHeapInformation");
                if (RtlQueryProcessHeapInformation) {
                    ULONG flags = debug_info->Flags;
                    if (flags & ~HEAP_GROWABLE) {
                        rval = true;
                    }
                } else {
                    printf("ERROR %d: GetProcAddress() failed to map RtlQueryProcessHeapInformation() from ntdll.dll\n", GetLastError());
                }
            } else {
                printf("ERROR %d: RtlCreateQueryDebugBuffer failed to create a buffer\n", GetLastError());
            }
        } else {
            printf("ERROR %d: GetProcAddress() failed to map RtlCreateQueryDebugBuffer() from ntdll.dll\n", GetLastError());
        }
        FreeLibrary(dll_handle);
    } else {
        printf("ERROR %d: LoadLibrary() failed to obtain handle to ntdll.dll\n", GetLastError());
    }
    return rval;
}

// check flag values at specific offset in _HEAP struct
bool heapstruct_flag_forceflags() {
    bool rval = false;
    PPEB pPEB = get_peb();
    if (pPEB != NULL) {
        #if defined(_WIN64)
            DWORD heap_offset = 0x30;
            DWORD heap_flags_offset = (IsWindowsVistaOrGreater() ? 0x70 : 0x14);
            DWORD heap_forceflags_offset = (IsWindowsVistaOrGreater() ? 0x74 : 0x18);
        #elif defined (_WIN32)
            DWORD heap_offset = 0x18;
            DWORD heapflags_offset = (IsWindowsVistaOrGreater() ? 0x40 : 0x0C);
            DWORD heap_forceflags_offset = (IsWindowsVistaOrGreater() ? 0x44 : 0x10);
        #endif
        PVOID heap = (PVOID)*(PDWORD_PTR)((PBYTE)pPEB + heap_offset);
        PDWORD heap_flags_ptr = (PDWORD)((PBYTE)heap + heap_flags_offset);
        PDWORD heap_forceflags_ptr = (PDWORD)((PBYTE)heap + heap_forceflags_offset);
        if ((((*heap_flags_ptr) & (~HEAP_GROWABLE)) || *heap_forceflags_ptr) != 0) {    // all () not necessary, but clarifies desired operator precedence
            rval = true;    // only detects if process started by debugger
        }
    } else {
        printf("pPEB is NULL!\n");
    }
    return rval;
}
