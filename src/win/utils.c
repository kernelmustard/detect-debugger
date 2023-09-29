#include <Windows.h>
#include <winternl.h>
#include <stdbool.h>

// determine whether process is WOW64
bool is_wow64() {
    bool rval = false;

    #if defined(_WIN64)
        HMODULE dll_handle;
        if (dll_handle = GetModuleHandle("Kernel32.dll")) {
            typedef BOOL(WINAPI *pIsWow64Process)(HANDLE, PBOOL);
            pIsWow64Process IsWow64Process = (pIsWow64Process)GetProcAddress(dll_handle, "IsWow64Process");
            BOOL is_wow64;
            if (IsWow64Process(GetCurrentProcess(), &is_wow64)) {
                if (is_wow64) {
                    rval = true;
                } else {
                    printf("Not WOW64 process.\n");
                }
            } else {
                printf("ERROR %d: IsWow64Process() failed.\n", GetLastError());
            }
        } else {
            printf("ERROR %d: GetModuleHandle() failed to get handle to ntdll.dll.", GetLastError());
        }
        FreeLibrary(dll_handle);
    #else
        rval = false;   // not 64-bit binary
    #endif

    return rval;
}

// return pointer to PEB of current process
PPEB get_peb() {
    PPEB pPEB = NULL;
    HMODULE dll_handle = LoadLibrary("ntdll.dll");
    if (dll_handle) {
        typedef NTSTATUS(WINAPI *pZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        pZwQueryInformationProcess ZwQueryInformationProcess = (pZwQueryInformationProcess)GetProcAddress(dll_handle, "ZwQueryInformationProcess"); // uses untstable kernel function
        if (ZwQueryInformationProcess) {
            PROCESS_BASIC_INFORMATION pbi;
            ULONG rlength;
            NTSTATUS status = ZwQueryInformationProcess(
                GetCurrentProcess(),
                ProcessBasicInformation,
                &pbi,
                sizeof(pbi),
                &rlength
            );
            if (NT_SUCCESS(status)) {
                pPEB = pbi.PebBaseAddress;
            } else {
                printf("ERROR %x: ZwQueryInformationProcess() unable to access PEB.\n", status);
            }
        } else {
            printf("ERROR %d: Failed to map ZwQueryInformationProcess() from ntdll.dll\n", GetLastError());
        }
        FreeLibrary(dll_handle);
    } else {
        printf("ERROR %d: Unable to load ntdll.dll\n", GetLastError());
    }
    return pPEB;
}
