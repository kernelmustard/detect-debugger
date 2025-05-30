/**
 * @file win.h
 * @author kernelmustard (https://github.com/kernelmustard)
 * @copyright GPLv3
 * @brief header for windows anti-analysis
 */

#pragma once
#ifndef WIN_H
#define WIN_H

// Windows headers
#include <windows.h>
#include <winternl.h>
#include <VersionHelpers.h>
// C standard and Compiler headers
#include <intrin.h>
#include <stdbool.h>

typedef ULONG(WINAPI *_RtlGetNtGlobalFlags)(VOID);

typedef NTSTATUS(NTAPI *_ZwQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef struct _DEBUG_BUFFER {
    HANDLE  SectionHandle;
    PVOID  SectionBase;
    PVOID  RemoteSectionBase;
    ULONG  SectionBaseDelta;
    HANDLE  EventPairHandle;
    ULONG  Unknown[2];
    HANDLE  RemoteThreadHandle;
    ULONG  InfoClassMask;
    ULONG  SizeOfInfo;
    ULONG  AllocatedSize;
    ULONG  SectionSize;
    PVOID  ModuleInformation;
    PVOID  BackTraceInformation;
    PVOID  HeapInformation;
    PVOID  LockInformation;
    PVOID  Reserved[8];
} DEBUG_BUFFER, *PDEBUG_BUFFER;

// Taken from https://processhacker.sourceforge.io/doc
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX {
    USHORT NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageChecksum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

typedef struct _RTL_HEAP_ENTRY {
    SIZE_T Size;
    USHORT Flags;
    USHORT AllocatorBackTraceIndex;
    union {
        struct {
            SIZE_T Settable;
            ULONG Tag;
        } s1;
        struct {
            SIZE_T CommittedSize;
            PVOID FirstBlock;
        } s2;
    } u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;

#define RTL_HEAP_BUSY (USHORT)0x0001
#define RTL_HEAP_SEGMENT (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1 (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2 (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3 (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS (USHORT)0x00e0
#define RTL_HEAP_UNCOMMITTED_RANGE (USHORT)0x0100
#define RTL_HEAP_PROTECTED_ENTRY (USHORT)0x0200

typedef struct _RTL_HEAP_TAG {
    ULONG NumberOfAllocations;
    ULONG NumberOfFrees;
    SIZE_T BytesAllocated;
    USHORT TagIndex;
    USHORT CreatorBackTraceIndex;
    WCHAR TagName[24];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;

typedef struct _RTL_HEAP_INFORMATION {
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PRTL_HEAP_TAG Tags;
    PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION, *PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS {
    ULONG NumberOfHeaps;
    RTL_HEAP_INFORMATION Heaps[1];
} RTL_PROCESS_HEAPS, *PRTL_PROCESS_HEAPS;

typedef struct _RTL_PROCESS_VERIFIER_OPTIONS {
    ULONG SizeStruct;
    ULONG Option;
    UCHAR OptionData[1];
} RTL_PROCESS_VERIFIER_OPTIONS, *PRTL_PROCESS_VERIFIER_OPTIONS;

typedef struct _RTL_DEBUG_INFORMATION {
    HANDLE SectionHandleClient;
    PVOID ViewBaseClient;
    PVOID ViewBaseTarget;
    ULONG_PTR ViewBaseDelta;
    HANDLE EventPairClient;
    HANDLE EventPairTarget;
    HANDLE TargetProcessId;
    HANDLE TargetThreadHandle;
    ULONG Flags;
    SIZE_T OffsetFree;
    SIZE_T CommitSize;
    SIZE_T ViewSize;
    union {
        struct _RTL_PROCESS_MODULES *Modules;
        struct _RTL_PROCESS_MODULE_INFORMATION_EX *ModulesEx;
    };
    struct _RTL_PROCESS_BACKTRACES *BackTraces; // no definition?
    struct _RTL_PROCESS_HEAPS *Heaps;
    struct _RTL_PROCESS_LOCKS *Locks;   // no definition?
    PVOID SpecificHeap;
    HANDLE TargetProcessHandle;
    PRTL_PROCESS_VERIFIER_OPTIONS VerifierOptions;
    PVOID ProcessHeap;
    HANDLE CriticalSectionHandle;
    HANDLE CriticalSectionOwnerThread;
    PVOID Reserved[4];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;

typedef PRTL_DEBUG_INFORMATION(NTAPI *_RtlCreateQueryDebugBuffer)(ULONG, BOOLEAN);

typedef NTSTATUS(NTAPI *_RtlQueryProcessHeapInformation)(PRTL_DEBUG_INFORMATION);

/**
 * @brief simple wrapper for IsDebuggerPresent() API
 * @return bool rval
 * @param void
 */
bool is_debugger_present(void);

/**
 * @brief check val of BeingDebugged flag in PEB
 * @return bool rval
 * @param void
 */
bool beingdebugged_flag_peb(void);

/**
 * @brief call IsDebuggerPresent() via TLS callback prior to main execution, set static value true if found
 * @return void
 * @param void
 */
//void WINAPI tlscb_is_debugger_present(void);

/**
 * @brief call CheckRemoteDebuggerPresent() on current process
 * @return bool rval
 * @param void
 */
bool check_remote_debugger_present(void);

/**
 * @brief call ZwQueryInformationProcess() on current process to see if ProcessDebugPort == -1
 * @return bool rval
 * @param void
 */
bool zwqueryinfoproc_processdebugport(void);

/**
 * @brief call ZwQueryProcessInformation() on current process to see if ProcessDebugFlags == 0
 * @return bool rval
 * @param void
 */
bool zwqueryinfoproc_processdebugflags(void);

/**
 * @brief call ZwQueryProcessInformation() on current process to see if ProcessDebugHandle != 0
 * @return bool rval
 * @param void
 */
bool zwqueryinfoproc_processdebugobjecthandle(void);

/**
 * @brief call RtlGetNtGlobalFlags() on current process to see if 3 flags are set in NtGlobalFlags section of PEB
 * @return bool rval
 * @param void
 */
bool ntgf_in_current_process(void);

/**
 * @brief call RtlQueryProcessHeapInformation() on current process to see if HEAP_GROWABLE flag is set
 * @return bool rval
 * @param void
 */
bool qprocheapinfo(void);

/**
 * @brief get PEB of current process, check flags and forceflags in heap struct for specific values depending on OS ver
 * @return bool rval
 * @param void
 */
bool heapstruct_flag_forceflags(void);

/**
 * @brief check if computer has <2 CPUs
 * @return bool rval
 * @param void
 */
bool vm_check_cpu(void);

/**
 * @brief check if computer has <2GB RAM
 * @return bool rval
 * @param void
 */
bool vm_check_ram(void);

/**
 * @brief check if computer has <100GB of storage
 * @return bool rval
 * @param void
 */
bool vm_check_storage(void);

#endif