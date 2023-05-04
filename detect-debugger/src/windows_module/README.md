# windows_module
## BeingDebugged
### Use the Windows API function IsDebuggerPresent
IsDebuggerPresent takes no arguments, checks if the calling process is being debugged User Mode debugger, and returns a boolean TRUE if it is. Otherwise, it returns FALSE. This will only detect debuggers that have spawned a process using this image, not a debugger that has attached to this 
process.
### Use the Windows API function CheckRemoteDebuggerPresent
CheckRemoteDebuggerPresent takes 2 arguments: the first is a HANDLE to the process you are checking and the second is a mutable raw pointer to a BOOL that will store the the result. The main difference is that you can check any process outside the context of the calling process.
### Manually parse the PEB and query the value of the flag. 
First initialize 2 variables: a zeroed PROCESS_BASIC_INFORMATION struct and a u32 representing the size of the struct in memory. Then use the system call NtQueryInformationProcess() to fill that peb.
## NtGlobalFlag
### Check value at PEB+offset
NtGlobalFlag is a struct that exists at PEB+0x68 on 32-bit and PEB+0xBC on 64-bit Windows. If a process was started by a debugger, it will have the following flags enabled:
- FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
- FLG_HEAP_ENABLE_FREE_CHECK (0x20)
- FLG_HEAP_VALIDATE_PARAMETERS (0x40)

To check, first you must look at the process environment block (PEB) offset 0x68 because that is the undocumented location where the system determines how to create heap structures. If the value is 0x70, then the process was started by a debugger. If the value is 0x0, the process is running as normal.
**These fields are undocumented and subject to change. It's very likely that I'm implementing this technique incorrectly, but I can't seem to get it to trigger when it's being debugged.**
## HeapFlag
### Check Value at PEB + HeapFlag offset + ForceFlags/Flags offset
Within the PEB is the HeapFlag struct. 2 8-byte flags within that struct indicate to the kernel that the heap was created within a debugger:

| Windows Version | Flags offset | ForceFlags offset |
| --- | --- | --- |
| 32-bit Windows NT, Windows 2000, Windows XP | 0x0C | 0x10 |
| 32-bit Windows Vista and later              | 0x40 | 0x44 |
| 64-bit Windows XP                           | 0x14 | 0x18 |
| 64-bit Windows Vista and later              | 0x70 | 0x74 |
## Use FindWindow() and EnumWindows() to find interesting top-level windows
## Use TerminateProcess() to kill interesting processes
## Detect/Crash an attached debugger with OutputDebugString()
