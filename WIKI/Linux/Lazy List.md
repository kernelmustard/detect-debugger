- fork() and ptrace()
- fork() and ptrace() with internal state
- TracerPID from /proc/self/status
- resolve /proc/\<PPID\>/exe to name of parent process, and match to list of known debuggers
- time delta in ms between start and end of program, using breakme() as example
- 0xCC at function entry point
- register SIGTRAP handler and call int3 to see whether theis program or a debugger handles i