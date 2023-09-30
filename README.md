# detect-debugger
## Using
### Linux
#### Anti-Static
The point of this isn't "perfect" anti-static-analysis, but the following should be configured at build to make it nontrivial:
1. CMake build target should be set to MinSizeRel, where it excludes debug info and optimizes for size
2. `add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND strip -R .comment ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME})` in CMakeLists.txt to strip the .comment section after every build
3. `add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND echo 'Ag==' | base64 -d | dd conv=notrunc of=${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME} bs=1 seek=5)` in CMakeLists.txt 
## Building
The easiest way to build is via VSCode CMake Extension on the target platform. Otherwise it may take some finnagling.
### Manually
#### Linux
```bash
cd detect-debugger
mkdir build
cd build
cmake ..; make
```
#### Windows
```powershell
# I am assuming default powershell with aliases
chdir detect-debugger
mkdir build
chdir build
cmake ..; msbuild build/somefile # need to build on windows to get the actual name
```
## Reference
### Windows
- [Geoff Chappell, Software Analyst (ask him about consulting!)](https://www.geoffchappell.com/index.htm)
- [Checkpoint Anti-Debug Tricks](https://anti-debug.checkpoint.com/)
- [Process Hacker documentation](https://processhacker.sourceforge.io/doc/index.html)
### Linux
- [Hacker's Corner: Complete Guide to Anti-Debugging in Linux - Part 1 ](https://linuxsecurity.com/features/anti-debugging-for-noobs-part-1)
- [CTF Wiki: Detecting Breakpoints Bypassing](https://ctf-wiki.mahaloz.re/reverse/linux/detect-bp/)
- [CodeBreakers 2006 - AntiDebugging Techniques](https://repo.zenk-security.com/Reversing%20.%20cracking/CodeBreakers%202006%20-%20AntiDebugging%20techniques.pdf)
- [Programming Linux Anti-Reversing Techniques.pdf](https://samples.vx-underground.org/root/Papers/Linux/Evasion/2016-12-20%20-%20Programming%20Linux%20Anti-Reversing%20Techniques.pdf)
## Will Not Do
### Anti-VM Detection
- Check out [this](https://github.com/a0rtega/pafish) great project by a0rtega called pafish for all your Anti-VM testing needs