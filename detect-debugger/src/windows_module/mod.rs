use windows::{
    w,
    Win32::{
        System::{
            Diagnostics::Debug::{
                IsDebuggerPresent,
                CheckRemoteDebuggerPresent,
            },
            Threading::{
                GetCurrentProcess,
                PROCESS_BASIC_INFORMATION,
                PROCESSINFOCLASS,
                NtQueryInformationProcess,
            },
        },
        Foundation::{
            BOOL,
        },
    }
};
use std::{
    mem::size_of,
    ffi::c_void,
    process::{
        Command,
        Stdio,
    },
    io::{
        BufReader,
        BufRead,
    },
};

fn get_release_version() -> Option<String> {

    let command_output = Command::new("cmd")
        .args(&["/C", "ver"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to execute command")
        .stdout
        .expect("Failed to capture command output");

    let reader = BufReader::new(command_output);

    for line in reader.lines() {
        let line = line.expect("Failed to read line");

        if line.contains("Microsoft Windows") {
            let version = line.split('[').nth(1)?.split(']').nth(0)?;
            return Some(version.to_string());
        }
    }

    None

}

///////////////////////////////////////////////////////////////////////////////////////////////////
pub fn is_debugger_present() -> bool {
    unsafe { bool::from(IsDebuggerPresent()) }
}

pub fn check_remote_debugger_present() -> bool {
    let mut being_debugged = BOOL(0);
    let ptr: *mut BOOL = &mut being_debugged; // coerce mutable reference
    unsafe {
        CheckRemoteDebuggerPresent(
            GetCurrentProcess(),
            ptr,
        );
    }
    bool::from(being_debugged)
}

pub fn check_current_process_peb() -> bool {

    // manually search PEB of current process
    let mut peb = PROCESS_BASIC_INFORMATION::default();
    let mut peb_size: u32 = size_of::<PROCESS_BASIC_INFORMATION>() as u32;
    unsafe {
        let _nt_status = NtQueryInformationProcess(
            GetCurrentProcess(),
            PROCESSINFOCLASS(0),
            &mut peb as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
            peb_size,
            &mut peb_size,
        );
    };
    let peb_base = unsafe { &peb.PebBaseAddress.as_ref().unwrap() };
    if (*peb_base).BeingDebugged == 1 {
        true
    } else {
        false
    }
}

/*  You also access any of these debugging techniques in the TLS Callback function

https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software

#[no_mangle]
#[link_section = ".CRT$XLB"]
pub static TLS_CALLBACK_FUNCTION: unsafe extern "system" fn() = {
    extern "system" fn callback() {
        let debugger_present = unsafe { IsDebuggerPresent() } != 0;

        if debugger_present {
            println!("Debugger is present!");

            // Perform any action when a debugger is detected, e.g., terminate the process
            // or stop debugging the current process
            unsafe { DebugActiveProcessStop(0) };
        }
    }

    callback
};
*/

pub fn ntgf_in_current_process(is_x64: bool) -> bool {

    // parse PEB
    let mut peb = PROCESS_BASIC_INFORMATION::default();
    let mut peb_size: u32 = size_of::<PROCESS_BASIC_INFORMATION>() as u32;
    unsafe {
        let _nt_status = NtQueryInformationProcess(
            GetCurrentProcess(),
            PROCESSINFOCLASS(0),
            &mut peb as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
            peb_size,
            &mut peb_size,
        );
    };
    let peb_base = unsafe { &peb.PebBaseAddress.as_ref().unwrap() };   

    let ntgf_offset: isize;
    if is_x64 { 
        ntgf_offset = 0xBC; // offset of PEB is 0xBC on 64-bit machines
    } else { 
        ntgf_offset = 0x68; // offset of PEB is 0x68 on 32-bit machines
    }

    let ptr_ntgf = unsafe { ((*peb_base).Reserved9).as_ptr().offset(ntgf_offset) };
    let ntgf = unsafe { *(ptr_ntgf as *mut u32) };

    const FLG_HEAP_ENABLE_TAIL_CHECK: u32 = 0x00000010; 
    const FLG_HEAP_ENABLE_FREE_CHECK: u32 = 0x00000020;
    const FLG_HEAP_VALIDATE_PARAMETERS: u32 = 0x00000040;

    if ntgf & (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS) == 0x00000070 {
        true
    } else {
        false
    }
}
 
/*  Not going to implement this but put in too much effort to delete this

use std::arch::asm

pub asm_fn ntgf_in_current_process() -> bool {
    let ntgf_offset: u32;
    let result: i8;
    let b_ntgf: bool;
    println!("is_x64 = {}", is_x64);
    if is_x64 {
        ntgf_offset = 0xBC;     // PEB64
        b_ntgf = unsafe {       // offset of PEB is 0xBC on 64-bit machines
            asm!(
                "mov rax, gs:0x60",               // Process Environment Block
                "mov rbx, [rax + {ntgf_offset:r}]",   
                "and ebx, 70h",                     // bitwise AND the NtGlobalFlag and 0x70
                "cmp ebx, 70h",                     // compare result to 0x70, ZF set if equal
                "sete al",                          // set al to 1 if ZF set
                "mov {result}, al",                 // move result into al
                result = out(reg_byte) result,
                ntgf_offset = in(reg) ntgf_offset,
            );
            result != 0
        };
    } else {
        ntgf_offset = 0x68;     // offset of PEB is 0x68 on 32-bit machines
        b_ntgf = unsafe {       // PEB32
            asm!(
                "mov eax, fs:0x30",                 // Process Environment Block
                "mov ebx, [eax + {ntgf_offset:e}]",    
                "and ebx, 70h",                     // bitwise AND the NtGlobalFlag and 0x70
                "cmp ebx, 70h",                     // compare result to 0x70, ZF set if equal
                "sete al",                          // set al to 1 if ZF set
                "mov {result}, al",                 // move result into al
                result = out(reg_byte) result,
                ntgf_offset = in(reg) ntgf_offset,
            );
            result != 0
        };
    }
    println!("ASM result of b_ntgf is {}", b_ntgf);
    hm_techniques.insert(technique, b_ntgf);
    info_statements(b_ntgf, indicator, technique);
}

*/

pub fn heap_flags_in_current_process(is_x64: bool) -> bool {

    // parse PEB
    let mut peb = PROCESS_BASIC_INFORMATION::default();
    let mut peb_size: u32 = size_of::<PROCESS_BASIC_INFORMATION>() as u32;
    unsafe {
        let _nt_status = NtQueryInformationProcess(
            GetCurrentProcess(),
            PROCESSINFOCLASS(0),
            &mut peb as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
            peb_size,
            &mut peb_size,
        );
    };
    let peb_base = unsafe { peb.PebBaseAddress.as_ref().unwrap() };

    let heap_flags_offset: i32;
}