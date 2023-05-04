use windows::{
    w,
    Win32::{
        System::{
            Diagnostics::Debug::{
                IsDebuggerPresent,
                CheckRemoteDebuggerPresent,
            },
            Registry::{
                HKEY,
                HKEY_LOCAL_MACHINE,
                REG_SZ,
                RegGetValueW,
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
//          HANDLE,
        },
    }
};
use std::{
    mem::size_of,
    ffi::c_void
};

pub fn get_release_version() {

    RegGetValueW(
        HKEY_LOCAL_MACHINE,
        w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
        w!("ProductName"),
        0x0000ffff, // RRF_RT_ANY (no restriction on datatype)
        NULL,
          ,
    );
}

fn get_registry_value() -> Result<String, Error> {
    

    let 
    let mut value: Vec<u16> = vec![0; 256];
    let mut value_size = (value.len() * 2) as u32;
    let mut value_type: u32 = 0;

    let result = unsafe {
        RegGetValueW(
            key.handle(),
            None,
            VALUE_NAME.encode_utf16().chain(Some(0)).collect::<Vec<_>>().as_ptr(),
            REG_SZ,
            &mut value_type as *mut u32,
            value.as_mut_ptr() as *mut _,
            &mut value_size as *mut u32,
        )
    };

    if result == 0 {
        // Success! Convert the retrieved value to a Rust String.
        let value = String::from_utf16_lossy(&value[..(value_size as usize) / 2]);
        Ok(value)
    } else {
        // An error occurred. Convert the Windows error code to a `windows::Error` and return it.
        Err(Error::from_win32(result))
    }
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
    let peb_base = unsafe { &peb.PebBaseAddress.as_ref().unwrap() };

    let heap_flags_offset: i32;
}