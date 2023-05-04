/*
    Author:         kernelmustard
    Description:    Validate your anti-anti-debugging techniques against this binary
    Status:         Active Development as of 5/4/2023
*/

#[cfg(target_os = "linux")]
mod linux_module;

#[cfg(target_os = "windows")]
mod windows_module;
use windows_module::{
    is_debugger_present,
    check_remote_debugger_present,
    check_current_process_peb,
    ntgf_in_current_process,
};
use windows::Win32::System::{
    Threading::Sleep,
};
use std::{
    collections::HashMap,
    env::consts::ARCH,
};

pub fn info_statements(indicator: &str, technique: &str, detected: bool) -> () {
    if detected == true {
        println!("[+]\t{} found by {}",indicator, technique);
    } else {
        println!("[+]\t{} not found by {}",indicator, technique);
    }
}

fn main() {

    let mut hm_techniques: HashMap<&str, bool> = HashMap::new();    // dynamic k:v array for &str technique and bool detected
    let mut indicator: &str;                                        // strings useful for debugging purposes
    let mut technique: &str;
    let mut detected: bool;

    // determine whether the code is executed as a 32-bit or 64-bit process
    let is_x64: bool;
    if ARCH == "x86" {
        is_x64 = false; 
    } else if ARCH == "x86_64" {
        is_x64 = true;
    } else {
        return;
    }
    
    ///////////////////////////////////////////////////////////////////////////////////////////////
    indicator = "BeingDebugged flag";

    technique = "IsDebuggerPresent()";
    detected = is_debugger_present();
    hm_techniques.insert(technique, detected);             // add name and value to hash map
    info_statements(indicator, technique, detected);       // print debug statements

    technique = "CheckRemoteDebuggerPresent()";
    detected = check_remote_debugger_present();
    hm_techniques.insert(technique, detected);
    info_statements(indicator, technique, detected);

    technique = "manually parsing PEB";
    detected = check_current_process_peb();
    hm_techniques.insert(technique, detected);
    info_statements(indicator, technique, detected);

    technique = "executed within TLS Callback section";
    detected = tls_callback_is_debugger_present();
    hm_techniques.insert(technique, detected);
    info_statements(indicator, technique, detected);
    ///////////////////////////////////////////////////////////////////////////////////////////////
    indicator = "NtGlobalFlag";

    technique = "parsing struct at PEB.NtGlobalFlag";
    detected = ntgf_in_current_process(is_x64);
    hm_techniques.insert(technique, detected);
    info_statements(indicator, technique, detected);
    ///////////////////////////////////////////////////////////////////////////////////////////////
    indicator = "HeapFlag Flags and ForceFlags";

    technique = "manually parsing offset of PEB.HeapFlag";
    detected = heap_flags_in_current_process(is_x64);
    info_statements(indicator, technique, detected);
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // exit with message if any evidence of debugging
    for (_key, value) in hm_techniques {
        if value == true {
            println!("[+]\tDebugger detected. Exiting ...");
            unsafe { Sleep(5000); } // FOR DEBUGGING PURPOSES
            return;
        }
    }

    println!("[+]\tYou do not have a debugger running!");
    unsafe { Sleep(5000); } // FOR DEBUGGING PURPOSES
}
