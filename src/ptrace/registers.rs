use libc::user_regs_struct;
use std::io;

// Safe wrapper to get registers from tracee
pub fn get_regs(pid: i32) -> io::Result<user_regs_struct> {
    unsafe {
        let mut regs: user_regs_struct = std::mem::zeroed();
        if libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            0,
            &mut regs as *mut _ as *mut libc::c_void,
        ) == -1
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(regs)
        }
    }
}
