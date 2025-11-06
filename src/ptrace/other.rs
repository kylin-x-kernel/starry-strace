use std::io;

// Helper function to enable tracing in the child process (safe wrapper)
pub fn traceme() -> io::Result<()> {
    unsafe {
        if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

// Helper function to continue the tracee and wait for the next syscall (safe wrapper)
pub fn ptrace_syscall(pid: i32) -> io::Result<()> {
    unsafe {
        if libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

// Safe wrapper for fork
pub fn fork() -> io::Result<libc::pid_t> {
    unsafe {
        let pid = libc::fork();
        if pid == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(pid)
        }
    }
}

// Safe wrapper for waitpid
pub fn waitpid(pid: i32, status: &mut i32, options: i32) -> io::Result<i32> {
    unsafe {
        let result = libc::waitpid(pid, status as *mut i32, options);
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }
}
