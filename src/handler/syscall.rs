use crate::decoder::syscalls::{
    decode_dirfd, decode_mmap_flags, decode_open_flags, decode_prot_flags,
};
use crate::ptrace::mm::{peek_data, read_buffer, read_string};

pub fn handle_syscall_entry(pid: i32, regs: &libc::user_regs_struct) -> String {
    let syscall_nr = regs.regs[8] as i64;
    if let Some(syscall_name) = syscall_numbers::aarch64::sys_call_name(syscall_nr) {
        match syscall_name {
            "write" => {
                let fd = regs.regs[0];
                let buf_addr = regs.regs[1];
                let count = regs.regs[2] as usize;
                let buf_content = unsafe { read_buffer(pid, buf_addr, count) };
                format!("write({}, {}, {})", fd, buf_content, count)
            }
            "writev" => {
                let fd = regs.regs[0];
                let iovec_addr = regs.regs[1];
                let iovcnt = regs.regs[2];
                // Try to read iovec structures
                let mut iovec_display = Vec::new();
                for i in 0..iovcnt.min(3) {
                    let iov_addr = iovec_addr + i * 16; // iovec is 16 bytes on 64-bit
                    if let Ok(iov_base) = unsafe { peek_data(pid, iov_addr) } {
                        if let Ok(iov_len) = unsafe { peek_data(pid, iov_addr + 8) } {
                            let content = unsafe { read_buffer(pid, iov_base, iov_len as usize) };
                            iovec_display
                                .push(format!("{{iov_base={}, iov_len={}}}", content, iov_len));
                        }
                    }
                }
                if !iovec_display.is_empty() {
                    format!("writev({}, [{}], {})", fd, iovec_display.join(", "), iovcnt)
                } else {
                    format!("writev({}, {:#x}, {})", fd, iovec_addr, iovcnt)
                }
            }
            "execve" => {
                let filename = unsafe { read_string(pid, regs.regs[0], 256) };
                format!(
                    "execve({}, {:#x}, {:#x})",
                    filename, regs.regs[1], regs.regs[2]
                )
            }
            "openat" => {
                let dfd = decode_dirfd(regs.regs[0]);
                let filename = unsafe { read_string(pid, regs.regs[1], 256) };
                let flags = decode_open_flags(regs.regs[2]);
                format!("openat({}, {}, {})", dfd, filename, flags)
            }
            "newfstatat" => {
                let dfd = decode_dirfd(regs.regs[0]);
                let pathname = unsafe { read_string(pid, regs.regs[1], 256) };
                format!(
                    "newfstatat({}, {}, {:#x}, {})",
                    dfd, pathname, regs.regs[2], regs.regs[3]
                )
            }
            "read" => {
                format!("read({}", regs.regs[0])
            }
            "getdents64" => {
                format!(
                    "getdents64({}, {:#x}, {})",
                    regs.regs[0], regs.regs[1], regs.regs[2]
                )
            }
            "ioctl" => {
                let fd = regs.regs[0];
                let request = regs.regs[1];
                let request_name = match request {
                    0x5413 => "TIOCGWINSZ",
                    0x5401 => "TCGETS",
                    0x5402 => "TCSETS",
                    _ => "",
                };
                if !request_name.is_empty() {
                    format!("ioctl({}, {}, {:#x})", fd, request_name, regs.regs[2])
                } else {
                    format!("ioctl({}, {:#x}, {:#x})", fd, request, regs.regs[2])
                }
            }
            "fcntl" => {
                let fd = regs.regs[0];
                let cmd = regs.regs[1];
                let cmd_name = match cmd {
                    0 => "F_DUPFD",
                    1 => "F_GETFD",
                    2 => "F_SETFD",
                    3 => "F_GETFL",
                    4 => "F_SETFL",
                    _ => "",
                };
                let arg_name = if cmd == 2 && regs.regs[2] == 1 {
                    "FD_CLOEXEC".to_string()
                } else {
                    format!("{:#x}", regs.regs[2])
                };
                if !cmd_name.is_empty() {
                    format!("fcntl({}, {}, {})", fd, cmd_name, arg_name)
                } else {
                    format!("fcntl({}, {}, {})", fd, cmd, arg_name)
                }
            }
            "close" => format!("close({})", regs.regs[0]),
            "lseek" => {
                let fd = regs.regs[0];
                let offset = regs.regs[1] as i64;
                let whence = regs.regs[2];
                let whence_name = match whence {
                    0 => "SEEK_SET",
                    1 => "SEEK_CUR",
                    2 => "SEEK_END",
                    _ => "SEEK_UNKNOWN",
                };
                format!("lseek({}, {}, {})", fd, offset, whence_name)
            }
            "mmap" => {
                let addr = if regs.regs[0] == 0 {
                    "NULL".to_string()
                } else {
                    format!("{:#x}", regs.regs[0])
                };
                let prot = decode_prot_flags(regs.regs[2]);
                let flags = decode_mmap_flags(regs.regs[3]);
                format!(
                    "mmap({}, {}, {}, {}, {}, {})",
                    addr, regs.regs[1], prot, flags, regs.regs[4] as i32, regs.regs[5]
                )
            }
            "mprotect" => {
                let prot = decode_prot_flags(regs.regs[2]);
                format!("mprotect({:#x}, {}, {})", regs.regs[0], regs.regs[1], prot)
            }
            "munmap" => format!("munmap({:#x}, {})", regs.regs[0], regs.regs[1]),
            "brk" => {
                let addr = if regs.regs[0] == 0 {
                    "NULL".to_string()
                } else {
                    format!("{:#x}", regs.regs[0])
                };
                format!("brk({})", addr)
            }
            _ => format!(
                "{}({:#x}, {:#x}, {:#x})",
                syscall_name, regs.regs[0], regs.regs[1], regs.regs[2]
            ),
        }
    } else {
        format!(
            "syscall_{}({:#x}, {:#x}, {:#x})",
            syscall_nr, regs.regs[0], regs.regs[1], regs.regs[2]
        )
    }
}

pub fn handle_syscall_exit(
    pid: i32,
    regs: &libc::user_regs_struct,
    read_params: (u64, u64, u64),
) -> String {
    let retval = regs.regs[0] as i64;
    let syscall_nr = regs.regs[8] as i64;
    if let Some(syscall_name) = syscall_numbers::aarch64::sys_call_name(syscall_nr) {
        match syscall_name {
            "read" => {
                let (_fd, buf_addr, count) = read_params;
                if retval > 0 {
                    let bytes_read = retval as usize;
                    let buf_content = unsafe { read_buffer(pid, buf_addr, bytes_read) };
                    format!("{}, {}) = {}", buf_content, count, retval)
                } else {
                    format!("{:#x}, {}) = {}", buf_addr, count, retval)
                }
            }
            _ => format!(" = {}", retval),
        }
    } else {
        format!(" = {}", retval)
    }
}
