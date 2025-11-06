use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;

mod decoder;
mod handler;
mod ptrace;

use handler::syscall::{handle_syscall_entry, handle_syscall_exit};
use ptrace::other::{fork, ptrace_syscall, traceme, waitpid};
use ptrace::registers::get_regs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: strace [-v] <command> [args...]");
        return;
    }

    // Parse verbose flag
    let mut verbose = false;
    let mut cmd_start = 1;

    if args[1] == "-v" || args[1] == "--verbose" {
        verbose = true;
        cmd_start = 2;
        if args.len() < 3 {
            eprintln!("Usage: strace [-v] <command> [args...]");
            return;
        }
    }

    let command = &args[cmd_start];
    let command_args = &args[cmd_start + 1..];

    match fork() {
        Err(e) => panic!("fork failed: {}", e),
        Ok(0) => {
            // child process
            if verbose {
                eprintln!("strace: Child process starting, enabling ptrace...");
            }
            unsafe {
                let _ = Command::new(command)
                    .args(command_args)
                    .pre_exec(|| {
                        traceme()?;
                        Ok(())
                    })
                    .exec();
            }
            eprintln!("strace: exec failed!");
        }
        Ok(pid) => {
            // parent process
            if verbose {
                eprintln!(
                    "strace: Starting trace of command: {} {:?}",
                    command, command_args
                );
                eprintln!("strace: Parent tracing child process with PID: {}", pid);
            }
            let mut status = 0;
            if let Err(e) = waitpid(pid, &mut status, 0) {
                eprintln!("strace: waitpid failed: {}", e);
                return;
            }
            if verbose {
                eprintln!("strace: Child process stopped, beginning syscall trace...");
            }

            let mut syscall_count = 0;
            let mut is_entry = true; // Track if we're on entry (true) or exit (false)
            let mut pending_output = String::new(); // Store syscall entry output
            let mut current_syscall = String::new(); // Track current syscall name
            let mut current_syscall_nr: i64 = -1; // Track current syscall number
            let mut read_params: (u64, u64, u64) = (0, 0, 0); // Store read(fd, buf, count)

            while libc::WIFSTOPPED(status) {
                let regs = match get_regs(pid) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("strace: Failed to get registers: {}", e);
                        break;
                    }
                };

                let syscall_nr = regs.regs[8] as i64;

                // Detect if we're out of sync (syscall number changed when we expected exit)
                if !is_entry && syscall_nr != current_syscall_nr {
                    // Print the pending syscall without return value (unfinished)
                    if !pending_output.is_empty() {
                        eprintln!("{} = <unfinished ...>", pending_output);
                    }
                    // We're out of sync - treat this as a new entry
                    is_entry = true;
                    pending_output.clear();
                    current_syscall.clear();
                }

                if is_entry {
                    // Syscall entry - format but don't print yet
                    syscall_count += 1;
                    current_syscall_nr = syscall_nr;

                    // Get syscall name for tracking
                    if let Some(syscall_name) = syscall_numbers::aarch64::sys_call_name(syscall_nr)
                    {
                        current_syscall = syscall_name.to_string();

                        // Store read parameters for exit processing
                        if syscall_name == "read" {
                            read_params = (regs.regs[0], regs.regs[1], regs.regs[2]);
                        }
                    }

                    pending_output = handle_syscall_entry(pid, &regs);
                } else {
                    // Syscall exit - print with return value
                    let retval = regs.regs[0] as i64;

                    // Special handling for execve: it has extra ptrace stops from stop_current_and_wait
                    if current_syscall == "execve" {
                        // Detect exec-stop: if retval looks like a pointer (large positive value), skip it
                        if retval > 0x10000 {
                            // This is the exec-stop, not the real exit. Continue without printing or toggling
                            if let Err(e) = ptrace_syscall(pid) {
                                eprintln!("strace: ptrace_syscall failed: {}", e);
                                break;
                            }
                            if let Err(e) = waitpid(pid, &mut status, 0) {
                                eprintln!("strace: waitpid failed: {}", e);
                                break;
                            }
                            continue;
                        }
                        // Print with return value
                        eprintln!("{} = {}", pending_output, retval);
                    } else if current_syscall == "read" {
                        // Special handling for read: show buffer content if successful
                        let exit_output = handle_syscall_exit(pid, &regs, read_params);
                        eprintln!("{}{}", pending_output, exit_output);
                    } else {
                        // Standard syscall exit
                        let exit_output = handle_syscall_exit(pid, &regs, read_params);
                        eprintln!("{}{}", pending_output, exit_output);
                    }

                    pending_output.clear();
                    current_syscall.clear();
                }

                // Toggle between entry and exit
                is_entry = !is_entry;

                if let Err(e) = ptrace_syscall(pid) {
                    eprintln!("strace: ptrace_syscall failed: {}", e);
                    break;
                }
                if let Err(e) = waitpid(pid, &mut status, 0) {
                    eprintln!("strace: waitpid failed: {}", e);
                    break;
                }
            }

            if libc::WIFEXITED(status) {
                let exit_code = libc::WEXITSTATUS(status);
                eprintln!("+++ exited with {} +++", exit_code);
                if verbose {
                    eprintln!("strace: Total syscalls traced: {}", syscall_count);
                }
            } else if libc::WIFSIGNALED(status) {
                let signal = libc::WTERMSIG(status);
                eprintln!("+++ killed by signal {} +++", signal);
                if verbose {
                    eprintln!("strace: Total syscalls traced: {}", syscall_count);
                }
            }
        }
    }
}
