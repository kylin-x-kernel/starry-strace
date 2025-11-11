use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;

mod decoder;
mod handler;
mod ptrace;

use handler::syscall::{handle_syscall_entry, handle_syscall_exit};
use ptrace::other::{fork, ptrace_attach, ptrace_detach, ptrace_syscall, traceme, waitpid};
use ptrace::registers::get_regs;

// Parse PIDs from a string that may contain comma, space, tab, or newline separated values
fn parse_pids(pid_str: &str) -> Vec<i32> {
    pid_str
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<i32>().ok())
        .collect()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: strace [-v] [-p pid] <command> [args...]");
        eprintln!("       strace -p pid [-p pid...] [-v]");
        return;
    }

    // Parse command-line options
    let mut verbose = false;
    let mut attach_pids: Vec<i32> = Vec::new();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-v" | "--verbose" => {
                verbose = true;
                i += 1;
            }
            "-p" | "--attach" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: -p option requires a PID argument");
                    return;
                }
                i += 1;
                let pids = parse_pids(&args[i]);
                if pids.is_empty() {
                    eprintln!("Error: Invalid PID(s): {}", args[i]);
                    return;
                }
                attach_pids.extend(pids);
                i += 1;
            }
            _ => break,
        }
    }

    // Determine mode: attach to existing process or run a command
    if !attach_pids.is_empty() {
        // Attach mode
        if verbose {
            eprintln!("strace: Attaching to process(es): {:?}", attach_pids);
        }
        trace_attached_processes(attach_pids, verbose);
    } else {
        // Run command mode
        if i >= args.len() {
            eprintln!("Error: No command specified");
            eprintln!("Usage: strace [-v] [-p pid] <command> [args...]");
            return;
        }
        let command = &args[i];
        let command_args = &args[i + 1..];
        trace_command(command, command_args, verbose);
    }
}

fn trace_command(command: &str, command_args: &[String], verbose: bool) {
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

            trace_syscalls(pid, verbose, false);
        }
    }
}

fn trace_attached_processes(pids: Vec<i32>, verbose: bool) {
    // Set up signal handler for CTRL-C to detach gracefully
    unsafe {
        // Store PIDs in global for signal handler access
        ATTACHED_PIDS.lock().unwrap().clear();
        ATTACHED_PIDS.lock().unwrap().extend_from_slice(&pids);

        libc::signal(libc::SIGINT, handle_sigint as libc::sighandler_t);
    }

    // Attach to all processes
    for &pid in &pids {
        if verbose {
            eprintln!("strace: Attaching to PID {}...", pid);
        }
        if let Err(e) = ptrace_attach(pid) {
            eprintln!("strace: Failed to attach to PID {}: {}", pid, e);
            continue;
        }

        // Wait for the process to stop (from SIGSTOP sent by PTRACE_ATTACH)
        let mut status = 0;
        if let Err(e) = waitpid(pid, &mut status, 0) {
            eprintln!("strace: waitpid failed for PID {}: {}", pid, e);
            let _ = ptrace_detach(pid);
            continue;
        }

        if verbose {
            eprintln!("strace: Attached to PID {}, beginning trace...", pid);
        }
    }

    // For simplicity, trace only the first PID for now
    // TODO: Support tracing multiple processes concurrently
    if let Some(&first_pid) = pids.first() {
        trace_syscalls(first_pid, verbose, true);
    }
}

// Global variable for tracking attached PIDs for signal handler
static ATTACHED_PIDS: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

extern "C" fn handle_sigint(_: i32) {
    // Detach from all processes
    if let Ok(pids) = ATTACHED_PIDS.lock() {
        for &pid in pids.iter() {
            unsafe {
                // Direct libc call since we're in signal handler
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
            }
        }
    }

    eprintln!("\nstrace: Detached from processes, exiting...");
    unsafe {
        libc::_exit(0);
    }
}

fn trace_syscalls(pid: i32, verbose: bool, is_attached: bool) {
    let mut syscall_count = 0;
    let mut is_entry = true; // Track if we're on entry (true) or exit (false)
    let mut pending_output = String::new(); // Store syscall entry output
    let mut current_syscall = String::new(); // Track current syscall name
    let mut current_syscall_nr: i64 = -1; // Track current syscall number
    let mut read_params: (u64, u64, u64) = (0, 0, 0); // Store read(fd, buf, count)
    let mut status = 0;

    // Start syscall tracing
    if let Err(e) = ptrace_syscall(pid) {
        eprintln!("strace: Initial ptrace_syscall failed: {}", e);
        if is_attached {
            let _ = ptrace_detach(pid);
        }
        return;
    }

    // Wait for first syscall stop
    if let Err(e) = waitpid(pid, &mut status, 0) {
        eprintln!("strace: Initial waitpid failed: {}", e);
        if is_attached {
            let _ = ptrace_detach(pid);
        }
        return;
    }

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

    // Detach if we attached to this process
    if is_attached {
        if verbose {
            eprintln!("strace: Detaching from PID {}...", pid);
        }
        let _ = ptrace_detach(pid);
    }
}
