// Helper function to read a word from tracee memory using PTRACE_PEEKDATA
pub unsafe fn peek_data(pid: i32, addr: u64) -> Result<u64, ()> {
    let result = libc::ptrace(libc::PTRACE_PEEKDATA, pid, addr as *mut libc::c_void, 0);
    if result == -1 {
        Err(())
    } else {
        Ok(result as u64)
    }
}

// Helper function to read a null-terminated string from tracee memory
pub unsafe fn read_string(pid: i32, addr: u64, max_len: usize) -> String {
    if addr == 0 {
        return "NULL".to_string();
    }

    let mut result = Vec::new();
    let mut current_addr = addr;

    for _ in 0..(max_len / 8 + 1) {
        match peek_data(pid, current_addr) {
            Ok(word) => {
                // Extract bytes from the word (little-endian)
                let bytes = word.to_le_bytes();
                for &byte in &bytes {
                    if byte == 0 {
                        // Found null terminator
                        if result.is_empty() {
                            return "\"\"".to_string();
                        }
                        return format!("\"{}\"", String::from_utf8_lossy(&result));
                    }
                    result.push(byte);
                    if result.len() >= max_len {
                        return format!("\"{}\"...", String::from_utf8_lossy(&result));
                    }
                }
                current_addr += 8;
            }
            Err(_) => {
                return format!("<invalid-ptr-{:#x}>", addr);
            }
        }
    }

    format!("\"{}\"...", String::from_utf8_lossy(&result))
}

// Helper function to escape special characters for display
fn escape_string(bytes: &[u8]) -> String {
    let mut result = String::new();
    for &byte in bytes {
        match byte {
            b'\n' => result.push_str("\\n"),
            b'\r' => result.push_str("\\r"),
            b'\t' => result.push_str("\\t"),
            b'\\' => result.push_str("\\\\"),
            b'"' => result.push_str("\\\""),
            b'\0' => result.push_str("\\0"),
            0x20..=0x7e => result.push(byte as char), // Printable ASCII
            _ => result.push_str(&format!("\\x{:02x}", byte)), // Non-printable as hex
        }
    }
    result
}

// Helper function to read fixed-length buffer from tracee memory
pub unsafe fn read_buffer(pid: i32, addr: u64, len: usize) -> String {
    if addr == 0 {
        return "NULL".to_string();
    }

    let mut result = Vec::new();
    let mut current_addr = addr;
    let max_display = len.min(64); // Limit display to 64 bytes

    for _ in 0..((max_display + 7) / 8) {
        match peek_data(pid, current_addr) {
            Ok(word) => {
                let bytes = word.to_le_bytes();
                for &byte in &bytes {
                    if result.len() >= max_display {
                        break;
                    }
                    result.push(byte);
                }
                current_addr += 8;
            }
            Err(_) => {
                return format!("<invalid-ptr-{:#x}>", addr);
            }
        }
    }

    let escaped = escape_string(&result);
    if len > max_display {
        format!("\"{}\"... ({} bytes)", escaped, len)
    } else {
        format!("\"{}\"", escaped)
    }
}
