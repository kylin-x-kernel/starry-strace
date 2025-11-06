// Decode openat flags
pub fn decode_open_flags(flags: u64) -> String {
    let mut parts = Vec::new();
    let access_mode = flags & 0x3;

    match access_mode {
        0 => parts.push("O_RDONLY"),
        1 => parts.push("O_WRONLY"),
        2 => parts.push("O_RDWR"),
        _ => {}
    }

    if flags & 0x40 != 0 {
        parts.push("O_CREAT");
    }
    if flags & 0x80 != 0 {
        parts.push("O_EXCL");
    }
    if flags & 0x200 != 0 {
        parts.push("O_NOCTTY");
    }
    if flags & 0x400 != 0 {
        parts.push("O_TRUNC");
    }
    if flags & 0x800 != 0 {
        parts.push("O_APPEND");
    }
    if flags & 0x1000 != 0 {
        parts.push("O_NONBLOCK");
    }
    if flags & 0x8000 != 0 {
        parts.push("O_LARGEFILE");
    }
    if flags & 0x10000 != 0 {
        parts.push("O_DIRECTORY");
    }
    if flags & 0x20000 != 0 {
        parts.push("O_NOFOLLOW");
    }
    if flags & 0x80000 != 0 {
        parts.push("O_CLOEXEC");
    }

    if parts.is_empty() {
        format!("{:#x}", flags)
    } else {
        parts.join("|")
    }
}

// Decode dirfd value
pub fn decode_dirfd(dfd: u64) -> String {
    if dfd == 0xffffffffffffff9c || dfd as i32 == -100 {
        "AT_FDCWD".to_string()
    } else {
        format!("{}", dfd as i32)
    }
}

// Decode mmap protection flags
pub fn decode_prot_flags(prot: u64) -> String {
    let mut parts = Vec::new();
    if prot & 0x1 != 0 {
        parts.push("PROT_READ");
    }
    if prot & 0x2 != 0 {
        parts.push("PROT_WRITE");
    }
    if prot & 0x4 != 0 {
        parts.push("PROT_EXEC");
    }
    if prot == 0 {
        return "PROT_NONE".to_string();
    }
    if parts.is_empty() {
        format!("{:#x}", prot)
    } else {
        parts.join("|")
    }
}

// Decode mmap flags
pub fn decode_mmap_flags(flags: u64) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 {
        parts.push("MAP_SHARED");
    }
    if flags & 0x02 != 0 {
        parts.push("MAP_PRIVATE");
    }
    if flags & 0x10 != 0 {
        parts.push("MAP_FIXED");
    }
    if flags & 0x20 != 0 {
        parts.push("MAP_ANONYMOUS");
    }
    if parts.is_empty() {
        format!("{:#x}", flags)
    } else {
        parts.join("|")
    }
}
