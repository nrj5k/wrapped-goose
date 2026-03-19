## Library: seccompiler

### What it does

Seccompiler is a Rust crate that provides high-level wrappers for creating Linux seccomp-bpf filters. It compiles seccomp filters (defined via JSON or Rust code) into BPF programs ready to be loaded into the kernel.

### Why use it

- Avoids writing BPF instructions by hand (error-prone)
- Supports both JSON and Rust-based filter definitions
- Handles architecture-specific validation automatically
- Provides safe wrappers around `prctl` and `seccomp` syscalls

### Basic Usage

```rust
use seccompiler::BpfMap;
use std::fs::File;

let input_file = File::open("filter.json").expect("Failed to open");
let arch = seccompiler::TargetArch::x86_64;

// Compile JSON to BPF program map
let filters: BpfMap = seccompiler::compile_from_json(input_file, arch)
    .expect("Failed to compile");

// Extract specific filter
let bpf_program = filters.get("main_thread")
    .expect("Missing filter");

// Convert to raw bytes for file output
let bytes = unsafe {
    std::slice::from_raw_parts(
        bpf_program.as_ptr() as *const u8,
        bpf_program.len() * std::mem::size_of::<seccompiler::sock_filter>(),
    )
};

std::fs::write("output.bpf", bytes).expect("Failed to write");
```

### Key APIs

- `compile_from_json(reader, arch)` - Compiles JSON filter to `BpfMap`
- `BpfMap` - `HashMap<String, BpfProgram>` mapping filter names to programs
- `BpfProgram` - `Vec<sock_filter>` sequence of BPF instructions
- `sock_filter` - 8-byte BPF instruction struct: `{ code: u16, jt: u8, jf: u8, k: u32 }`
- `apply_filter(bpf_program)` - Installs filter on current thread
- `TargetArch` - Architecture enum (x86_64, aarch64, riscv64)

### Common Patterns

**Converting BpfProgram to raw bytes:**

```rust
// Each sock_filter is 8 bytes (little-endian)
let bytes = unsafe {
    std::slice::from_raw_parts(
        bpf_program.as_ptr() as *const u8,
        bpf_program.len() * std::mem::size_of::<seccompiler::sock_filter>(),
    )
};
```

**Installing filter directly:**

```rust
seccompiler::apply_filter(bpf_program).unwrap();
```

**Defining filters in Rust:**

```rust
use seccompiler::{SeccompFilter, SeccompAction, SeccompRule};

let filter: BpfProgram = SeccompFilter::new(
    vec![(libc::SYS_accept4, vec![])],
    SeccompAction::Allow,
    SeccompAction::Trap,
    TargetArch::x86_64,
).unwrap().try_into().unwrap();
```

### sock_filter Structure

Each BPF instruction is 8 bytes:

```c
struct sock_filter {
    __u16 code;  // Operation code
    __u8  jt;    // Jump if true offset
    __u8  jf;    // Jump if false offset
    __u32 k;     // Immediate operand
};
```

Total size: 2 + 1 + 1 + 4 = 8 bytes per instruction

### Source

- [GitHub](https://github.com/rust-vmm/seccompiler)
- [docs.rs](https://docs.rs/seccompiler/latest/seccompiler/)
- [JSON Format](https://github.com/rust-vmm/seccompiler/blob/master/docs/json_format.md)
