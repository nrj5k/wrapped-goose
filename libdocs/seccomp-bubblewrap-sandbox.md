# Seccomp Filtering with Bubblewrap for Development Sandboxes

## Research Summary

This document provides comprehensive guidance on implementing seccomp (Secure Computing Mode) filtering with bubblewrap (bwrap) for secure development sandboxes.

---

## 1. How to Use Seccomp with Bubblewrap

### Command-Line Options

Bubblewrap supports two seccomp-related options (verified via `bwrap --help`):

```bash
--seccomp FD                 Load and use seccomp rules from FD (not repeatable)
--add-seccomp-fd FD          Load and use seccomp rules from FD (repeatable)
```

### Key Points

- **File Descriptor (FD)**: bwrap expects a file descriptor, not a file path
- **Not Repeatable vs Repeatable**: `--seccomp` can only be used once, `--add-seccomp-fd` can be used multiple times to layer filters
- **Pre-filtering**: The seccomp filter must be loaded by the parent process before execing bwrap

### Usage Pattern

```bash
# Pattern 1: Using process substitution with exec
exec 3<seccomp-filter.bpf
bwrap --seccomp 3 --ro-bind /usr /usr -- bash
exec 3<&-

# Pattern 2: Using a helper script to load filter
#!/bin/bash
BPF_FD=$(bpf-loader seccomp-filter.bpf)
bwrap --seccomp $BPF_FD --ro-bind /usr /usr -- "$@"
```

### Important Notes from Official Documentation

From the [bubblewrap README](https://github.com/containers/bubblewrap):

> "Seccomp filters: You can pass in seccomp filters that limit which syscalls can be done in the sandbox."

> **Critical Limitation**: "If you limit the syscalls and don't allow the seccomp syscall, a browser cannot apply these restrictions."

This means if the sandboxed application needs to install its own seccomp filters, you must allow the `seccomp` syscall.

---

## 2. Syscalls to Block for Security

### 2.1 Raw Socket Creation (Packet Crafting)

**Block these syscalls to prevent raw socket creation:**

| Syscall | Number (x86_64) | Purpose |
|---------|-----------------|---------|
| `socket` | 41 | Create socket (check domain/type) |
| `socketpair` | 53 | Create pair of sockets |
| `bind` | 49 | Bind name to socket |
| `connect` | 42 | Connect socket |
| `listen` | 50 | Listen for connections |
| `accept` | 43 | Accept connection |
| `sendto` | 44 | Send data |
| `recvfrom` | 45 | Receive data |
| `setsockopt` | 54 | Set socket options |
| `getsockopt` | 55 | Get socket options |

**Verified with libseccomp:**
```bash
$ scmp_sys_resolver -a x86_64 socket
41
$ scmp_sys_resolver -a x86_64 socketpair
53
```

### 2.2 Tunneling Tool Prevention

**Block execution-related syscalls or specific binaries:**

Note: Seccomp cannot directly block specific binaries. Instead, combine with:
- Filesystem isolation (don't bind-mount nc, netcat, socat, telnet)
- AppArmor/SELinux for path-based restrictions

**Syscalls that enable network tools:**
| Syscall | Number | Purpose |
|---------|--------|---------|
| `socket` | 41 | Required for all network tools |
| `connect` | 42 | TCP/UDP connections |
| `execve` | 59 | Execute programs (if you want to block specific tools) |

### 2.3 Kernel Module Loading

**Critical syscalls to block:**

| Syscall | Number (x86_64) | Purpose |
|---------|-----------------|---------|
| `init_module` | 175 | Load kernel module |
| `finit_module` | 313 | Load module from fd |
| `delete_module` | 106 | Unload module |
| `kexec_load` | 246 | Load new kernel |
| `kexec_file_load` | 320 | Load new kernel from fd |
| `reboot` | 169 | Reboot system |

**Verified:**
```bash
$ scmp_sys_resolver -a x86_64 init_module
175
$ scmp_sys_resolver -a x86_64 ptrace
101
```

### 2.4 Process Injection/Debugging

**Block these to prevent process manipulation:**

| Syscall | Number | Purpose |
|---------|--------|---------|
| `ptrace` | 101 | Process tracing/debugging |
| `process_vm_readv` | 310 | Read from another process |
| `process_vm_writev` | 311 | Write to another process |
| `personality` | 135 | Change execution domain |
| `syslog` | 103 | Access kernel log |

### 2.5 Other Sandbox Escape Techniques

**Block these additional dangerous syscalls:**

| Syscall | Number | Risk |
|---------|--------|------|
| `mount` | 165 | Mount filesystems |
| `umount2` | 166 | Unmount filesystems |
| `pivot_root` | 155 | Change root filesystem |
| `chroot` | 161 | Change root directory |
| `mknod` | 133 | Create device files |
| `mknodat` | 259 | Create device files (at fd) |
| `swapon` | 167 | Enable swap |
| `swapoff` | 168 | Disable swap |
| `acct` | 172 | Process accounting |
| `sethostname` | 170 | Set hostname |
| `setdomainname` | 171 | Set NIS name |
| `iopl` | 172 | I/O privilege level |
| `ioperm` | 173 | I/O port permissions |
| `init_module` | 175 | Kernel modules |
| `create_module` | 174 | Create module |
| `query_module` | 177 | Query modules |
| `nfsservctl` | 179 | NFS control |
| `get_kernel_syms` | 177 | Kernel symbols |
| `uselib` | 134 | Load shared library |
| `userfaultfd` | 323 | User fault handling |

---

## 3. Seccomp Filter File Format

### 3.1 BPF (Berkeley Packet Filter) Structure

Seccomp filters use BPF programs. The structure from [seccomp(2) man page](https://www.man7.org/linux/man-pages/man2/seccomp.2.html):

```c
struct sock_fprog {
    unsigned short      len;    /* Number of BPF instructions */
    struct sock_filter *filter; /* Pointer to array of BPF instructions */
};

struct sock_filter {            /* Filter block */
    __u16 code;                 /* Actual filter code */
    __u8  jt;                   /* Jump true */
    __u8  jf;                   /* Jump false */
    __u32 k;                    /* Generic multiuse field */
};
```

### 3.2 BPF Instruction Format

Each BPF instruction operates on `struct seccomp_data`:

```c
struct seccomp_data {
    int   nr;                   /* System call number */
    __u32 arch;                 /* AUDIT_ARCH_* value */
    __u64 instruction_pointer;  /* CPU instruction pointer */
    __u64 args[6];              /* Up to 6 system call arguments */
};
```

### 3.3 Return Values (Actions)

From highest to lowest precedence:

| Action | Value | Effect |
|--------|-------|--------|
| `SECCOMP_RET_KILL_PROCESS` | 0x80000000 | Kill entire process |
| `SECCOMP_RET_KILL_THREAD` | 0x00000000 | Kill calling thread |
| `SECCOMP_RET_TRAP` | 0x00030000 | Send SIGSYS signal |
| `SECCOMP_RET_ERRNO` | 0x00050000 | Return specified errno |
| `SECCOMP_RET_USER_NOTIF` | 0x7fc00000 | Notify userspace supervisor |
| `SECCOMP_RET_TRACE` | 0x7ff00000 | Notify ptrace tracer |
| `SECCOMP_RET_LOG` | 0x7ffc0000 | Log and allow |
| `SECCOMP_RET_ALLOW` | 0x7fff0000 | Allow syscall |

### 3.4 BPF Code Constants

| Code | Value | Meaning |
|------|-------|---------|
| `BPF_LD` | 0x00 | Load |
| `BPF_W` | 0x00 | Word (4 bytes) |
| `BPF_ABS` | 0x20 | Absolute addressing |
| `BPF_JMP` | 0x05 | Jump |
| `BPF_JEQ` | 0x14 | Jump if equal |
| `BPF_JGT` | 0x20 | Jump if greater than |
| `BPF_RET` | 0x06 | Return |

### 3.5 Tools to Generate Filters

#### libseccomp and scmp_sys_resolver

[libseccomp](https://github.com/seccomp/libseccomp) provides high-level API:

```bash
# Convert syscall name to number
scmp_sys_resolver -a x86_64 socket      # Returns: 41
scmp_sys_resolver -a x86_64 ptrace      # Returns: 101
scmp_sys_resolver -a x86_64 init_module # Returns: 175

# Reverse lookup (number to name)
scmp_sys_resolver -a x86_64 -t 41       # Returns: socket
scmp_sys_resolver -a x86_64 -t 101      # Returns: ptrace
```

#### Using libseccomp Programmatically (C)

```c
#include <seccomp.h>

scmp_filter_ctx ctx;
ctx = seccomp_init(SCMP_ACT_ALLOW);  // Default: allow all

// Block specific syscalls
seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 0);
seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0);

// Load the filter
seccomp_load(ctx);
```

#### Python (using python-seccomp)

```python
import seccomp

# Create filter with default allow
filter = seccomp.SyscallFilter(seccomp.ALLOW)

# Add deny rules
filter.add_rule(seccomp.KILL_THREAD, "socket")
filter.add_rule(seccomp.KILL_THREAD, "ptrace")
filter.add_rule(seccomp.KILL_THREAD, "init_module")

# Load filter
filter.load()
```

---

## 4. Best Practices

### 4.1 Essential Syscalls to ALLOW for Development

For a typical development environment, these syscalls must be allowed:

#### File Operations
| Syscall | Purpose |
|---------|---------|
| `open` / `openat` | Open files |
| `read` | Read from file descriptor |
| `write` | Write to file descriptor |
| `close` | Close file descriptor |
| `stat` / `fstat` / `lstat` | Get file status |
| `access` | Check file accessibility |
| `getcwd` | Get working directory |
| `getdents` / `getdents64` | Read directory |
| `dup` / `dup2` / `dup3` | Duplicate fd |
| `fcntl` | File descriptor operations |
| `ioctl` | Device I/O control |
| `mmap` | Map files into memory |
| `munmap` | Unmap memory |
| `mprotect` | Set memory protection |
| `brk` | Change data segment size |

#### Process Operations
| Syscall | Purpose |
|---------|---------|
| `execve` | Execute program |
| `exit` / `exit_group` | Exit process |
| `wait4` | Wait for child |
| `clone` | Create process |
| `fork` / `vfork` | Create child process |
| `getpid` / `getppid` | Get process IDs |
| `getuid` / `geteuid` | Get user IDs |
| `getgid` / `getegid` | Get group IDs |
| `getgroups` | Get supplementary groups |
| `setuid` / `setgid` | Set user/group IDs |
| `prctl` | Process control (needed for NO_NEW_PRIVS) |
| `rt_sigaction` | Signal handling |
| `rt_sigprocmask` | Signal mask |
| `rt_sigreturn` | Return from signal |

#### Memory Operations
| Syscall | Purpose |
|---------|---------|
| `mmap` | Memory mapping |
| `munmap` | Unmapping |
| `mprotect` | Protection changes |
| `madvise` | Memory advice |
| `brk` | Heap management |

#### Network (if needed)
| Syscall | Purpose |
|---------|---------|
| `socket` | Create socket |
| `connect` | Connect |
| `bind` | Bind address |
| `listen` | Listen |
| `accept` | Accept connection |
| `sendto` / `sendmsg` | Send data |
| `recvfrom` / `recvmsg` | Receive data |
| `getsockname` | Get socket name |
| `getpeername` | Get peer name |
| `shutdown` | Shutdown socket |

#### Time Operations
| Syscall | Purpose |
|---------|---------|
| `clock_gettime` | Get clock time |
| `gettimeofday` | Get time of day |
| `nanosleep` | High-resolution sleep |
| `clock_nanosleep` | Clock-based sleep |

### 4.2 Common Pitfalls

#### 1. Architecture Checking

From [seccomp_filter documentation](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html):

> "The biggest pitfall to avoid during use is filtering on system call number without checking the architecture value."

Always check the `arch` field to prevent bypasses on multi-arch systems.

#### 2. vDSO Syscalls

Some syscalls may be handled entirely in userspace via vDSO:
- `clock_gettime`
- `gettimeofday`
- `time`

These may not trigger seccomp filters on some systems.

#### 3. Wrapper Function Differences

Glibc wrappers may use different syscalls than expected:
- `exit()` uses `exit_group` syscall
- `fork()` uses `clone` syscall
- `open()` may use `openat` syscall (glibc 2.26+)

#### 4. TIOCSTI Attack

From bubblewrap documentation:

> "If you are not filtering out `TIOCSTI` commands using seccomp filters, argument `--new-session` is needed to protect against out-of-sandbox command execution (see CVE-2017-5226)."

Block `ioctl` with `TIOCSTI` request or use `--new-session`.

#### 5. D-Bus Escape Vector

> "Everything mounted into the sandbox can potentially be used to escalate privileges. For example, if you bind a D-Bus socket into the sandbox, it can be used to execute commands via systemd."

Use `xdg-dbus-proxy` to filter D-Bus communication.

#### 6. ptrace Escape

From man page:

> "seccomp-based sandboxes MUST NOT allow use of ptrace, even of other sandboxed processes, without extreme care; ptracers can use this mechanism to escape."

Always block `ptrace` unless absolutely needed.

### 4.3 Recommended Approach

**Use allow-list (whitelist) approach:**

```
Default action: KILL or TRAP
Explicitly allow: Only known-needed syscalls
```

This is more secure than deny-list because:
- New dangerous syscalls are automatically blocked
- No need to update when kernel adds syscalls
- Simpler to audit

---

## 5. Examples

### 5.1 Minimal Development Sandbox Seccomp Profile

```c
// seccomp-dev-filter.c
#include <seccomp.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    scmp_filter_ctx ctx;
    
    // Start with default KILL action (deny all)
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) {
        fprintf(stderr, "seccomp_init failed\n");
        return 1;
    }
    
    // Set NO_NEW_PRIVS before loading filter
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl");
        return 1;
    }
    
    // Allow essential file operations
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
    
    // Allow memory operations
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);
    
    // Allow process operations
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
    
    // Allow signal handling
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    
    // Allow time operations
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
    
    // Allow stat family
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlinkat), 0);
    
    // Explicitly block dangerous syscalls (defense in depth)
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(init_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(finit_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(delete_module), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kexec_load), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socketpair), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(umount2), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(pivot_root), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(swapon), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(swapoff), 0);
    
    // Load the filter
    seccomp_load(ctx);
    
    // Execute the sandboxed command
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }
    
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 1;
}
```

### 5.2 Complete bwrap Command with Seccomp

```bash
#!/bin/bash
# run-sandbox.sh - Launch development sandbox with seccomp

SECCOMP_FILTER="/path/to/seccomp-filter.bpf"
SANDBOX_ROOT="/tmp/sandbox"

# Create minimal sandbox filesystem
mkdir -p "$SANDBOX_ROOT"/{bin,lib,lib64,usr,tmp,home,proc,dev}

# Copy essential binaries
cp /bin/bash "$SANDBOX_ROOT/bin/"
cp /bin/ls "$SANDBOX_ROOT/bin/"
cp /bin/cat "$SANDBOX_ROOT/bin/"
# Copy any other needed tools...

# Copy shared libraries (use ldd to find dependencies)
ldd /bin/bash | grep -o '/[^ ]*' | sort -u | while read lib; do
    mkdir -p "$SANDBOX_ROOT$(dirname $lib)"
    cp -n "$lib" "$SANDBOX_ROOT$lib" 2>/dev/null
done

# Create device nodes
mknod -m 666 "$SANDBOX_ROOT/dev/null" c 1 3
mknod -m 666 "$SANDBOX_ROOT/dev/zero" c 1 5
mknod -m 666 "$SANDBOX_ROOT/dev/random" c 1 8
mknod -m 666 "$SANDBOX_ROOT/dev/urandom" c 1 9
mknod -m 666 "$SANDBOX_ROOT/dev/tty" c 5 0
mknod -m 620 "$SANDBOX_ROOT/dev/ptmx" c 5 2

# Mount proc
mount -t proc proc "$SANDBOX_ROOT/proc"

# Load seccomp filter and run bwrap
exec 3<"$SECCOMP_FILTER"

bwrap \
    --seccomp 3 \
    --ro-bind /usr "$SANDBOX_ROOT/usr" \
    --bind "$SANDBOX_ROOT/tmp" /tmp \
    --bind "$SANDBOX_ROOT/home" /home \
    --dev /dev \
    --proc /proc \
    --unshare-pid \
    --unshare-ipc \
    --unshare-cgroup \
    --unshare-uts \
    --hostname sandbox \
    --new-session \
    --chdir /home \
    -- "$SANDBOX_ROOT/bin/bash"

exec 3<&-
```

### 5.3 Python Seccomp Filter Generator

```python
#!/usr/bin/env python3
"""
Generate seccomp BPF filter for development sandbox
"""

import seccomp

def create_dev_sandbox_filter():
    """Create a seccomp filter for development sandbox"""
    
    # Start with default KILL action
    filter = seccomp.SyscallFilter(seccomp.KILL_PROCESS)
    
    # File operations - allow
    file_syscalls = [
        "openat", "read", "write", "close", "lseek", "access",
        "fstat", "lstat", "stat", "newfstatat", "getcwd",
        "getdents", "getdents64", "readlink", "readlinkat",
        "dup", "dup2", "dup3", "fcntl", "ioctl",
        "mmap", "munmap", "mprotect", "madvise", "brk",
    ]
    
    for syscall in file_syscalls:
        filter.add_rule(seccomp.ALLOW, syscall)
    
    # Process operations - allow
    process_syscalls = [
        "execve", "exit", "exit_group", "wait4", "waitid",
        "getpid", "getppid", "getuid", "geteuid", "getgid",
        "getegid", "getgroups", "prctl", "arch_prctl",
    ]
    
    for syscall in process_syscalls:
        filter.add_rule(seccomp.ALLOW, syscall)
    
    # Signal handling - allow
    signal_syscalls = [
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "rt_sigtimedwait", "tgkill", "kill",
    ]
    
    for syscall in signal_syscalls:
        filter.add_rule(seccomp.ALLOW, syscall)
    
    # Time operations - allow
    time_syscalls = [
        "clock_gettime", "gettimeofday", "nanosleep",
        "clock_nanosleep", "getitimer", "setitimer",
    ]
    
    for syscall in time_syscalls:
        filter.add_rule(seccomp.ALLOW, syscall)
    
    # Explicitly block dangerous syscalls
    dangerous_syscalls = [
        # Process injection
        "ptrace", "process_vm_readv", "process_vm_writev",
        # Kernel modules
        "init_module", "finit_module", "delete_module",
        "create_module", "query_module",
        # Kernel execution
        "kexec_load", "kexec_file_load", "reboot",
        # Filesystem manipulation
        "mount", "umount2", "pivot_root", "chroot",
        "mknod", "mknodat",
        # Swap
        "swapon", "swapoff",
        # System identity
        "sethostname", "setdomainname",
        # Raw sockets (block all socket creation)
        "socket", "socketpair", "accept", "connect",
        "bind", "listen", "sendto", "recvfrom",
        # I/O privileges
        "iopl", "ioperm",
        # Accounting
        "acct",
        # Userfaultfd (can be used for escapes)
        "userfaultfd",
    ]
    
    for syscall in dangerous_syscalls:
        filter.add_rule(seccomp.KILL_PROCESS, syscall)
    
    return filter

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: {} <output.bpf> [command...]".format(sys.argv[0]))
        sys.exit(1)
    
    output_file = sys.argv[1]
    
    # Create and export filter
    filter = create_dev_sandbox_filter()
    filter.export_bpf(output_file)
    
    print(f"Seccomp filter written to {output_file}")
    print("Use with: bwrap --seccomp 3 < filter.bpf -- <command>")
```

### 5.4 Example from valoq/bwscripts

From the [bwscripts repository](https://github.com/valoq/bwscripts):

```bash
#!/bin/bash
# Example bubblewrap profile with seccomp

# Generate seccomp filter using exportFilter tool
./exportFilter > /tmp/bwrap-seccomp.bpf

# Run application with bubblewrap
bwrap \
    --seccomp 3 \
    --ro-bind /usr /usr \
    --ro-bind /etc /etc \
    --bind /tmp /tmp \
    --dev /dev \
    --proc /proc \
    --unshare-pid \
    --unshare-net \
    --hostname sandbox \
    --new-session \
    -- "$@"
```

### 5.5 Docker Default Seccomp Profile Reference

Docker's default seccomp profile (for reference) blocks ~44 syscalls out of 300+:

**Blocked syscalls include:**
- `acctp`, `add_key`, `bpf`, `clock_settime`
- `create_module`, `delete_module`, `finit_module`, `init_module`
- `iopl`, `ioperm`
- `kexec_load`, `kexec_file_load`
- `keyctl`, `lookup_dcookie`, `mknod`, `mknodat`
- `mount`, `umount`, `umount2`
- `nfsservctl`, `open_by_handle_at`
- `personality`, `pivot_root`, `process_vm_readv`, `process_vm_writev`
- `ptrace`, `query_module`, `reboot`, `renameat2`
- `request_key`, `sethostname`, `setdomainname`
- `swapon`, `swapoff`, `syslog`
- `uselib`, `userfaultfd`, `vm86`, `vm86old`

Source: [Docker seccomp profiles](https://github.com/docker/engine/blob/master/profiles/seccomp/default.json)

---

## 6. Quick Reference: Syscall Numbers (x86_64)

### Critical Block List

| Syscall | Number | Category |
|---------|--------|----------|
| `socket` | 41 | Network |
| `socketpair` | 53 | Network |
| `connect` | 42 | Network |
| `ptrace` | 101 | Debug |
| `process_vm_readv` | 310 | Process |
| `process_vm_writev` | 311 | Process |
| `init_module` | 175 | Kernel |
| `finit_module` | 313 | Kernel |
| `delete_module` | 106 | Kernel |
| `kexec_load` | 246 | Kernel |
| `mount` | 165 | FS |
| `pivot_root` | 155 | FS |
| `mknod` | 133 | FS |
| `swapon` | 167 | System |

### Use scmp_sys_resolver for lookup:

```bash
# Name to number
scmp_sys_resolver -a x86_64 <syscall_name>

# Number to name
scmp_sys_resolver -a x86_64 -t <number>
```

---

## Sources

1. [Bubblewrap GitHub](https://github.com/containers/bubblewrap)
2. [Linux Kernel Seccomp Documentation](https://www.kernel.org/doc/html/v4.19/userspace-api/seccomp_filter.html)
3. [seccomp(2) man page](https://www.man7.org/linux/man-pages/man2/seccomp.2.html)
4. [libseccomp GitHub](https://github.com/seccomp/libseccomp)
5. [valoq/bwscripts](https://github.com/valoq/bwscripts)
6. [Docker seccomp profiles](https://github.com/docker/engine/blob/master/profiles/seccomp/default.json)

---

*Generated: 2026-03-19*
*Research conducted using searxng, webfetch, and official documentation sources*
