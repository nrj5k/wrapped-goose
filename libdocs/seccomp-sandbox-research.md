# Seccomp Filter Research for AI Agent Sandbox

**Research Date:** March 19, 2026
**Purpose:** Additional syscalls to block for Goose AI agent bubblewrap sandbox

## Executive Summary

Based on analysis of Docker's default seccomp profile, Chrome/Chromium sandbox, Firejail, and kernel security documentation, here are the recommended additional syscalls to block beyond your current list.

---

## 1. Privilege Escalation Syscalls

### Recommendation: **ALLOW with caveats** (or BLOCK if running as unprivileged user)

| Syscall | Docker Default | Rationale |
|---------|---------------|-----------|
| `setuid`, `setuid32` | ALLOWED | Namespace-aware; only affects processes in same user namespace |
| `setgid`, `setgid32` | ALLOWED | Namespace-aware |
| `setreuid`, `setreuid32` | ALLOWED | Namespace-aware |
| `setregid`, `setregid32` | ALLOWED | Namespace-aware |
| `setresuid`, `setresuid32` | ALLOWED | Namespace-aware |
| `setresgid`, `setresgid32` | ALLOWED | Namespace-aware |
| `setfsgid`, `setfsgid32` | ALLOWED | Namespace-aware |
| `setfsuid`, `setfsuid32` | ALLOWED | Namespace-aware |
| `capset` | ALLOWED | Namespace-aware; requires CAP_CAPABILITY |
| `capget` | ALLOWED | Read-only; no security risk |

**Why Docker allows these:**
- In container environments with user namespaces, these calls only affect the namespace
- Real protection comes from dropping capabilities and running as non-root
- Many legitimate applications need to drop privileges after startup

**For your AI agent sandbox:**
- **If running bubblewrap with `--uid 0 --gid 0` (fake root):** These are safe to allow
- **If running as your regular user:** Consider blocking to prevent confusion
- **Critical:** Ensure bubblewrap is invoked with `--no-new-privs` flag

```bash
# Recommended bubblewrap invocation
bwrap --no-new-privs \
      --seccomp "seccomp-filter.bpf" \
      --uid 0 --gid 0 \
      --ro-bind /usr /usr \
      ...
```

---

## 2. Process Control Syscalls

### Recommendation: **BLOCK** (prevent killing other processes)

| Syscall | Docker Default | Risk | Recommendation |
|---------|---------------|------|----------------|
| `kill` | ALLOWED | Can send signals to other processes | **BLOCK** |
| `tkill` | ALLOWED | Thread-specific kill | **BLOCK** |
| `tgkill` | ALLOWED | Thread group kill | **BLOCK** |
| `rt_sigqueueinfo` | ALLOWED | Send arbitrary signals | **BLOCK** |
| `rt_tgsigqueueinfo` | ALLOWED | Thread-specific signal queue | **BLOCK** |

**Why block:**
- AI-generated code could maliciously or accidentally kill host processes
- Bubblewrap PID namespace provides isolation, but defense-in-depth is valuable
- Legitimate code rarely needs to send signals outside its process group

**Implementation:**
```c
// Block all signal-sending syscalls
SCMP_ACT_ERRNO, kill
SCMP_ACT_ERRNO, tkill
SCMP_ACT_ERRNO, tgkill
SCMP_ACT_ERRNO, rt_sigqueueinfo
SCMP_ACT_ERRNO, rt_tgsigqueueinfo
```

**Exception:** Allow if the AI agent needs to manage child processes it spawns.

---

## 3. Namespace Syscalls

### Recommendation: **BLOCK** (primary escape vector)

| Syscall | Docker Default | Risk | Recommendation |
|---------|---------------|------|----------------|
| `unshare` | BLOCKED* | Create new namespaces | **BLOCK** |
| `setns` | BLOCKED* | Join existing namespaces | **BLOCK** |
| `clone` | RESTRICTED | Fork with namespace flags | **RESTRICT** |
| `clone3` | BLOCKED* | Modern clone with namespace flags | **BLOCK** |

*Docker allows with CAP_SYS_ADMIN

**Why block:**
- **`unshare()`** can create new mount/user/PID/network namespaces
- Combined with setuid mappings, can escape bubblewrap isolation
- **`setns()`** can join host namespaces if file descriptors are leaked
- **`clone()`** with CLONE_NEW* flags creates namespace escapes

**Critical clone flags to block:**
```
CLONE_NEWNS      0x00020000  // Mount namespace
CLONE_NEWCGROUP  0x02000000  // Cgroup namespace
CLONE_NEWIPC     0x08000000  // IPC namespace
CLONE_NEWUSER    0x10000000  // User namespace (most dangerous)
CLONE_NEWPID     0x20000000  // PID namespace
CLONE_NEWNET     0x40000000  // Network namespace
CLONE_NEWTIME    0x00000080  // Time namespace
```

**Implementation:**
```c
// Block unshare/setns completely
SCMP_ACT_ERRNO, unshare
SCMP_ACT_ERRNO, setns

// Allow clone but block namespace creation flags
SCMP_ACT_ALLOW, clone, args[0] & 0x7A020000 == 0  // Block all NEW* flags
```

---

## 4. Dangerous Ioctls

### Recommendation: **BLOCK specific commands** (ioctl too common to block entirely)

| Ioctl Command | Risk | Recommendation |
|--------------|------|----------------|
| `TIOCSTI` (0x5412) | Terminal injection | **BLOCK** |
| `TIOCLINUX` (0x541D) | Linux-specific terminal ops | **BLOCK** |
| `TIOCSCTTY` (0x540E) | Set controlling terminal | **BLOCK** |
| `VT_DISALLOCATE` | Virtual terminal manipulation | **BLOCK** |
| `KDSETMODE` | Console graphics mode | **BLOCK** |

**Why TIOCSTI is dangerous:**
```c
// TIOCSTI can inject arbitrary input into terminal
ioctl(fd, TIOCSTI, "rm -rf /\n");  // Injects command as if typed
```

**Historical exploits:**
- Used in container escapes (CVE-2024-22924, Dirty Pipe variants)
- Can inject commands into root shells if terminal is compromised

**Implementation:**
```c
// Block ioctl entirely (breaks many apps)
SCMP_ACT_ERRNO, ioctl

// OR: Use seccomp notify to filter specific ioctl commands
// This requires userspace handling
```

**Practical approach:** Since `ioctl` is extremely common, consider:
1. Allow ioctl but use seccomp notify to filter dangerous commands
2. Or accept that terminal injection is a risk and mitigate via other controls

---

## 5. BPF-related Syscalls

### Recommendation: **BLOCK** (kernel compromise vector)

| Syscall | Docker Default | Risk | Recommendation |
|---------|---------------|------|----------------|
| `bpf` | BLOCKED* | Load eBPF programs into kernel | **BLOCK** |
| `perf_event_open` | BLOCKED* | Performance monitoring, kernel introspection | **BLOCK** |

*Docker allows with CAP_BPF / CAP_PERFMON

**Why block:**
- **`bpf()`** can load arbitrary kernel code (eBPF programs)
- eBPF can read/write arbitrary kernel memory
- Known escape vector (CVE-2020-8835, CVE-2023-2163)
- **`perf_event_open()`** can introspect kernel and other processes
- Can leak sensitive information from host

**Implementation:**
```c
SCMP_ACT_ERRNO, bpf
SCMP_ACT_ERRNO, perf_event_open
```

---

## 6. Kernel Keyring Syscalls

### Recommendation: **BLOCK** (not namespaced)

| Syscall | Docker Default | Risk | Recommendation |
|---------|---------------|------|----------------|
| `add_key` | BLOCKED | Add keys to kernel keyring | **BLOCK** |
| `request_key` | BLOCKED | Request keys from kernel keyring | **BLOCK** |
| `keyctl` | BLOCKED | Manipulate kernel keyring | **BLOCK** |

**Why block:**
- Kernel keyring is **NOT namespaced**
- Keys are shared across all containers/processes
- Can be used for covert channel communication
- Can leak secrets between isolated environments

**Implementation:**
```c
SCMP_ACT_ERRNO, add_key
SCMP_ACT_ERRNO, request_key
SCMP_ACT_ERRNO, keyctl
```

---

## 7. Other Dangerous Syscalls

### Recommendation: **BLOCK** (based on Docker's profile)

| Syscall | Risk | Recommendation |
|---------|------|----------------|
| `ptrace` | Process inspection/code injection | **BLOCK** (already in your list) |
| `process_vm_readv` | Read another process memory | **BLOCK** |
| `process_vm_writev` | Write another process memory | **BLOCK** |
| `kcmp` | Compare kernel objects | **BLOCK** |
| `pidfd_getfd` | Extract FDs from other processes | **BLOCK** |
| `open_by_handle_at` | File handle escape (CVE-2019-17527) | **BLOCK** |
| `name_to_handle_at` | Get file handles (paired with above) | **BLOCK** |
| `lookup_dcookie` | Kernel memory disclosure | **BLOCK** |
| `acct` | Process accounting manipulation | **BLOCK** |
| `uselib` | Obsolete library loading | **BLOCK** |
| `userfaultfd` | Userspace page fault handling | **BLOCK** |
| `kexec_load` | Load new kernel | **BLOCK** (already in your list) |
| `kexec_file_load` | Load new kernel (file-based) | **BLOCK** (already in your list) |
| `reboot` | Reboot system | **BLOCK** (already in your list) |
| `swapon` | Enable swap | **BLOCK** |
| `swapoff` | Disable swap | **BLOCK** |
| `syslog` | Kernel log access | **BLOCK** |
| `iopl` | I/O privilege level | **BLOCK** |
| `ioperm` | I/O port permissions | **BLOCK** |
| `init_module` | Load kernel module | **BLOCK** (already in your list) |
| `finit_module` | Load kernel module (fd-based) | **BLOCK** (already in your list) |
| `delete_module` | Remove kernel module | **BLOCK** (already in your list) |
| `create_module` | Create kernel module (obsolete) | **BLOCK** |
| `query_module` | Query kernel modules (obsolete) | **BLOCK** |
| `get_kernel_syms` | Get kernel symbols (obsolete) | **BLOCK** |
| `personality` | Change execution domain | **BLOCK** |
| `sysfs` | Sysfs interface (obsolete) | **BLOCK** |
| `_sysctl` | Sysctl interface (obsolete) | **BLOCK** |
| `ustat` | Filesystem statistics (obsolete) | **BLOCK** |
| `nfsservctl` | NFS daemon control (obsolete) | **BLOCK** |
| `vhangup` | Hangup virtual terminal | **BLOCK** |
| `pivot_root` | Change root filesystem | **BLOCK** (already in your list) |
| `chroot` | Change root directory | **BLOCK** |
| `mknod` | Create device nodes | **BLOCK** (already in your list) |
| `mknodat` | Create device nodes (at fd) | **BLOCK** (already in your list) |
| `mount` | Mount filesystems | **BLOCK** (already in your list) |
| `umount2` | Unmount filesystems | **BLOCK** (already in your list) |
| `settimeofday` | Change system time | **BLOCK** |
| `stime` | Set system time (obsolete) | **BLOCK** |
| `clock_settime` | Set clock time | **BLOCK** |
| `clock_adjtime` | Adjust clock time | **BLOCK** |
| `adjtimex` | Adjust kernel time parameters | **BLOCK** |
| `setdomainname` | Set NIS domain name | **BLOCK** |
| `sethostname` | Set hostname | **BLOCK** |
| `quotactl` | Manipulate disk quotas | **BLOCK** |
| `quotactl_fd` | Manipulate disk quotas (fd-based) | **BLOCK** |
| `get_mempolicy` | Query NUMA policy | **BLOCK** |
| `set_mempolicy` | Set NUMA policy | **BLOCK** |
| `mbind` | Bind memory to NUMA nodes | **BLOCK** |
| `move_pages` | Move pages between nodes | **BLOCK** |
| `migrate_pages` | Migrate pages | **BLOCK** |
| `socket` (AF_PACKET) | Raw packet sockets | **BLOCK** (already in your list) |
| `socket` (AF_NETLINK) | Netlink sockets | **BLOCK** (already in your list) |

---

## 8. Docker's Default Seccomp Profile Summary

Docker blocks **~44 syscalls** by default out of 300+. Key categories:

### Always Blocked (no capability):
- Kernel module manipulation: `init_module`, `finit_module`, `delete_module`, `create_module`, `query_module`, `get_kernel_syms`
- Kernel execution: `kexec_load`, `kexec_file_load`, `reboot`
- Namespace manipulation: `unshare`, `setns`, `clone` (with NEW* flags)
- Filesystem escape: `mount`, `umount`, `umount2`, `pivot_root`, `open_by_handle_at`
- Process inspection: `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`
- Kernel keyring: `add_key`, `request_key`, `keyctl`
- BPF: `bpf`, `perf_event_open`
- Time manipulation: `clock_settime`, `settimeofday`, `stime`, `clock_adjtime`, `adjtimex`
- Privileged operations: `acct`, `quotactl`, `swapon`, `swapoff`, `syslog`
- Device/IO: `mknod`, `mknodat`, `iopl`, `ioperm`, `vhangup`
- Obsolete: `uselib`, `sysfs`, `_sysctl`, `ustat`, `nfsservctl`, `lookup_dcookie`

### Conditionally Allowed (with capabilities):
- `clone`, `unshare`, `setns` - with CAP_SYS_ADMIN
- `bpf` - with CAP_BPF
- `perf_event_open` - with CAP_PERFMON
- `reboot` - with CAP_SYS_BOOT
- `chroot` - with CAP_SYS_CHROOT
- Module operations - with CAP_SYS_MODULE
- `ptrace`, `process_vm_*`, `kcmp` - with CAP_SYS_PTRACE
- Time operations - with CAP_SYS_TIME
- `iopl`, `ioperm` - with CAP_SYS_RAWIO

**Source:** [Docker Seccomp Documentation](https://docs.docker.com/engine/security/seccomp/)
**Profile:** [moby/profiles/seccomp/default.json](https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json)

---

## 9. Chrome/Chromium Sandbox

Chrome uses a multi-layered sandbox approach:

### Blocked syscalls (Linux sandbox):
- `ptrace` - Process debugging
- `process_vm_readv`, `process_vm_writev` - Cross-process memory
- `kexec_load`, `kexec_file_load` - Kernel loading
- `init_module`, `finit_module`, `delete_module` - Kernel modules
- `mount`, `umount`, `umount2` - Filesystem mounting
- `ptrace` - Process tracing
- `setuid`, `setgid` - After sandbox initialization
- Various networking syscalls in untrusted processes

**Key difference:** Chrome's sandbox is more restrictive because:
- Renderer processes are untrusted by default
- Uses PID/network/user namespaces aggressively
- Doesn't need to run arbitrary build/compile tools

**For AI agent:** You need more permissive defaults since the agent must compile/run code.

**Source:** [Chromium Sandbox Design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)

---

## 10. Firejail Profile

Firejail takes a more aggressive blocking approach:

### Key blocked syscalls in Firejail:
```
# Default seccomp profile blocks:
@blacklist
arch_prctl
bpf
clock_adjtime
clock_settime
create_module
delete_module
finit_module
get_kernel_syms
init_module
iopl
ioperm
kcmp
kexec_file_load
kexec_load
keyctl
lookup_dcookie
mbind
mount
move_pages
nfsservctl
open_by_handle_at
perf_event_open
process_vm_readv
process_vm_writev
ptrace
query_module
quotactl
set_mempolicy
setdomainname
sethostname
setns
swapoff
swapon
syslog
umount
umount2
unshare
uselib
userfaultfd
vhangup
vm86
vm86old
```

**Firejail approach:** Block first, allow specific as needed

**Source:** [Firejail seccomp.profile](https://github.com/netblue30/firejail/blob/master/etc/seccomp.profile)

---

## 11. Recommended Seccomp Filter for Goose AI Agent

### Minimal Block List (in addition to your current blocks):

```c
// Additional recommended blocks for AI agent sandbox
SCMP_ACT_ERRNO, add_key          // Kernel keyring
SCMP_ACT_ERRNO, request_key      // Kernel keyring
SCMP_ACT_ERRNO, keyctl           // Kernel keyring
SCMP_ACT_ERRNO, bpf              // eBPF kernel code
SCMP_ACT_ERRNO, perf_event_open  // Kernel introspection
SCMP_ACT_ERRNO, unshare          // Namespace creation
SCMP_ACT_ERRNO, setns            // Namespace joining
SCMP_ACT_ERRNO, kcmp             // Process comparison
SCMP_ACT_ERRNO, pidfd_getfd      // FD extraction
SCMP_ACT_ERRNO, process_vm_readv // Cross-process memory read
SCMP_ACT_ERRNO, process_vm_writev// Cross-process memory write
SCMP_ACT_ERRNO, open_by_handle_at// File handle escape
SCMP_ACT_ERRNO, name_to_handle_at// File handle acquisition
SCMP_ACT_ERRNO, lookup_dcookie   // Kernel disclosure
SCMP_ACT_ERRNO, acct             // Process accounting
SCMP_ACT_ERRNO, uselib           // Obsolete
SCMP_ACT_ERRNO, userfaultfd      // Page fault handling
SCMP_ACT_ERRNO, syslog           // Kernel log access
SCMP_ACT_ERRNO, iopl             // I/O privilege
SCMP_ACT_ERRNO, ioperm           // I/O ports
SCMP_ACT_ERRNO, create_module    // Obsolete module
SCMP_ACT_ERRNO, query_module     // Obsolete module
SCMP_ACT_ERRNO, get_kernel_syms  // Obsolete
SCMP_ACT_ERRNO, person           // Execution domain
SCMP_ACT_ERRNO, sysfs            // Obsolete
SCMP_ACT_ERRNO, _sysctl          // Obsolete
SCMP_ACT_ERRNO, ustat            // Obsolete
SCMP_ACT_ERRNO, nfsservctl       // Obsolete
SCMP_ACT_ERRNO, vhangup          // Terminal hangup
SCMP_ACT_ERRNO, chroot           // Root change
SCMP_ACT_ERRNO, settimeofday     // Time change
SCMP_ACT_ERRNO, stime            // Obsolete time
SCMP_ACT_ERRNO, clock_settime    // Clock change
SCMP_ACT_ERRNO, clock_adjtime    // Clock adjust
SCMP_ACT_ERRNO, adjtimex         // Time parameters
SCMP_ACT_ERRNO, setdomainname    // Domain name
SCMP_ACT_ERRNO, sethostname      // Hostname
SCMP_ACT_ERRNO, quotactl         // Disk quotas
SCMP_ACT_ERRNO, quotactl_fd      // Disk quotas (fd)
SCMP_ACT_ERRNO, get_mempolicy    // NUMA query
SCMP_ACT_ERRNO, set_mempolicy    // NUMA set
SCMP_ACT_ERRNO, mbind            // NUMA bind
SCMP_ACT_ERRNO, move_pages       // Page migration
// Consider blocking signal syscalls if not needed:
// SCMP_ACT_ERRNO, kill
// SCMP_ACT_ERRNO, tkill
// SCMP_ACT_ERRNO, tgkill
// SCMP_ACT_ERRNO, rt_sigqueueinfo
// SCMP_ACT_ERRNO, rt_tgsigqueueinfo
```

### Allow List Approach (more secure):

Instead of blocking dangerous syscalls, consider an allow-list approach:

```c
// Default action: ERRNO
"defaultAction": "SCMP_ACT_ERRNO"

// Only allow known-safe syscalls
"syscalls": [
    {
        "names": [
            "accept", "access", "bind", "brk", "capget", "capset",
            "chdir", "chmod", "chown", "clock_getres", "clock_gettime",
            "close", "connect", "dup", "dup2", "dup3", "epoll_create",
            "epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait",
            "eventfd", "eventfd2", "execve", "exit", "exit_group",
            "faccessat", "fchmod", "fchmodat", "fchown", "fchownat",
            "fcntl", "fdatasync", "fgetxattr", "flock", "fork",
            "fstat", "fsync", "ftruncate", "futex", "getcwd",
            "getdents", "getdents64", "getegid", "geteuid", "getgid",
            "getgroups", "getpid", "getppid", "getpriority",
            "getrandom", "getresgid", "getresuid", "getrlimit",
            "getrusage", "getsid", "getsockname", "getsockopt",
            "gettid", "gettimeofday", "getuid", "getxattr",
            "inotify_add_watch", "inotify_init", "inotify_init1",
            "inotify_rm_watch", "ioctl", "kill", "lgetxattr",
            "link", "linkat", "listen", "lseek", "lstat", "madvise",
            "membarrier", "memfd_create", "mincore", "mkdir",
            "mkdirat", "mlock", "mlock2", "mlockall", "mmap",
            "mprotect", "munlock", "munlockall", "munmap", "nanosleep",
            "open", "openat", "openat2", "pause", "pipe", "pipe2",
            "poll", "ppoll", "prctl", "pread64", "preadv", "preadv2",
            "prlimit64", "pwrite64", "pwritev", "pwritev2", "read",
            "readlink", "readlinkat", "readv", "recv", "recvfrom",
            "recvmmsg", "recvmsg", "rename", "renameat", "renameat2",
            "rmdir", "rt_sigaction", "rt_sigpending", "rt_sigprocmask",
            "rt_sigreturn", "rt_sigsuspend", "sched_getaffinity",
            "sched_getparam", "sched_get_priority_max",
            "sched_get_priority_min", "sched_getscheduler",
            "sched_yield", "seccomp", "select", "send", "sendfile",
            "sendmmsg", "sendmsg", "sendto", "setfsgid", "setfsuid",
            "setgid", "setgroups", "setitimer", "setpgid", "setpriority",
            "setregid", "setresgid", "setresuid", "setreuid",
            "setrlimit", "setsid", "setsockopt", "set_tid_address",
            "setuid", "shutdown", "sigaltstack", "signalfd",
            "signalfd4", "socket", "socketpair", "splice", "stat",
            "statfs", "symlink", "symlinkat", "sync", "sync_file_range",
            "syncfs", "sysinfo", "tee", "tgkill", "time",
            "timer_create", "timer_delete", "timer_getoverrun",
            "timer_gettime", "timer_settime", "timerfd_create",
            "timerfd_gettime", "timerfd_settime", "times", "tkill",
            "truncate", "umask", "uname", "unlink", "unlinkat",
            "utimensat", "utimes", "vfork", "wait4", "waitid",
            "waitpid", "write", "writev"
        ],
        "action": "SCMP_ACT_ALLOW"
    }
]
```

---

## 12. Implementation Notes

### Testing Your Filter

1. **Start permissive, then tighten:**
   ```bash
   # First run with LOG action to see what's used
   seccomp_rule_add(ctx, SCMP_ACT_LOG, syscall_number);
   
   // Review logs, then switch to ERRNO for unused syscalls
   ```

2. **Use seccomp-bpf generators:**
   - [libseccomp](https://github.com/seccomp/libseccomp)
   - [docker-syscall-trace](https://github.com/estesp/docker-syscall-trace)

3. **Test with real workloads:**
   ```bash
   # Run typical AI agent tasks and check for denials
   dmesg | grep -i seccomp
   ```

### Bubblewrap Integration

```bash
# Generate seccomp filter
bwrap --seccomp <(
    echo "action allow
    default errno 1
    # Add your syscalls here
    "
) ...
```

### Version Considerations

- **Kernel 4.8+:** `ptrace` can be allowed safely (seccomp bypass fixed)
- **Kernel 5.0+:** `clone3` support (block if not needed)
- **Kernel 5.3+:** `clone3` with pidfd support

---

## 13. Summary Table

| Category | Syscalls | Action | Priority |
|----------|----------|--------|----------|
| Kernel Modules | `init_module`, `finit_module`, `delete_module`, `create_module`, `query_module`, `get_kernel_syms` | BLOCK | Critical (already blocked) |
| Kernel Execution | `kexec_load`, `kexec_file_load`, `reboot` | BLOCK | Critical (already blocked) |
| Filesystem Escape | `mount`, `umount2`, `pivot_root`, `chroot`, `open_by_handle_at` | BLOCK | Critical |
| Raw Sockets | `socket` (AF_PACKET, AF_NETLINK) | BLOCK | Critical (already blocked) |
| Process Injection | `ptrace`, `process_vm_readv`, `process_vm_writev` | BLOCK | Critical |
| Namespace Escape | `unshare`, `setns`, `clone` (NEW* flags) | BLOCK | Critical |
| Kernel Keyring | `add_key`, `request_key`, `keyctl` | BLOCK | High |
| BPF | `bpf`, `perf_event_open` | BLOCK | High |
| Kernel Introspection | `kcmp`, `pidfd_getfd`, `lookup_dcookie` | BLOCK | Medium |
| Obsolete Syscalls | `uselib`, `sysfs`, `_sysctl`, `ustat`, `nfsservctl` | BLOCK | Low |
| Time Manipulation | `settimeofday`, `clock_settime`, `adjtimex` | BLOCK | Medium |
| Signal Control | `kill`, `tkill`, `tgkill` | CONSIDER | Medium |
| Privilege Change | `setuid`, `setgid`, `capset` | ALLOW* | Low |

*Allow if using user namespaces; block if running as regular user

---

## Sources

1. [Docker Seccomp Documentation](https://docs.docker.com/engine/security/seccomp/)
2. [Docker Default Profile](https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json)
3. [Linux Kernel Seccomp Documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
4. [Firejail Seccomp Profile](https://github.com/netblue30/firejail/blob/master/etc/seccomp.profile)
5. [Chromium Sandbox Design](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md)
6. [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
7. [libseccomp Documentation](https://github.com/seccomp/libseccomp)

---

## Quick Reference: Complete Block List

```
# Your current blocks (keep these)
ptrace
init_module, finit_module, delete_module
kexec_load, kexec_file_load, reboot
mount, umount2, pivot_root, chroot, mknod, mknodat
socket (AF_PACKET), socket (AF_NETLINK)

# Additional recommended blocks
add_key, request_key, keyctl
bpf, perf_event_open
unshare, setns
kcmp, pidfd_getfd
process_vm_readv, process_vm_writev
open_by_handle_at, name_to_handle_at
lookup_dcookie
acct, uselib, userfaultfd
syslog, iopl, ioperm
create_module, query_module, get_kernel_syms
personality, sysfs, _sysctl, ustat, nfsservctl
vhangup
settimeofday, stime, clock_settime, clock_adjtime, adjtimex
setdomainname, sethostname
quotactl, quotactl_fd
get_mempolicy, set_mempolicy, mbind, move_pages

# Consider blocking (application-dependent)
kill, tkill, tgkill
rt_sigqueueinfo, rt_tgsigqueueinfo
clone3
```
