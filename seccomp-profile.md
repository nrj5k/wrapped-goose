# BPF Seccomp Filter Profile Documentation

## Purpose

This seccomp filter profile blocks syscalls that enable bubblewrap (bwrap) sandbox escape and container breakout techniques while preserving agent functionality for normal operations.

## Philosophy

This is a **denylist (blocklist)** approach suitable for:
- Containing AI agents in sandboxed environments
- Preventing privilege escalation
- Blocking known container escape vectors

**Note:** A denylist approach requires maintenance as new syscalls are added to the kernel. For maximum security, consider an allowlist approach instead.

## Architecture Support

- **x86_64**: Full support
- **aarch64**: Full support  
- **riscv64**: Full support

## Filter Configuration

```json
{
  "main_thread": {
    "mismatch_action": "allow",
    "match_action": {"errno": 1},
    "filter": [
      // Core Process Control
      {"syscall": "ptrace"},
      
      // Module Loading (kernel code injection)
      {"syscall": "init_module"},
      {"syscall": "finit_module"},
      {"syscall": "delete_module"},
      
      // Kernel Execution (replace running kernel)
      {"syscall": "kexec_load"},
      {"syscall": "kexec_file_load"},
      {"syscall": "reboot"},
      
      // Filesystem Mount Operations
      {"syscall": "mount"},
      {"syscall": "umount2"},
      {"syscall": "pivot_root"},
      {"syscall": "chroot"},
      
      // Device Creation
      {"syscall": "mknod"},
      {"syscall": "mknodat"},
      
      // Namespace Operations
      {"syscall": "unshare"},
      {"syscall": "setns"},
      
      // Signal Sending (process control)
      {"syscall": "kill"},
      {"syscall": "tkill"},
      {"syscall": "tgkill"},
      
      // BPF (kernel bytecode injection)
      {"syscall": "bpf"},
      {"syscall": "perf_event_open"},
      
      // Keyring Operations
      {"syscall": "add_key"},
      {"syscall": "request_key"},
      {"syscall": "keyctl"},
      
      // Cross-Process Memory Access
      {"syscall": "process_vm_readv"},
      {"syscall": "process_vm_writev"},
      
      // Filesystem Handle Operations
      {"syscall": "open_by_handle_at"},
      {"syscall": "name_to_handle_at"},
      
      // Time/Date Changes
      {"syscall": "settimeofday"},
      {"syscall": "clock_settime"},
      {"syscall": "adjtimex"},
      
      // System Identity Changes
      {"syscall": "setdomainname"},
      {"syscall": "sethostname"},
      {"syscall": "syslog"},
      
      // I/O Port Access (hardware direct access)
      {"syscall": "iopl"},
      {"syscall": "ioperm"},
      
      // Legacy/Deprecated System Calls
      {"syscall": "acct"},
      {"syscall": "uselib"},
      {"syscall": "userfaultfd"},
      
      // Anonymous Executable Memory
      {"syscall": "memfd_create"},
      
      // Process Control and Capabilities
      {"syscall": "prctl"},
      {"syscall": "capset"},
      
      // Cross-Process File Descriptor Access
      {"syscall": "pidfd_getfd"},
      
      // Async I/O (io_uring) - New attack surface
      {"syscall": "io_uring_setup"},
      {"syscall": "io_uring_enter"},
      {"syscall": "io_uring_register"},
      
      // New Mount API (kernel 5.1+)
      {"syscall": "mount_setattr"},
      {"syscall": "fsopen"},
      {"syscall": "fsmount"},
      {"syscall": "fsconfig"},
      {"syscall": "open_tree"},
      {"syscall": "move_mount"},
      
      // Kernel Resource Comparison
      {"syscall": "kcmp"},
      
      // Execute via File Descriptor
      {"syscall": "fexecve"},
      
      // Raw Socket Creation
      {
        "syscall": "socket",
        "args": [
          {"index": 0, "type": "dword", "op": "eq", "val": 17, "comment": "AF_PACKET - raw packet access"}
        ]
      },
      {
        "syscall": "socket",
        "args": [
          {"index": 0, "type": "dword", "op": "eq", "val": 16, "comment": "AF_NETLINK - kernel/userspace communication"}
        ]
      }
    ]
  }
}
```

## Syscall Categories and Rationale

### 1. Core Process Control (1 syscall)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `ptrace` | **Critical** | Allows process debugging and memory manipulation. Can attach to processes outside the sandbox, read/write memory, and inject code. Primary escape vector. |

### 2. Kernel Module Operations (3 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `init_module` | **Critical** | Load kernel modules (arbitrary kernel code execution). Full system compromise. |
| `finit_module` | **Critical** | Load kernel modules from file descriptor. Same risk as init_module. |
| `delete_module` | **High** | Unload kernel modules. Can destabilize system or remove security modules. |

### 3. Kernel Execution (3 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `kexec_load` | **Critical** | Load new kernel for execution. Replace running kernel without reboot. |
| `kexec_file_load` | **Critical** | Load kernel from file. Same as kexec_load. |
| `reboot` | **High** | Reboot/halt system. Denial of service. |

### 4. Filesystem Mount Operations (4 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `mount` | **Critical** | Mount filesystems. Can mount over existing paths to escape chroot/bind mounts. |
| `umount2` | **High** | Unmount filesystems. Can remove sandbox mount restrictions. |
| `pivot_root` | **Critical** | Change root filesystem. Classic container escape technique. |
| `chroot` | **High** | Change root directory. Can be combined with other techniques to escape. |

### 5. Device Creation (2 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `mknod` | **High** | Create special files (devices). Can create device nodes to access raw hardware. |
| `mknodat` | **High** | Same as mknod, relative to directory. |

### 6. Namespace Operations (2 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `unshare` | **Critical** | Create new namespaces. Can create new mount namespace to bypass restrictions. |
| `setns` | **Critical** | Enter existing namespace. Can join host namespaces to escape sandbox. |

### 7. Signal Operations (3 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `kill` | **Medium** | Send signals to any process. Can kill sandbox supervisor or other processes. |
| `tkill` | **Medium** | Send signal to specific thread. |
| `tgkill` | **Medium** | Send signal to thread in thread group. |

### 8. BPF and Performance Monitoring (2 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `bpf` | **Critical** | Load BPF programs into kernel. Arbitrary kernel bytecode execution. |
| `perf_event_open` | **High** | Performance monitoring. Can be used for timing attacks and information disclosure. |

### 9. Keyring Operations (3 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `add_key` | **Medium** | Add key to kernel keyring. Potential for privilege escalation via keyrings. |
| `request_key` | **Medium** | Request key from kernel. |
| `keyctl` | **Medium** | Control kernel keyring. Can manipulate keys for privilege escalation. |

### 10. Cross-Process Memory (2 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `process_vm_readv` | **Critical** | Read memory from other processes. Information disclosure, can read secrets. |
| `process_vm_writev` | **Critical** | Write memory to other processes. Code injection into other processes. |

### 11. Filesystem Handles (2 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `open_by_handle_at` | **High** | Open file by handle. Can bypass path restrictions. CVE-2014-7975 exploit vector. |
| `name_to_handle_at` | **High** | Get handle from path. Combined with open_by_handle_at for escape. |

### 12. Time Manipulation (3 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `settimeofday` | **Medium** | Set system time. Can affect time-based security mechanisms. |
| `clock_settime` | **Medium** | Set specific clock. |
| `adjtimex` | **Medium** | Adjust kernel clock. |

### 13. System Identity (3 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `setdomainname` | **Low** | Set NIS domain name. System configuration tampering. |
| `sethostname` | **Low** | Set system hostname. System configuration tampering. |
| `syslog` | **Medium** | System logging. Can read sensitive kernel messages. |

### 14. Hardware Access (2 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `iopl` | **Critical** | Set I/O privilege level. Direct hardware access. |
| `ioperm` | **Critical** | Set port I/O permissions. Direct hardware access. |

### 15. Legacy/Deprecated (3 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `acct` | **Low** | Process accounting. Information disclosure. |
| `uselib` | **Medium** | Load shared library (obsolete). Can load arbitrary code. |
| `userfaultfd` | **High** | Handle page faults in userspace. Exploit primitive for timing attacks. |

### 16. Modern Escape Vectors (12 syscalls)

| Syscall | Risk | Reasoning |
|---------|------|-----------|
| `memfd_create` | **High** | Create anonymous memory file that can be executed. Used in "fileless" malware. |
| `prctl` | **High** | Process control. Can modify securebits, capabilities, seccomp filters. |
| `capset` | **High** | Set process capabilities. Privilege escalation. |
| `pidfd_getfd` | **High** | Get FD from another process (kernel 5.6+). Cross-process FD theft. |
| `io_uring_setup` | **High** | Setup async I/O (kernel 5.1+). New attack surface, bypasses many restrictions. |
| `io_uring_enter` | **High** | Submit async I/O operations. |
| `io_uring_register` | **High** | Register files/buffers for io_uring. |
| `mount_setattr` | **Critical** | Change mount attributes (kernel 5.12+). Can change mount propagation to escape. |
| `fsopen` | **High** | Open filesystem context (new mount API). |
| `fsmount` | **High** | Mount filesystem (new mount API). |
| `fsconfig` | **High** | Configure filesystem (new mount API). |
| `open_tree` | **High** | Clone mount tree (new mount API). |
| `move_mount` | **High** | Move mount to new location (new mount API). |
| `kcmp` | **Medium** | Compare kernel resources. Information disclosure for exploit development. |
| `fexecve` | **High** | Execute program via file descriptor. Bypass path-based restrictions. |

### 17. Socket Restrictions (Conditional)

| Condition | Risk | Reasoning |
|-----------|------|-----------|
| `socket(AF_PACKET)` | **Critical** | Raw packet socket. Can send/receive arbitrary network packets, bypass firewall. |
| `socket(AF_NETLINK)` | **High** | Netlink socket. Kernel/userspace communication. Can manipulate network config. |

## Syscalls NOT Blocked (And Why)

These syscalls were considered but excluded to preserve agent functionality:

### File Operations (Excluded)

| Syscall | Why Excluded |
|---------|--------------|
| `openat` | Essential for file I/O. Modern replacement for open(). Breaking this breaks most programs. |
| `fcntl` | Critical for FD operations (duplicating, setting flags). Used by networking, file locking. |
| `readlink` / `readlinkat` | Common for path resolution. Breaking would break many libraries. |

### Process Operations (Excluded)

| Syscall | Why Excluded |
|---------|--------------|
| `clone` / `clone3` | Thread creation. Blocking breaks pthread and async runtimes. Risk: low if PID namespace restricted. |
| `setuid` / `setgid` / `setresuid` / `setresgid` | Privilege changes. In container with no new privileges, these are already restricted. |

### IPC Operations (Excluded)

| Syscall | Why Excluded |
|---------|--------------|
| `sendmsg` / `recvmsg` | Unix domain sockets. Required for agent-tool communication (SCM_RIGHTS). |

## Usage

### Compile the filter

```bash
./bpf-seccomp-generator config.json output.bpf
```

### Load the filter (in your sandbox wrapper)

```c
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>

// Load the BPF program
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
```

Or using libseccomp:

```c
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
seccomp_load(ctx);
```

## Testing

Test your sandbox with this profile:

```bash
# Should FAIL (EPERM)
bwrap --ro-bind / / --seccomp output.bpf /bin/sh -c "ptrace -p 1"
bwrap --ro-bind / / --seccomp output.bpf /bin/sh -c "mount -t proc proc /proc"

# Should SUCCEED
bwrap --ro-bind / / --seccomp output.bpf /bin/sh -c "ls /"
bwrap --ro-bind / / --seccomp output.bpf /bin/sh -c "cat /etc/passwd"
```

## References

- [seccompiler crate documentation](https://docs.rs/seccompiler/latest/seccompiler/)
- [Linux seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
- [Docker default seccomp profile](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)
- [Container Escape Techniques](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout)

## Changelog

- **v1.0**: Initial blocklist for bwrap agent containment
- **v1.1**: Added modern escape vectors (io_uring, new mount API, memfd_create)
