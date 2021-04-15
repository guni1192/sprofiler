use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use regex::Regex;

use crate::lang::SeccompProfiler;
use crate::oci::{Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSyscall};

#[derive(Default)]
pub struct GoSeccompProfiler {
    pub destination: PathBuf,
    pub target_bin: PathBuf,
}

impl SeccompProfiler for GoSeccompProfiler {
    fn analyze(&self) -> Result<LinuxSeccomp> {
        let syscall: LinuxSyscall = self.run()?;

        Ok(LinuxSeccomp {
            syscalls: Some(vec![syscall]),
            default_action: LinuxSeccompAction::SCMP_ACT_ERRNO,
            architectures: Some(vec![Arch::SCMP_ARCH_X86_64]),
        })
    }

    fn output(&self) -> Result<()> {
        let file = File::create(&self.destination)?;
        let seccomp = self.analyze()?;
        serde_json::to_writer(file, &seccomp)?;
        Ok(())
    }
}

impl GoSeccompProfiler {
    fn run(&self) -> Result<LinuxSyscall> {
        let output = Command::new("nm").arg(&self.target_bin).output()?;
        let lines = String::from_utf8_lossy(&output.stdout);

        let re = Regex::new(r"syscall.[a-zA-Z][\w]+").unwrap();
        let mut syscalls: HashSet<String> = re
            .captures_iter(&lines)
            .map(|cap| cap[0].replace("syscall.", "").to_lowercase())
            .filter(|symbol| is_syscalls(symbol))
            .collect();

        DEFAULT_ALLOW_SYSCALLS
            .to_vec()
            .into_iter()
            .map(String::from)
            .for_each(|syscall| {
                syscalls.insert(syscall);
            });

        let mut syscalls: Vec<String> = syscalls.into_iter().collect();
        syscalls.sort();

        Ok(LinuxSyscall {
            names: syscalls,
            action: LinuxSeccompAction::SCMP_ACT_ALLOW,
            args: None,
        })
    }
}

// TODO: aarch64 and other architectures
// #[cfg(all(any(target_arch = "aarch64", target_arch = "x86_64"),))]
// #[cfg(any(target_arch = "x86_64"))]
fn is_syscalls(fname: &str) -> bool {
    // #[cfg(target_arch = "aarch64")]
    // use arch::aarch64::syscalls;
    #[cfg(target_arch = "x86_64")]
    use crate::arch::x86_64;

    x86_64::is_syscall(fname)
}

static DEFAULT_ALLOW_SYSCALLS: &[&str; 58] = &[
    "bind",
    "capget",
    "capset",
    "chdir",
    "clone",
    "close",
    // debug {{{
    "dup",
    "dup2",
    "dup3",
    // }}}
    "execve",
    "epoll_wait",
    "fchdir",
    "fchmodat",
    "fchown",
    "fchownat",
    "fcntl",
    "fstat",
    "fstatfs",
    "futex",
    "getdents",
    "getdents64",
    "getppid",
    "getsockname",
    "gettid",
    "getuid",
    "keyctl",
    "mkdirat",
    "mknodat",
    "mmap",
    "mount",
    "mprotect",
    "newfstatat",
    "openat",
    "prctl",
    "read",
    "readlinkat",
    "recvfrom",
    "sendto",
    "setgid",
    "setgroups",
    "sethostname",
    "setsid",
    "setuid",
    "sigaltstack",
    "socket",
    "statfs",
    "symlinkat",
    "umask",
    "unlinkat",
    "write",
    // Go Runtime
    "arch_prctl",
    "epoll_pwait",
    "epoll_create",
    "epoll_ctl",
    "openat",
    "uname",
    "rt_sigaction",
    "rt_sigprocmask",
];