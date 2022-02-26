use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use object::{Object, ObjectSymbol};
use oci_spec::runtime::{
    Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscall, LinuxSyscallBuilder,
};
use regex::Regex;

use crate::lang::SeccompProfiler;

#[derive(Default)]
pub struct GoSeccompProfiler {
    pub destination: PathBuf,
    pub target_bin: PathBuf,
}

impl SeccompProfiler for GoSeccompProfiler {
    fn analyze(&self) -> Result<LinuxSeccomp> {
        let syscall: LinuxSyscall = self.run()?;

        let seccomp = LinuxSeccompBuilder::default()
            .syscalls(vec![syscall])
            .default_action(LinuxSeccompAction::ScmpActErrno)
            .architectures(vec![Arch::ScmpArchX86_64])
            .build()?;

        Ok(seccomp)
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
        let bin_data = std::fs::read(&self.target_bin)?;
        let obj_file = object::File::parse(&*bin_data)?;

        let lines = obj_file.symbols().fold(String::new(), |a, b| {
            format!("{}\n{}", a, b.name().unwrap())
        });

        let re = Regex::new(r"syscall.[a-zA-Z][\w]+").unwrap();
        let syscalls: HashSet<String> = re
            .captures_iter(&lines)
            .map(|cap| cap[0].replace("syscall.", "").to_lowercase())
            .filter(|symbol| is_syscalls(symbol))
            .collect();

        let mut syscalls: Vec<String> = syscalls.into_iter().collect();
        syscalls.sort();

        let syscall = LinuxSyscallBuilder::default()
            .names(syscalls)
            .action(LinuxSeccompAction::ScmpActAllow)
            .build()?;

        Ok(syscall)
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
