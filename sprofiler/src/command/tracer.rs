use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use libbpf_rs::Error;
use libbpf_rs::PerfBufferBuilder;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use plain::Plain;
use signal_hook::consts::*;
use signal_hook::iterator::exfiltrator::WithOrigin;
use signal_hook::iterator::SignalsInfo;
use sprofiler_sys::arch::x86_64::SYSCALLS;

use crate::bpf::*;
use crate::dynamic::annotation;
use crate::dynamic::process;
use crate::oci::State;

use oci_spec::runtime::{
    Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder,
};

lazy_static! {
    static ref SYSCALL_LIST: Mutex<HashSet<&'static str>> = Mutex::new(HashSet::new());
}

#[repr(C)]
#[derive(Default, Debug)]
struct SysEnterEvent {
    pub uid: u32,
    pub cgid: u64,
    pub syscall_nr: i64,
    pub comm: [u8; 32],
}

unsafe impl Plain for SysEnterEvent {}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event = SysEnterEvent::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short or invalid");

    let syscall_name = SYSCALLS.get(&(event.syscall_nr as u32));

    if let Some(syscall_name) = syscall_name {
        let mut syscall_list = SYSCALL_LIST.lock().unwrap();
        syscall_list.insert(syscall_name);
    }
}

fn handle_lost_event(cpu: i32, count: u64) {
    eprintln!("Lost event (CPU: {}, COUNT: {})", cpu, count);
}

fn gen_seccomp_rule() -> anyhow::Result<LinuxSeccomp> {
    let syscall_list = SYSCALL_LIST.lock().unwrap();
    let mut syscall_list: Vec<String> = syscall_list
        .clone()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    syscall_list.sort();

    let architectures = vec![Arch::ScmpArchX86, Arch::ScmpArchX86_64];

    let seccomp_profile = LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActErrno)
        .architectures(architectures)
        .syscalls(vec![LinuxSyscallBuilder::default()
            .names(syscall_list)
            .action(LinuxSeccompAction::ScmpActAllow)
            .build()?])
        .build()?;

    Ok(seccomp_profile)
}

/// only work when cgroup driver is systemd & v2 on podman
fn get_contianer_cgroup_id(container_id: &str) -> Result<u64> {
    let path = format!(
        "/sys/fs/cgroup/machine.slice/libpod-{}.scope/container",
        container_id
    );
    let path = PathBuf::from(path);
    let meta = fs::metadata(&path)
        .with_context(|| format!("failed to get metadata from {}", path.display()))?;
    Ok(meta.ino())
}

fn start_tracing(spinlock: Arc<AtomicBool>, state: &State) -> Result<()> {
    let skel_builder = SystraceSkelBuilder::default();
    let mut systrace_skel = skel_builder.open()?;

    systrace_skel.rodata().target_cgid = get_contianer_cgroup_id(&state.id)?;

    let mut skel = systrace_skel.load()?;

    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps().sys_enter_events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_event)
        .build()?;

    while spinlock.load(Ordering::Relaxed) {
        match perf.poll(std::time::Duration::from_millis(100)) {
            Ok(()) | Err(Error::System(4)) => {} // EINTER
            Err(e) => return Err(e.into()),
        };
    }

    if let Some(path) = annotation::get_trace_target_path(state) {
        let file = File::create(path)?;
        serde_json::to_writer(file, &gen_seccomp_rule()?)?;
    }

    Ok(())
}

pub fn trace_command() -> Result<()> {
    let state = process::container_state_load_from_reader(io::stdin()).expect("state load error:");

    let pid = std::process::id() as i32;
    println!("PID: {pid}");

    process::create_pid_file(state.bundle.join("sprofiler.pid"), pid)?;

    let spinlock = Arc::new(AtomicBool::new(true));
    let spinlock_clone = Arc::clone(&spinlock);

    let th = thread::spawn(move || {
        let mut sigs = vec![SIGUSR1, SIGUSR2, SIGTERM];
        sigs.extend(TERM_SIGNALS);
        let mut signals = SignalsInfo::<WithOrigin>::new(&sigs).expect("Signal new");
        for info in &mut signals {
            if info.signal == SIGUSR1 {
                spinlock_clone.store(false, Ordering::SeqCst);
                break;
            }
        }
    });

    start_tracing(spinlock, &state).context("start_tracing: ")?;

    th.join().expect("thread join: ");

    Ok(())
}

pub fn stop_tracing() -> anyhow::Result<()> {
    let state =
        process::container_state_load_from_reader(std::io::stdin()).expect("state load error:");
    let pid = process::read_pid_file(state.bundle.join("sprofiler.pid"))?;
    kill(Pid::from_raw(pid), Signal::SIGUSR1)?;

    Ok(())
}
