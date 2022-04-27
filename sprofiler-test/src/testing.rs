use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Result};
use async_std::fs::File;
use async_std::io::ReadExt;
use oci_spec::runtime::{LinuxSeccomp, LinuxSeccompAction};
use serde::{Deserialize, Serialize};
use tracing::{error, info, trace};

use crate::hooks;
use crate::podman::PodmanRunnerBuilder;
use crate::seccomp;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Testing {
    pub name: String,
    pub config: Config,
    pub tests: Vec<Test>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub sprofiler: PathBuf,
    pub podman: PathBuf,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Test {
    pub name: String,
    pub no_new_priv: bool,
    pub runtime: String,
    pub should_success: bool,
    pub image: String,
}

pub async fn execute_test_case<P: AsRef<Path>>(
    testcase: &Test,
    podman_path: P,
    hooks_dir: P,
) -> Result<()>
where
    PathBuf: From<P>,
    P: Copy,
{
    let seccomp_profile_path = seccomp::create_seccomp_profile(hooks_dir, &testcase.name)?;

    let podman = PodmanRunnerBuilder::default()
        .podman_path(podman_path)
        .runtime(&testcase.runtime)
        .hooks_dir(hooks_dir)
        .image(&testcase.image)
        .sprofiler_output(&seccomp_profile_path)
        .no_new_priv(testcase.no_new_priv)
        .debug(false)
        .build()?;

    trace!("[{}] {}", testcase.name, podman.args().join(" "));

    podman.run().await?;

    if let Some(seccomp_profile_path) = podman.sprofiler_output.as_ref() {
        trace!(
            "[{}] Seccomp Profile: {}",
            testcase.name,
            seccomp_profile_path.display()
        );

        for _ in 0..500 {
            let mut file = match File::open(&seccomp_profile_path).await {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => bail!(e),
            };

            let mut s = String::new();
            file.read_to_string(&mut s).await?;
            trace!("[{}] Read Seccomp Profile: {}", testcase.name, s);
            let seccomp: LinuxSeccomp = serde_json::from_str(&s)?;
            let s = serde_json::to_string(&seccomp)?;
            trace!("[{}] Seccomp: {}", testcase.name, s);

            assert_seccomp_profile(&testcase.name, seccomp);
            return Ok(());
        }
    }
    bail!("Seccomp Profile Not Generated")
}

pub fn assert_seccomp_profile(testname: &str, seccomp: LinuxSeccomp) {
    assert!(seccomp.default_action() == LinuxSeccompAction::ScmpActErrno);
    info!("[{}] OK seccomp.default_action == SCMP_ACT_ERRNO", testname);

    assert!(seccomp.syscalls().is_some());
    info!("[{}] OK seccomp.syscalls.is_some()", testname);
    if let Some(syscalls) = seccomp.syscalls().as_ref() {
        assert!(!syscalls.is_empty());
        info!("[{}] OK !seccomp.syscalls.is_empty()", testname);

        for syscall in syscalls {
            assert!(!syscall.names().is_empty());

            info!("[{}] OK !seccomp.syscalls[i].names.is_empty()", testname);

            assert_eq!(syscall.action(), LinuxSeccompAction::ScmpActAllow);
            info!(
                "[{}] OK seccomp.syscalls[i].action == SCMP_ACT_ALLOW",
                testname
            );
        }
    }
}

pub async fn run_tests(testing: Testing) -> Result<()> {
    if !testing.config.sprofiler.exists() {
        error!("Not found: {}", testing.config.sprofiler.display());
        std::process::exit(1);
    }
    trace!("Sprofiler Path: {}", testing.config.sprofiler.display());

    if !testing.config.podman.exists() {
        error!("Not found: {}", testing.config.podman.display());
        std::process::exit(1);
    }
    trace!("Podman Path: {}", testing.config.podman.display());

    let base_dir = tempdir::TempDir::new("sprofiler-test")?;
    let hooks_dir =
        hooks::create_hook_config(base_dir.path().to_path_buf(), testing.config.sprofiler)?;

    for test in testing.tests {
        match execute_test_case(&test, &testing.config.podman, &hooks_dir).await {
            Ok(_) => info!("[{}] PASSED", &test.name),
            Err(e) => error!("[{}] FAILED: {}", &test.name, e),
        };
    }

    Ok(())
}
