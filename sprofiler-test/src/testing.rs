use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{bail, Result};
use derive_builder::Builder;
use oci_runtime_spec::{LinuxSeccomp, LinuxSeccompAction};
use serde::{Deserialize, Serialize};
use tracing::{error, info, trace};

use crate::hooks;
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

#[derive(Default, Debug, Clone, Builder)]
#[builder(pattern = "owned", setter(into, strip_option))]
pub struct PodmanRunner {
    podman_path: PathBuf,
    hooks_dir: PathBuf,
    runtime: String,
    image: String,
    sprofiler_output: Option<PathBuf>,
    debug: bool,
}

impl PodmanRunner {
    fn args(&self) -> Vec<String> {
        let podman_path = format!("{}", self.podman_path.display());
        let mut args = vec![podman_path.to_string()];

        if self.debug {
            args.push(self.log_level_arg("debug"));
        }

        args.push(self.runtime_arg());
        args.push("run".to_string());
        args.push("--rm".to_string());
        args.push(self.hooks_dir_arg());
        args.push(self.sprofiler_annotation());
        args.push(self.image.clone());
        args
    }

    fn run(&self) -> Result<()> {
        let args = self.args();
        let output = Command::new(&args[0])
            .args(&args[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()?;

        if output.status.success() {
            trace!("Podman exit code: {}", output.status);
        } else {
            let stderr = String::from_utf8(output.stderr)?;
            error!("Error: {}", stderr);
            error!("Podman exit code: {}", output.status);
        }
        Ok(())
    }

    fn runtime_arg(&self) -> String {
        format!("--runtime={}", self.runtime)
    }

    fn log_level_arg(&self, level: &str) -> String {
        format!("--log-level={}", level)
    }

    fn hooks_dir_arg(&self) -> String {
        format!("--hooks-dir={}", self.hooks_dir.display())
    }

    fn sprofiler_annotation(&self) -> String {
        if let Some(sprofiler_output) = self.sprofiler_output.as_ref() {
            format!(
                "--annotation=\"io.sprofiler.output_seccomp_profile_path={}\"",
                sprofiler_output.display()
            )
        } else {
            "".to_string()
        }
    }
}

pub fn execute_test_case<P: AsRef<Path>>(
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
        .debug(false)
        .build()?;

    trace!("[{}] {}", testcase.name, podman.args().join(" "));

    podman.run()?;

    if let Some(seccomp_profile_path) = podman.sprofiler_output.as_ref() {
        trace!(
            "[{}] Seccomp Profile: {}",
            testcase.name,
            seccomp_profile_path.display()
        );

        for _ in 0..50 {
            let file = match File::open(&seccomp_profile_path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => bail!(e),
            };
            let seccomp: LinuxSeccomp = serde_json::from_reader(file)?;
            let s = serde_json::to_string(&seccomp)?;
            trace!("[{}] Seccomp: {}", testcase.name, s);

            assert_seccomp_profile(&testcase.name, seccomp);
            return Ok(());
        }
    }
    bail!("Seccomp Profile Not Generated")
}

pub fn assert_seccomp_profile(testname: &str, seccomp: LinuxSeccomp) {
    assert!(seccomp.default_action == LinuxSeccompAction::SCMP_ACT_ERRNO);
    info!("[{}] OK seccomp.default_action == SCMP_ACT_ERRNO", testname);

    assert!(seccomp.syscalls.is_some());
    info!("[{}] OK seccomp.syscalls.is_some()", testname);
    if let Some(syscalls) = seccomp.syscalls {
        assert!(syscalls.len() > 0);
        info!("[{}] OK seccomp.syscalls.len() > 0", testname);

        for syscall in syscalls {
            assert!(syscall.names.len() > 0);
            info!("[{}] OK seccomp.syscalls.names.len() > 0", testname);

            assert_eq!(syscall.action, LinuxSeccompAction::SCMP_ACT_ALLOW);
            info!(
                "[{}] OK seccomp.syscalls.action == SCMP_ACT_ALLOW",
                testname
            );
        }
    }
}

pub fn run_tests(testing: Testing) -> Result<()> {
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
    // let base_dir = PathBuf::from("/tmp/sprofiler-test");
    let hooks_dir =
        hooks::create_hook_config(base_dir.path().to_path_buf(), testing.config.sprofiler)?;

    for test in testing.tests {
        match execute_test_case(&test, &testing.config.podman, &hooks_dir) {
            Ok(_) => info!("[{}] PASSED", &test.name),
            Err(e) => error!("[{}] FAILED: {}", &test.name, e),
        };
    }

    Ok(())
}