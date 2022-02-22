use std::path::PathBuf;

use anyhow::Result;
use async_std::process::{Command, Stdio};
use derive_builder::Builder;
use tracing::{error, trace};

#[derive(Default, Debug, Clone, Builder)]
#[builder(pattern = "owned", setter(into, strip_option))]
pub struct PodmanRunner {
    podman_path: PathBuf,
    hooks_dir: PathBuf,
    runtime: String,
    image: String,
    pub sprofiler_output: Option<PathBuf>,
    debug: bool,
    no_new_priv: bool,
}

impl PodmanRunner {
    pub fn args(&self) -> Vec<String> {
        let podman_path = format!("{}", self.podman_path.display());
        let mut args = vec![podman_path];

        if self.debug {
            args.push(self.log_level_arg("debug"));
        }

        args.push(self.runtime_arg());
        args.push("run".to_string());
        args.push("--rm".to_string());

        if self.no_new_priv {
            args.push(self.no_new_priv_arg());
        }

        args.push(self.hooks_dir_arg());
        args.push(self.sprofiler_annotation());
        args.push(self.image.clone());
        args
    }

    pub async fn run(&self) -> Result<()> {
        let args = self.args();
        let output = Command::new(&args[0])
            .args(&args[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await?;

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

    fn no_new_priv_arg(&self) -> String {
        "--security-opt=no-new-privileges".to_string()
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
