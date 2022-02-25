use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use oci_spec::runtime::LinuxSeccomp;

pub mod c;
pub mod golang;

pub trait SeccompProfiler {
    fn analyze(&self) -> Result<LinuxSeccomp>;
    fn output(&self) -> Result<()>;
}

#[derive(Clone)]
pub struct SeccompProfilerBuilder {
    src: PathBuf,
    dst: PathBuf,
    lang: Language,
    syscall_map: Option<PathBuf>,
}

impl SeccompProfilerBuilder {
    pub fn new(src: PathBuf, dst: PathBuf, lang: Language) -> Self {
        SeccompProfilerBuilder {
            src,
            dst,
            lang,
            syscall_map: None,
        }
    }

    pub fn set_syscall_map(&mut self, syscall_map: PathBuf) -> &mut Self {
        self.syscall_map = Some(syscall_map);
        self
    }

    pub fn build(&self) -> Box<dyn SeccompProfiler> {
        match self.lang {
            Language::C => Box::new(c::CSeccompProfiler {
                target_bin: self.src.clone(),
                destination: self.dst.clone(),
                syscall_map: self
                    .syscall_map
                    .as_ref()
                    .expect("C binary analyzer need syscall_map")
                    .to_path_buf(),
            }),
            Language::Go => Box::new(golang::GoSeccompProfiler {
                target_bin: self.src.clone(),
                destination: self.dst.clone(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Language {
    C,
    Go,
}

impl FromStr for Language {
    type Err = ();

    #[rustfmt::skip]
    fn from_str(lang: &str) -> Result<Language, Self::Err> {
        match lang.to_lowercase().as_str() {
            "c"             => Ok(Language::C),
            "go" | "golang" => Ok(Language::Go),
            _               => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_c_seccomp_profiler() {
        SeccompProfilerBuilder::new(PathBuf::new(), PathBuf::new(), Language::C)
            .set_syscall_map(PathBuf::new())
            .build();
    }

    #[test]
    #[should_panic]
    fn build_c_seccomp_profiler_none_syscall_map() {
        SeccompProfilerBuilder::new(PathBuf::new(), PathBuf::new(), Language::C).build();
    }

    #[test]
    fn build_go_seccomp_profiler() {
        SeccompProfilerBuilder::new(PathBuf::new(), PathBuf::new(), Language::Go).build();
    }
}
