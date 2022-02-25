use std::path::PathBuf;

use crate::oci::State;

const SPROFILER_OCI_ANNOTATION: &str = "io.sprofiler.output_seccomp_profile_path";

pub fn get_trace_target_path(state: &State) -> Option<PathBuf> {
    if let Some(annotations) = &state.annotations {
        annotations.get(SPROFILER_OCI_ANNOTATION).map(PathBuf::from)
    } else {
        None
    }
}
