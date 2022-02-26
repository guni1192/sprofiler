use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use crate::oci::State;

pub fn create_pid_file(path: PathBuf, pid: i32) -> anyhow::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(pid.to_string().as_bytes())?;

    Ok(())
}

pub fn read_pid_file(path: PathBuf) -> anyhow::Result<i32> {
    let mut file = File::open(path)?;
    let mut s = String::new();
    file.read_to_string(&mut s)?;
    let pid = s.parse()?;
    Ok(pid)
}

pub fn container_state_load_from_reader<R: std::io::Read>(reader: R) -> anyhow::Result<State> {
    let state: State = serde_json::from_reader(reader)?;
    Ok(state)
}
