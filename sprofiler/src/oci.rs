use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub oci_version: String,
    pub id: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    pub bundle: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    #[serde(rename = "creating")]
    Creating,
    #[serde(rename = "created")]
    Created,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopped")]
    Stopped,
}
