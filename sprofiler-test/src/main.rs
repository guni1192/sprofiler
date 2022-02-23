use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::{trace, Level};

mod testing;
use testing::run_tests;

mod hooks;
mod podman;
mod seccomp;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Test case files
    tests_file: PathBuf,

    /// Log Level (TRACE, INFO, )
    #[clap(short, long, default_value_t = Level::INFO)]
    log_level: Level,
}

#[async_std::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(args.log_level)
        .without_time()
        .init();

    let reader = File::open(args.tests_file)?;
    let testing = serde_yaml::from_reader(&reader)?;

    trace!("Starting test tool");
    run_tests(testing).await?;

    Ok(())
}
