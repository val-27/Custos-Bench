//! Coordinated-omission-free open-loop load generator for Custos.

mod cli;
mod raw_codec;
mod report;
mod scheduler;
mod telemetry;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use quanta::Clock;

use crate::cli::Cli;
use crate::report::{export, print_summary};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    if cli.workers > 0 {
        runtime.worker_threads(cli.workers);
    }
    let runtime = match runtime.build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("failed to build runtime: {err}");
            return ExitCode::from(1);
        }
    };
    let clock = Clock::new();
    match runtime.block_on(scheduler::execute(&cli, &clock)) {
        Ok(trial) => {
            let _ = print_summary(&trial, io::stdout());
            match export(&trial, &cli.output_dir) {
                Ok((json_path, csv_path)) => {
                    let _ = writeln!(io::stdout(), "json {}", json_path.display());
                    let _ = writeln!(io::stdout(), "csv  {}", csv_path.display());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("failed to export results: {err}");
                    ExitCode::from(2)
                }
            }
        }
        Err(err) => {
            eprintln!("benchmark failed: {err:#}");
            ExitCode::from(1)
        }
    }
}
