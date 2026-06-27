mod audit;
mod config;
mod panel;
mod policy;
mod runtime;
mod ssr;
mod tcp;
mod traffic;
mod udp;

use std::path::PathBuf;

use anyhow::Result;
use config::Config;
use panel::PanelClient;
use runtime::BackendRuntime;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let config_path = config_path_from_args();
    let config = Config::load(&config_path)?;
    config.validate()?;

    let panel = PanelClient::new(&config.panel)?;
    let runtime = BackendRuntime::new(config, panel);
    runtime.run().await
}

fn config_path_from_args() -> PathBuf {
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(path) = args.next() {
                return PathBuf::from(path);
            }
        }
    }
    PathBuf::from("config.toml")
}
