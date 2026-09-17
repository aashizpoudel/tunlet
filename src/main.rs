//! Parse command-line arguments and configuration, initialize logging, and start execution.

use std::{env, process::ExitCode};
use tokio_util::sync::CancellationToken;
use tunlet::{
    cli::{self, Command, Mode},
    config::{self, ProcessEnv},
    error::Result,
    logging, shutdown,
    timing::Timing,
};

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("tunlet: cannot start the async runtime: {error}");
            return ExitCode::from(1);
        }
    };
    let code = match runtime.block_on(run()) {
        Ok(()) => 0,
        Err(error) => {
            // Output fatal errors to stderr, even when quiet mode is active.
            eprintln!("tunlet: {error}");
            error.exit_code()
        }
    };
    ExitCode::from(code as u8)
}

async fn run() -> Result<()> {
    // The help and version commands do not read configuration files or require a key.
    let command = cli::parse(env::args_os())?;
    let (mode, path, config_explicit, raw) = match command {
        Command::Help => {
            print!("{}", cli::help());
            return Ok(());
        }
        Command::Version => {
            println!("{}", cli::version());
            return Ok(());
        }
        Command::Run {
            mode,
            config,
            config_explicit,
            cli,
        } => (mode, config, config_explicit, cli),
    };

    let merged = config::resolve(&path, config_explicit, raw, &ProcessEnv)?;
    let cancel = CancellationToken::new();
    let signals = cancel.clone();
    tokio::spawn(async move { shutdown::wait_for_signal(signals).await });

    match mode {
        Mode::Server => {
            let config = config::server(&merged)?;
            logging::init(config.log_level, config.quiet);
            tunlet::server::run(config, Timing::default(), cancel, None).await
        }
        Mode::Expose => {
            let config = config::expose(&merged)?;
            logging::init(config.log_level, config.quiet);
            tunlet::client::run(config, Timing::default(), cancel).await
        }
    }
}
