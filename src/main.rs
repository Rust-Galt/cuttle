mod app;
mod cli;

use crate::app::App;
use color_eyre::eyre::Result;

// Decryption not implemented yet!

fn main() -> Result<()> {
    // Install the panic and error report handlers
    color_eyre::install()?;
    // initialize cli
    let config = cli::initialize()?;

    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt()
        // all spans/events with a level higher than TRACE (e.g, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(config.verbosity)
        // sets this to be the default, global collector for this application.
        .init();

    App::new().run(config.operation)
}
