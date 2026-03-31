use clap::{CommandFactory, Parser, Subcommand};
use eyre::Result;
use metrics_tracing_context::MetricsLayer;
use powdr_autoprecompiles::{pgo::pgo_config, PgoType};
use sp1_core_machine::{
    autoprecompiles::{
        compile_guest, execution_profile_from_guest, sp1_powdr_config, CompiledProgram,
    },
    io::SP1Stdin,
};
use std::{io, path::PathBuf};
use tracing::Level;
use tracing_forest::ForestLayer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

#[derive(Parser)]
#[command(name = "powdr_sp1", author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Compile {
        guest: String,

        #[arg(long, default_value_t = 1)]
        autoprecompiles: usize,

        #[arg(long, default_value_t = 0)]
        skip: usize,

        #[arg(long, default_value_t = PgoType::default())]
        pgo: PgoType,

        #[arg(long)]
        input: Option<usize>,

        /// When `--pgo cell`, the directory to persist all APC candidates + a metrics summary
        #[arg(long)]
        apc_candidates_dir: Option<PathBuf>,
    },
}

fn main() -> Result<(), io::Error> {
    let args = Cli::parse();

    setup_tracing_with_log_level(Level::INFO);

    if let Some(command) = args.command {
        run_command(command);
        Ok(())
    } else {
        Cli::command().print_help()
    }
}

fn run_command(command: Commands) {
    match command {
        Commands::Compile { guest, autoprecompiles, skip, pgo, input, apc_candidates_dir } => {
            let mut config = sp1_powdr_config(autoprecompiles as u64, skip as u64);
            if let Some(apc_candidates_dir) = apc_candidates_dir {
                config = config.with_apc_candidates_dir(apc_candidates_dir);
            }
            let execution_profile = execution_profile_from_guest(&guest, stdin_from(input));
            let pgo_config = pgo_config(pgo, None, execution_profile);
            let program = compile_guest(&guest, config, pgo_config);
            // `cbor` file written to the guest folder
            write_program_to_file(program, &format!("{guest}_compiled.cbor")).unwrap();
        }
    }
}

fn write_program_to_file(program: CompiledProgram, filename: &str) -> Result<(), io::Error> {
    use std::fs::File;

    let mut file = File::create(filename)?;
    serde_cbor::to_writer(&mut file, &program).map_err(io::Error::other)?;
    Ok(())
}

fn stdin_from(input: Option<usize>) -> SP1Stdin {
    let mut s = SP1Stdin::default();
    if let Some(i) = input {
        s.write(&i);
    }
    s
}

fn setup_tracing_with_log_level(level: Level) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{level},p3_=warn")));
    let subscriber =
        Registry::default().with(env_filter).with(ForestLayer::default()).with(MetricsLayer::new());
    tracing::subscriber::set_global_default(subscriber).unwrap();
}
