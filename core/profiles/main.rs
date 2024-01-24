use clap::{command, Parser};
use succinct_core::runtime::Program;
use succinct_core::utils::{self, prove};

#[derive(Parser, Debug, Clone)]
#[command(about = "Profile a program.")]
struct ProfileArgs {
    #[arg(long)]
    pub program: String,
}

fn main() {
    #[cfg(not(feature = "perf"))]
    unreachable!("--features=perf must be enabled to run this program");

    utils::setup_tracer();
    let args = ProfileArgs::parse();
    let program = Program::from_elf(args.program.as_str());
    prove(program);
}
