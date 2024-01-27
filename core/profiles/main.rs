use clap::{command, Parser};
#[cfg(feature = "perf")]
use succinct_core::runtime::Program;
#[cfg(feature = "perf")]
use succinct_core::utils::{self, prove};

#[derive(Parser, Debug, Clone)]
#[command(about = "Profile a program.")]
struct ProfileArgs {
    #[arg(long)]
    pub program: String,
}

fn main() {
    #[cfg(feature = "perf")]
    {
        utils::setup_tracer();
        let args = ProfileArgs::parse();
        let program = Program::from_elf(args.program.as_str());
        prove(program);
    }

    #[cfg(not(feature = "perf"))]
    panic!("--features=perf must be enabled to run this program");
}
