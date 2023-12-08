use clap::Parser;

#[derive(Parser)]
#[command(about = "A Curta interpreter.")]
pub struct Args {
    /// Program assemnly file
    #[arg(long)]
    pub program: String,

    #[arg(long, default_value = "programs")]
    pub src_dir: String,

    #[arg(long, default_value = "programs/build")]
    pub build_dir: String,
}
