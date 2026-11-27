#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// jemalloc reads this C string before main. Release the short-lived trace pages between stages.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[export_name = "_rjem_malloc_conf"]
static JEMALLOC_CONF: &u8 =
    &c"narenas:8,background_thread:true,dirty_decay_ms:250,muzzy_decay_ms:250".to_bytes_with_nul()
        [0];

use clap::Parser;
use server::Server;
use sp1_gpu_cudart::run_in_place;

mod server;

#[derive(Debug, Parser)]
struct Args {
    #[clap(long)]
    version: bool,
}

#[tokio::main]
#[allow(clippy::print_stdout)]
async fn main() {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    if args.version {
        println!("{}", sp1_primitives::SP1_CRATE_VERSION);
        return;
    }

    let cuda_device_id = std::env::var("CUDA_VISIBLE_DEVICES")
        .expect("CUDA_VISIBLE_DEVICES must be set")
        .parse()
        .expect("Expected only one CUDA device as a u32");

    let server = Server { cuda_device_id };

    if let Err(e) = run_in_place(|scope| server.run(scope)).await.await {
        eprintln!("Error running server: {e}");
    }
}
