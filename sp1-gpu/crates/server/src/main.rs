#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use clap::Parser;
use server::Server;
use sp1_cuda::client::socket_path;
use sp1_gpu_cudart::run_in_place;
use tokio::net::UnixListener;

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

    eprintln!(
        "Running sp1-gpu-server {} with device {}",
        sp1_primitives::SP1_CRATE_VERSION,
        cuda_device_id
    );

    // Bind the socket *before* CUDA init. CUDA context creation can take
    // several seconds on cold GPUs; if the listener isn't ready by then the
    // sp1-cuda client's 1s reconnect window fires and panics the parent.
    let socket_path = socket_path(cuda_device_id);
    if let Err(e) = std::fs::remove_file(&socket_path) {
        tracing::warn!("Failed to remove orphaned socket: {}", e);
    }
    let listener =
        UnixListener::bind(&socket_path).expect("Failed to bind to socket addr");
    tracing::info!("Server listening @ {}", socket_path.display());

    let server = Server { cuda_device_id };

    if let Err(e) = run_in_place(|scope| server.run(scope, listener, socket_path)).await.await {
        eprintln!("Error running server: {e}");
    }
}
