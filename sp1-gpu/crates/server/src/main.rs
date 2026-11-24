#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// Trace records are large and short lived. Return dirty pages between proving stages.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[export_name = "_rjem_malloc_conf"]
pub static JEMALLOC_CONF: &std::ffi::c_char =
    unsafe { &*c"narenas:8,background_thread:true,dirty_decay_ms:250,muzzy_decay_ms:250".as_ptr() };

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

    if std::env::var_os("RAYON_NUM_THREADS").is_none()
        && std::env::var_os("RAYON_RS_NUM_CPUS").is_none()
    {
        // Trace generation is bandwidth bound and runs alongside execution and the GPU driver.
        let threads = num_cpus::get_physical().min(num_cpus::get()).max(1);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .expect("failed to initialize the CPU trace workers");
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
