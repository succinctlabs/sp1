use sp1_gpu_cudart::sys::runtime::{nvtx_range_end, nvtx_range_start, NvtxRangeId};
use tracing::{span, Subscriber};
use tracing_subscriber::{layer::Context, registry::LookupSpan, Layer};

pub struct NvtxLayer;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for NvtxLayer {
    fn on_new_span(&self, _attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Failed to get span");

        // Attach start domain to the span
        let range = start_range(span.name());
        span.extensions_mut().insert(range);
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("Failed to get span");

        // Retrieve start time and calculate the duration
        let extensions = span.extensions();
        if let Some(range) = extensions.get::<NvtxRangeId>() {
            end_range(*range);
        }
    }
}

fn start_range(name: &str) -> NvtxRangeId {
    let name = std::ffi::CString::new(name).unwrap();
    unsafe { nvtx_range_start(name.as_ptr()) }
}

fn end_range(id: NvtxRangeId) {
    unsafe { nvtx_range_end(id) }
}
