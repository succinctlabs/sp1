use std::{slice, time::Duration};

use sp1_gpu_cudart::{
    run_sync_in_place, sys::runtime::cuda_stream_query, CudaError, DeviceBuffer, PinnedBuffer,
};

#[test]
fn borrowed_pinned_host_memory_is_ready_when_the_copy_returns() {
    run_sync_in_place(|scope| {
        let mut host = PinnedBuffer::<u32>::with_capacity(1);
        let mut device = DeviceBuffer::with_capacity_in(1, scope.clone());
        let value = host.as_mut_slice()[0].write(42);
        scope.sleep(Duration::from_millis(30));
        // The stream queue is deliberately occupied so an asynchronous transfer
        // cannot normally finish by the time the caller regains its host slice.
        let uploaded = unsafe {
            device.extend_from_host_slice(slice::from_ref(value)).unwrap();
            CudaError::result_from_ffi(cuda_stream_query(scope.handle()))
        };
        scope.synchronize_blocking().unwrap();
        uploaded.unwrap();

        host.as_mut_slice()[0].write(0);
        scope.sleep(Duration::from_millis(30));
        let downloaded = unsafe {
            device.copy_to_host_slice(host.as_mut_slice()).unwrap();
            CudaError::result_from_ffi(cuda_stream_query(scope.handle()))
        };
        scope.synchronize_blocking().unwrap();
        downloaded.unwrap();
        assert_eq!(unsafe { host.as_slice()[0].assume_init() }, 42);
    })
    .unwrap();
}
