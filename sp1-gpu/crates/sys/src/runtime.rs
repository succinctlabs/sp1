use std::ffi::{c_char, c_void};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct CudaRustError {
    pub message: *const c_char,
}

extern "C" {
    pub static CUDA_SUCCESS_CSL: CudaRustError;

    pub static CUDA_OUT_OF_MEMORY: CudaRustError;

    pub static CUDA_ERROR_NOT_READY_SLOP: CudaRustError;

    pub fn cuda_malloc(ptr: *mut *mut c_void, count: usize) -> CudaRustError;

    pub fn cuda_free(ptr: *const c_void) -> CudaRustError;

    pub fn cuda_mem_get_info(free: *mut usize, total: *mut usize) -> CudaRustError;

    pub fn cuda_malloc_host(ptr: *mut *mut c_void, count: usize) -> CudaRustError;
    pub fn cuda_host_register(ptr: *const c_void, count: usize) -> CudaRustError;
    pub fn cuda_free_host(ptr: *const c_void) -> CudaRustError;
    pub fn cuda_host_unregister(ptr: *const c_void) -> CudaRustError;

    pub fn cuda_mem_set(dst: *mut c_void, value: u8, size: usize) -> CudaRustError;

    pub fn cuda_mem_copy_host_to_device(
        dst: *mut c_void,
        src: *const c_void,
        count: usize,
    ) -> CudaRustError;

    pub fn cuda_mem_copy_device_to_host(
        dst: *mut c_void,
        src: *const c_void,
        count: usize,
    ) -> CudaRustError;

    pub fn cuda_mem_copy_device_to_device(
        dst: *const c_void,
        src: *const c_void,
        count: usize,
    ) -> CudaRustError;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CudaStreamHandle(pub *mut c_void);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CudaEventHandle(pub *mut c_void);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Dim3 {
    pub x: u32,
    pub y: u32,
    pub z: u32,
}

#[repr(transparent)]
pub struct KernelPtr(pub *const c_void);

#[repr(transparent)]
pub struct CudaMemPool(pub *mut c_void);

#[repr(transparent)]
pub struct CudaDevice(pub i32);

extern "C" {

    pub static DEFAULT_STREAM: CudaStreamHandle;

    pub fn cuda_device_synchronize() -> CudaRustError;
    pub fn cuda_event_create(event: *mut CudaEventHandle) -> CudaRustError;
    pub fn cuda_event_destroy(event: CudaEventHandle) -> CudaRustError;
    pub fn cuda_event_record(event: CudaEventHandle, stream: CudaStreamHandle) -> CudaRustError;
    pub fn cuda_event_synchronize(event: CudaEventHandle) -> CudaRustError;
    pub fn cuda_event_elapsed_time(
        ms: *mut f32,
        start: CudaEventHandle,
        end: CudaEventHandle,
    ) -> CudaRustError;

    pub fn cuda_stream_create(stream: *mut CudaStreamHandle) -> CudaRustError;
    pub fn cuda_stream_destroy(stream: CudaStreamHandle) -> CudaRustError;
    pub fn cuda_stream_synchronize(stream: CudaStreamHandle) -> CudaRustError;

    pub fn cuda_stream_wait_event(
        stream: CudaStreamHandle,
        event: CudaEventHandle,
    ) -> CudaRustError;

    // Async memory operations.

    pub fn cuda_malloc_async(
        devPtr: *mut *mut c_void,
        size: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    pub fn cuda_mem_set_async(
        dst: *mut c_void,
        value: u8,
        size: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    pub fn cuda_free_async(devPtr: *mut c_void, stream: CudaStreamHandle) -> CudaRustError;

    pub fn cuda_mem_copy_device_to_device_async(
        dst: *mut c_void,
        src: *const c_void,
        count: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;
    pub fn cuda_mem_copy_host_to_device_async(
        dst: *mut c_void,
        src: *const c_void,
        count: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;
    pub fn cuda_mem_copy_device_to_host_async(
        dst: *mut c_void,
        src: *const c_void,
        count: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;
    pub fn cuda_mem_copy_host_to_host_async(
        dst: *mut c_void,
        src: *const c_void,
        count: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    pub fn cuda_stream_query(stream: CudaStreamHandle) -> CudaRustError;

    pub fn cuda_event_query(event: CudaEventHandle) -> CudaRustError;

    pub fn cuda_launch_host_function(
        stream: CudaStreamHandle,
        host_fn: Option<unsafe extern "C" fn(*mut c_void)>,
        data: *const c_void,
    ) -> CudaRustError;

    pub fn cuda_launch_kernel(
        kernel: KernelPtr,
        grid: Dim3,
        block: Dim3,
        args: *mut *mut c_void,
        shared_mem: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    pub fn cuda_device_get_default_mem_pool(
        memPool: *mut CudaMemPool,
        device: CudaDevice,
    ) -> CudaRustError;

    pub fn cuda_device_get_mem_pool(memPool: *mut CudaMemPool, device: CudaDevice)
        -> CudaRustError;
    pub fn cuda_mem_pool_set_release_threshold(
        memPool: CudaMemPool,
        threshold: u64,
    ) -> CudaRustError;
}

#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct NvtxRangeId(u64);

extern "C" {
    pub fn nvtx_range_start(name: *const c_char) -> NvtxRangeId;

    pub fn nvtx_range_end(domain: NvtxRangeId);
}

impl Dim3 {
    pub fn new(x: u32, y: u32, z: u32) -> Self {
        Self { x, y, z }
    }

    pub fn x(num_elements: u32) -> Self {
        Self { x: num_elements, y: 1, z: 1 }
    }
}

impl From<u32> for Dim3 {
    fn from(x: u32) -> Self {
        Self { x, y: 1, z: 1 }
    }
}

impl From<u64> for Dim3 {
    fn from(x: u64) -> Self {
        Self { x: x as u32, y: 1, z: 1 }
    }
}

impl From<i32> for Dim3 {
    fn from(x: i32) -> Self {
        Self { x: x as u32, y: 1, z: 1 }
    }
}

impl From<i64> for Dim3 {
    fn from(x: i64) -> Self {
        Self { x: x as u32, y: 1, z: 1 }
    }
}

impl From<usize> for Dim3 {
    fn from(x: usize) -> Self {
        Self { x: x as u32, y: 1, z: 1 }
    }
}

impl From<(u32, u32, u32)> for Dim3 {
    fn from((x, y, z): (u32, u32, u32)) -> Self {
        Self { x, y, z }
    }
}

impl From<(u64, u64, u64)> for Dim3 {
    fn from((x, y, z): (u64, u64, u64)) -> Self {
        Self { x: x as u32, y: y as u32, z: z as u32 }
    }
}

impl From<(usize, usize, usize)> for Dim3 {
    fn from((x, y, z): (usize, usize, usize)) -> Self {
        Self { x: x as u32, y: y as u32, z: z as u32 }
    }
}
