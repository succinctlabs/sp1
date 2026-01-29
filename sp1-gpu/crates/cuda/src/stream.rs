use super::{CudaError, CudaEvent};
use slop_alloc::mem::{CopyDirection, CopyError, DeviceMemory};
use slop_alloc::{AllocError, Allocator};
use sp1_gpu_sys::runtime::{
    cuda_event_record, cuda_free_async, cuda_launch_host_function, cuda_malloc_async,
    cuda_mem_copy_device_to_device_async, cuda_mem_copy_device_to_host_async,
    cuda_mem_copy_host_to_device_async, cuda_mem_set_async, cuda_stream_create,
    cuda_stream_destroy, cuda_stream_query, cuda_stream_synchronize, cuda_stream_wait_event,
    CudaStreamHandle, Dim3, KernelPtr, DEFAULT_STREAM,
};
use std::{
    alloc::Layout,
    ffi::c_void,
    future::{Future, IntoFuture},
    ops::Deref,
    pin::Pin,
    ptr::{self, NonNull},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::Interval;

pub(crate) const INTERVAL_MS: u64 = 2000;

#[derive(Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CudaStream(pub(crate) CudaStreamHandle);

unsafe impl Send for CudaStream {}
unsafe impl Sync for CudaStream {}

impl Drop for CudaStream {
    fn drop(&mut self) {
        if self.0 != unsafe { DEFAULT_STREAM } {
            // We unwrap because any cuda error should throw here.
            CudaError::result_from_ffi(unsafe { cuda_stream_destroy(self.0) }).unwrap();
        }
    }
}

impl CudaStream {
    #[inline]
    pub(crate) fn create() -> Result<Self, CudaError> {
        let mut ptr = CudaStreamHandle(ptr::null_mut());
        CudaError::result_from_ffi(unsafe {
            cuda_stream_create(&mut ptr as *mut CudaStreamHandle)
        })?;
        Ok(Self(ptr))
    }

    /// # Safety
    ///
    /// TODO
    #[inline]
    unsafe fn launch_host_fn(
        &self,
        host_fn: Option<unsafe extern "C" fn(*mut c_void)>,
        data: *const c_void,
    ) -> Result<(), CudaError> {
        CudaError::result_from_ffi(unsafe { cuda_launch_host_function(self.0, host_fn, data) })
    }

    /// # Safety
    ///
    /// This function launch is asynchronous when called with the non-default stream. The caller
    /// must ensure that the data read to and written by the kernel remains valid throughout its
    /// execution.
    #[inline]
    pub unsafe fn launch_kernel(
        &self,
        kernel: KernelPtr,
        grid_dim: impl Into<Dim3>,
        block_dim: impl Into<Dim3>,
        args: &[*mut c_void],
        shared_mem: usize,
    ) -> Result<(), CudaError> {
        CudaError::result_from_ffi(sp1_gpu_sys::runtime::cuda_launch_kernel(
            kernel,
            grid_dim.into(),
            block_dim.into(),
            args.as_ptr() as *mut *mut c_void,
            shared_mem,
            self.0,
        ))
    }

    #[inline]
    fn query(&self) -> Result<(), CudaError> {
        CudaError::result_from_ffi(unsafe { cuda_stream_query(self.0) })
    }

    #[inline]
    fn record(&self, event: &CudaEvent) -> Result<(), CudaError> {
        CudaError::result_from_ffi(unsafe { cuda_event_record(event.0, self.0) })
    }

    /// # Safety
    ///
    /// This function is marked unsafe because it requires the caller to ensure that the event is
    /// valid and that the stream is valid.
    #[inline]
    unsafe fn wait(&self, event: &CudaEvent) -> Result<(), CudaError> {
        CudaError::result_from_ffi(cuda_stream_wait_event(self.0, event.0))
    }

    #[inline]
    fn synchronize(&self) -> Result<(), CudaError> {
        CudaError::result_from_ffi(unsafe { cuda_stream_synchronize(self.0) })
    }
}

impl Default for CudaStream {
    fn default() -> Self {
        Self(unsafe { DEFAULT_STREAM })
    }
}

/// State shared between the future and the CUDA callback
struct CallbackState<S> {
    // Holding the stream to prevent it from being dropped
    task: Option<S>,
    done: bool,
    result: Result<(), CudaError>,
    waker: Option<Waker>,
}

/// A future that completes once the GPU has completed all work queued in `stream` so far.
///
/// This future uses a callback to the host to check if the GPU has completed all work. This is
/// useful for waiting for the GPU to finish work before continuing on the host and avoiding
/// busy-waiting.
pub struct StreamCallbackFuture<S> {
    shared: Arc<Mutex<CallbackState<S>>>,
    interval: Pin<Box<Interval>>,
}

// /// A future that completes once the GPU has completed all work queued in `stream` so far.
// ///
// /// This future uses a busy-wait loop to check if the GPU has completed all work. This is useful for
// /// a future waiting on stream completion with minimal overhead.
// #[repr(transparent)]
// pub struct StreamSpinFuture {
//     stream: CudaStream,
// }

pub trait StreamRef {
    unsafe fn stream(&self) -> &CudaStream;

    /// # Safety
    ///
    /// TODO
    #[inline]
    unsafe fn launch_host_fn_uncheked(
        &self,
        host_fn: Option<unsafe extern "C" fn(*mut c_void)>,
        data: *const c_void,
    ) -> Result<(), CudaError> {
        self.stream().launch_host_fn(host_fn, data)
    }

    #[inline]
    unsafe fn query(&self) -> Result<(), CudaError> {
        self.stream().query()
    }

    #[inline]
    unsafe fn record_unchecked(&self, event: &CudaEvent) -> Result<(), CudaError> {
        self.stream().record(event)
    }

    /// # Safety
    ///
    /// This function is marked unsafe because it requires the caller to ensure that the event is
    /// valid and that the stream is valid.
    #[inline]
    unsafe fn wait_unchecked(&self, event: &CudaEvent) -> Result<(), CudaError> {
        self.stream().wait(event)
    }

    #[inline]
    unsafe fn stream_synchronize(&self) -> Result<(), CudaError> {
        self.stream().synchronize()
    }
}

impl StreamRef for CudaStream {
    #[inline]
    unsafe fn stream(&self) -> &CudaStream {
        self
    }
}

impl<S> StreamRef for Arc<S>
where
    S: StreamRef + ?Sized,
{
    #[inline]
    unsafe fn stream(&self) -> &CudaStream {
        self.as_ref().stream()
    }
}

impl<S> StreamCallbackFuture<S> {
    /// Creates a new future that completes once the GPU has completed
    /// all work queued in `stream` so far.
    pub fn new(task: S) -> Self
    where
        S: StreamRef,
    {
        // 1) Create an Arc<Mutex<...>> for the shared state
        let shared = Arc::new(Mutex::new(CallbackState {
            task: None,
            done: false,
            result: Ok(()),
            waker: None,
        }));

        // 2) Convert Arc to a raw pointer for CUDA, leaking one Arc so  that the context is not
        //    dropped before the callback is called.
        let ptr = Arc::into_raw(shared.clone()) as *mut c_void;

        // 3) Enqueue the callback on the given stream
        //    This means "when the GPU finishes all prior tasks in `stream`,
        //    call `my_host_callback(ptr)`"
        let launch_result = unsafe { task.stream().launch_host_fn(Some(waker_callback::<S>), ptr) };

        shared.lock().unwrap().task = Some(task);

        if let Err(e) = launch_result {
            let mut state = shared.lock().unwrap();
            state.result = Err(e);
            state.done = true;
        }

        let interval = Box::pin(tokio::time::interval(Duration::from_millis(INTERVAL_MS)));

        Self { shared, interval }
    }
}

unsafe extern "C" fn waker_callback<S>(user_data: *mut c_void)
where
    S: StreamRef,
{
    // Convert the raw pointer back to our Arc<Mutex<CallbackState>>
    let shared = Arc::<Mutex<CallbackState<S>>>::from_raw(user_data as *const _);
    let mut state = shared.lock().unwrap();

    // Mark GPU done
    state.done = true;

    // If we have a waker, wake it so poll() is called again
    if let Some(ref waker) = state.waker {
        waker.wake_by_ref();
    }
}

impl<S> Future for StreamCallbackFuture<S>
where
    S: StreamRef,
{
    type Output = Result<(), CudaError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.shared.lock().unwrap();

        // If the stream is done, return the result
        if state.done {
            // GPU has reached the callback
            return Poll::Ready(state.result);
        }

        //  If not done, check the stream's status
        match unsafe { state.task.as_ref().unwrap().stream().query() } {
            Ok(()) => {
                state.done = true;
                state.result = Ok(());
                return Poll::Ready(Ok(()));
            }
            Err(CudaError::NotReady) => {
                // Stream is not done yet, so we need to wait for it.
            }
            Err(e) => {
                // Got an error from the stream, so we need to return it.
                state.done = true;
                state.result = Err(e);
                return Poll::Ready(Err(e));
            }
        }

        // Not done yet, store the waker so we can wake it later
        state.waker = Some(cx.waker().clone());
        drop(state);

        // Poll the interval to check if we need to wake up again
        match self.interval.as_mut().poll_tick(cx) {
            Poll::Ready(_) => {
                // The time has passed, so we need to schedule another poll
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => {
                // The time has not passed yet, so we need to wait for it or for the callback.
                Poll::Pending
            }
        }
    }
}

impl IntoFuture for CudaStream {
    type Output = Result<(), CudaError>;
    type IntoFuture = StreamCallbackFuture<Self>;

    fn into_future(self) -> Self::IntoFuture {
        StreamCallbackFuture::new(self)
    }
}

unsafe impl Allocator for CudaStream {
    #[inline]
    unsafe fn allocate(&self, layout: Layout) -> Result<ptr::NonNull<[u8]>, AllocError> {
        let mut ptr: *mut c_void = ptr::null_mut();
        unsafe {
            CudaError::result_from_ffi(cuda_malloc_async(
                &mut ptr as *mut *mut c_void,
                layout.size(),
                self.0,
            ))
            .map_err(|_| AllocError)?;
        };
        let ptr = ptr as *mut u8;
        Ok(NonNull::slice_from_raw_parts(NonNull::new_unchecked(ptr), layout.size()))
    }

    #[inline]
    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            CudaError::result_from_ffi(cuda_free_async(ptr.as_ptr() as *mut c_void, self.0))
                .unwrap()
        }
    }
}

impl DeviceMemory for CudaStream {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError> {
        let maybe_err = match direction {
            CopyDirection::HostToDevice => cuda_mem_copy_host_to_device_async(
                dst as *mut c_void,
                src as *const c_void,
                size,
                self.0,
            ),
            CopyDirection::DeviceToHost => cuda_mem_copy_device_to_host_async(
                dst as *mut c_void,
                src as *const c_void,
                size,
                self.0,
            ),
            CopyDirection::DeviceToDevice => cuda_mem_copy_device_to_device_async(
                dst as *mut c_void,
                src as *const c_void,
                size,
                self.0,
            ),
        };
        CudaError::result_from_ffi(maybe_err).map_err(|_| CopyError)
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        unsafe {
            CudaError::result_from_ffi(cuda_mem_set_async(dst as *mut c_void, value, size, self.0))
                .map_err(|_| CopyError)
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct UnsafeCudaStream(CudaStream);

impl UnsafeCudaStream {
    #[allow(dead_code)]
    pub fn create() -> Result<Self, CudaError> {
        Ok(Self(CudaStream::create()?))
    }
}

impl Deref for UnsafeCudaStream {
    type Target = CudaStream;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl StreamRef for UnsafeCudaStream {
    #[inline]
    unsafe fn stream(&self) -> &CudaStream {
        &self.0
    }
}

impl IntoFuture for UnsafeCudaStream {
    type Output = Result<(), CudaError>;
    type IntoFuture = StreamCallbackFuture<Self>;

    fn into_future(self) -> Self::IntoFuture {
        StreamCallbackFuture::new(self)
    }
}

unsafe impl Allocator for UnsafeCudaStream {
    #[inline]
    unsafe fn allocate(&self, layout: Layout) -> Result<ptr::NonNull<[u8]>, AllocError> {
        self.0.allocate(layout)
    }

    #[inline]
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.0.deallocate(ptr, layout)
    }
}

impl DeviceMemory for UnsafeCudaStream {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError> {
        self.0.copy_nonoverlapping(src, dst, size, direction)
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        self.0.write_bytes(dst, value, size)
    }
}
