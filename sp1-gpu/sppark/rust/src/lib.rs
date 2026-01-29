// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

// Declare C/C++ counterpart as following:
// extern "C" { fn foobar(...) -> sppark::Error; }
#[repr(C)]
pub struct Error {
    pub code: i32,
    str: Option<core::ptr::NonNull<i8>>, // just strdup("string") from C/C++
}

impl Drop for Error {
    fn drop(&mut self) {
        extern "C" {
            fn free(str: Option<core::ptr::NonNull<i8>>);
        }
        unsafe { free(self.str) };
        self.str = None;
    }
}

impl From<&Error> for String {
    fn from(status: &Error) -> Self {
        if let Some(str) = status.str {
            let c_str = unsafe { std::ffi::CStr::from_ptr(str.as_ptr() as *const _) };
            String::from(c_str.to_str().unwrap_or("unintelligible"))
        } else {
            format!("sppark::Error #{}", status.code)
        }
    }
}

impl From<Error> for String {
    fn from(status: Error) -> Self {
        String::from(&status)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", String::from(self))
    }
}

#[macro_export]
macro_rules! cuda_error {
    // legacy macro, deprecated
    () => {
        mod cuda {
            pub type Error = sppark::Error;
        }
    };
}

use core::ffi::c_void;
#[cfg(feature = "cuda")]
use core::mem::transmute;

#[repr(C)]
pub struct Gpu_Ptr<T> {
    ptr: *const c_void,
    phantom: core::marker::PhantomData<T>,
}

#[cfg(feature = "cuda")]
impl<T> Default for Gpu_Ptr<T> {
    fn default() -> Self {
        Self {
            ptr: core::ptr::null(),
            phantom: core::marker::PhantomData,
        }
    }
}

#[cfg(feature = "cuda")]
impl<T> Drop for Gpu_Ptr<T> {
    fn drop(&mut self) {
        extern "C" {
            fn drop_gpu_ptr_t(by_ref: &Gpu_Ptr<c_void>);
        }
        unsafe { drop_gpu_ptr_t(transmute::<&_, &_>(self)) };
        self.ptr = core::ptr::null();
    }
}

#[cfg(feature = "cuda")]
impl<T> Clone for Gpu_Ptr<T> {
    fn clone(&self) -> Self {
        extern "C" {
            fn clone_gpu_ptr_t(by_ref: &Gpu_Ptr<c_void>) -> Gpu_Ptr<c_void>;
        }
        unsafe { transmute::<_, _>(clone_gpu_ptr_t(transmute::<&_, &_>(self))) }
    }
}

#[repr(C)]
pub enum NTTInputOutputOrder {
    NN = 0,
    NR = 1,
    RN = 2,
    RR = 3,
}

#[repr(C)]
pub enum NTTDirection {
    Forward = 0,
    Inverse = 1,
}

#[repr(C)]
pub enum NTTType {
    Standard = 0,
    Coset = 1,
}
