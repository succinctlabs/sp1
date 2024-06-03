#![allow(unused)]

//! FFI bindings for the Go code. The functions exported in this module are safe to call from Rust.
//! All C strings and other C memory should be freed in Rust, including C Strings returned by Go.
//! Although we cast to *mut c_char because the Go signatures can't be immutable, the Go functions
//! should not modify the strings.

use crate::PlonkBn254Proof;
use cfg_if::cfg_if;
use std::env;
use std::ffi::{c_char, CString};
use std::process::Command;

pub fn prove_plonk_bn254(data_dir: &str, witness_path: &str) -> PlonkBn254Proof {
    cfg_if! {
        if #[cfg(feature = "plonk")] {
            todo!("Docker connection not yet implemented.");
        } else {
            panic!("plonk feature not enabled");
        }
    }
}

pub fn build_plonk_bn254(data_dir: &str) {
    cfg_if! {
        if #[cfg(feature = "plonk")] {
            let cwd = env::current_dir().expect("Couldn't get CWD");
            let cwd_str = cwd.to_str().expect("Couldn't convert CWD to string");

            let status = Command::new("docker")
                .args([
                    "run",
                    "--rm",
                    "--mount",
                    format!("type=bind,source={},target=/root", cwd_str).as_str(),
                    "gnark-cli",
                    "build",
                    data_dir,
                ])
                .status()
                .expect("Failed to run GNARK CLI via Docker");

        } else {
            panic!("plonk feature not enabled");
        }
    }
}

pub fn verify_plonk_bn254(
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
) -> Result<(), String> {
    cfg_if! {
        if #[cfg(feature = "plonk")] {
            todo!("Docker connection not yet implemented.");
        } else {
            panic!("plonk feature not enabled");
        }
    }
}

pub fn test_plonk_bn254(witness_json: &str, constraints_json: &str) {
    cfg_if! {
        if #[cfg(feature = "plonk")] {
            todo!("Docker connection not yet implemented.");
        } else {
            panic!("plonk feature not enabled");
        }
    }
}

/// Converts a C string into a Rust String.
///
/// # Safety
/// This function frees the string memory, so the caller must ensure that the pointer is not used
/// after this function is called.
unsafe fn c_char_ptr_to_string(input: *mut c_char) -> String {
    unsafe {
        CString::from_raw(input) // Converts a pointer that C uses into a CString
            .into_string()
            .expect("CString::into_string failed")
    }
}
