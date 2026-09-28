// Copyright 2025 The Binius Developers
// Copyright 2025 Irreducible, Inc.
// Modifications copyright 2026 Succinct Labs, Benedikt Bunz, William Wang
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Portable arithmetic for binary fields.

mod binary_field_8;
mod ghash;

pub use binary_field_8::BinaryField8;
pub use ghash::{GHash, GHashUnreduced};
