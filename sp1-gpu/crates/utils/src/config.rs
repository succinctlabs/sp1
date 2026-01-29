//! A global configuration of types for device code.
//!
//! We are defining the field element and extension element as type aliases rather than using
//! generics in order to avoid complicated trait bounds but remain flexible enough to support
//! different field and extension element types.

use sp1_primitives::{SP1ExtensionField, SP1Field, SP1GlobalContext};

/// The base field element type.
pub type Felt = SP1Field;

/// The extension field element type.
pub type Ext = SP1ExtensionField;

/// The most common GC, used for testing.
pub type TestGC = SP1GlobalContext;
