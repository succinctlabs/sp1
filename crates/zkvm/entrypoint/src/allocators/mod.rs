#[cfg(not(feature = "embedded"))]
mod bump;

#[cfg(feature = "embedded")]
pub mod embedded;
