#![allow(clippy::all)]
#![allow(missing_docs)]
#![allow(clippy::pedantic)]

#[rustfmt::skip]
pub mod artifact;

cfg_if::cfg_if! {
    if #[cfg(feature = "sepolia")] {
        mod sepolia {
            #[rustfmt::skip]
            pub mod network;
            #[rustfmt::skip]
            pub mod types;
        }

        #[rustfmt::skip]
        pub use self::sepolia::{network, types};
    } else {
        mod base {
            #[rustfmt::skip]
            pub mod network;
            #[rustfmt::skip]
            pub mod types;
        }

        #[rustfmt::skip]
        pub use self::base::{network, types};
    }
}