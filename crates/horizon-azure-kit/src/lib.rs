//! Shared Azure plumbing for Horizon Tech desktop tools.
//!
//! See the crate README for the module overview. Only code needed by more
//! than one product lives here.

#![deny(rust_2018_idioms, unsafe_code, missing_docs)]
#![warn(clippy::all)]

pub mod arm;
pub mod auth;
pub mod cloud;
pub mod error;
pub mod safety;
pub mod sas;
pub mod secrets;

pub use cloud::AzureCloud;
pub use error::{KitError, KitResult};
