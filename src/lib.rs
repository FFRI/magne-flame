//! MagneFlame: Multi-thread Fuzzing Framework for Windows.
//!
//! Current version is only available for Windows.
//! When you compile MangeFlame on Linux, it does not work properly.
//! ## Documentation
//!
//! See [Get Started](https://github.com/FFRI/magne-flame/blob/master/book/src/GetStarted.md)
//!
//! ## Features
//!
//! - Multi-thread fuzzing
//! - Black-box fuzzing
//!

/// Mutator traits and implementations.
pub mod mutator;
/// Prelude.
pub mod prelude;
/// Supervisor traits and implementations.
pub mod supervisor;
/// Scheduler traits and implementations.
pub mod scheduler;
/// Utilities.
pub mod util;
/// FuzzerContext traits and implementations.
pub mod fuzzer;
/// Reporter traits and implementations.
pub mod reporter;
