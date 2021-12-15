#![warn(missing_docs)]
//! Yet Another Time-based OTP client.
//!
//! It stores TOTP accounts information locally, encrypted
//! so user can sync accounts with their own means (like cloud storage or USB storage).
//! It means user does not need to trust one specific sync server.
//!
//! In other words, the aim of this project is TOTP version of [Keepass].
//!
//! [Keepass]: https://keepass.info

pub mod cli;
pub mod database;
pub mod otp;
