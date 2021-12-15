// Copyright 2021, Nobuto Kaitoh
//
// This file is part of yatotp.
//
// Yatotp is free software: you can redistribute it and/or
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Yatotp is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with yatotp.  If not, see <https://www.gnu.org/licenses/>.


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
