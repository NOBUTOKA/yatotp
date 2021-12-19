[![Crates.io](https://img.shields.io/crates/v/yatotp)](https://crates.io/crates/yatotp)
[![docs.rs](https://img.shields.io/docsrs/yatotp)](https://docs.rs/yatotp/latest/yatotp/)
[![Workflow Status](https://github.com/NOBUTOKA/yatotp/workflows/Rust/badge.svg)](https://github.com/NOBUTOKA/yatotp/actions?query=workflow%3A%22Rust%22)
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)
![license](https://img.shields.io/crates/l/yatotp)

# yatotp

Yet Another Time-based OTP client.

It stores TOTP accounts information locally, encrypted
so user can sync accounts with their own means (like cloud storage or USB storage).
It means user does not need to trust one specific sync server.

In other words, the aim of this project is TOTP version of [Keepass].

[Keepass]: https://keepass.info

For now, it have only command-line interface.
## Usage
- Create database file (encryption password is needed).
  ```sh
  yatotp -i [database file path] create
  ```
- Add database to entry interactively.
  ```sh
  yatotp -i [database file path] add
  ```
  If you want to use base32-encoded secret key, such as gained from OpenAuth URI,
  add switch `-e` (`e` for Encoded) like this:
  ```sh
  yatotp -i [database file path] add -e
  ```
- Show TOTP value of the entry.
  ```sh
  yatotp -i [database file path] show [entry name]
  ```
- List entries in database.
  ```sh
  yatotp -i [database file path] list
  ```
- Remove the entry from database.
  ```sh
  yatotp -i [database file path] remove [entry name]
  ```
- Change database password to new one.
  ```sh
  yatotp -i [database file path] newpass
  ```

Current version: 0.2.0

License: AGPL-3.0-or-later
