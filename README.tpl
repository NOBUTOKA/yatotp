[![Crates.io](https://img.shields.io/crates/v/yatotp)](https://crates.io/crates/yatotp)
[![docs.rs](https://img.shields.io/docsrs/yatotp)](https://docs.rs/yatotp/latest/yatotp/)
{{badges}}
![license](https://img.shields.io/crates/l/yatotp)

# {{crate}}

{{readme}}

## Install
For now, it have only command-line interface.
```sh
$ cargo install yatotp --features=cli
```
## Usage
- Create database file (encryption password is needed).
  ```sh
  $ yatotp-cli -i [database file path] create
  ```
- Add database to entry interactively.
  ```sh
  $ yatotp-cli -i [database file path] add
  ```
  If you want to use base32-encoded secret key, such as gained from OpenAuth URI,
  add switch `-e` (`e` for Encoded) like this:
  ```sh
  $ yatotp-cli -i [database file path] add -e
  ```
- Show TOTP value of the entry.
  ```sh
  $ yatotp-cli -i [database file path] show [entry name]
  ```
- List entries in database.
  ```sh
  $ yatotp-cli -i [database file path] list
  ```
- Remove the entry from database.
  ```sh
  $ yatotp-cli -i [database file path] remove [entry name]
  ```
- Change database password to new one.
  ```sh
  $ yatotp-cli -i [database file path] newpass
  ```

Current version: {{version}}

License: {{license}}
