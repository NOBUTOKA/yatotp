[![Crates.io](https://img.shields.io/crates/v/yatotp)](https://crates.io/crates/yatotp)
[![docs.rs](https://img.shields.io/docsrs/yatotp)](https://docs.rs/yatotp/latest/yatotp/)
{{badges}}
![license](https://img.shields.io/crates/l/yatotp)

# {{crate}}

{{readme}}

## Usage
For now, it have only command-line interface.
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

Current version: {{version}}

License: {{license}}
