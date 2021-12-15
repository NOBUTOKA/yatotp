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


//! Save and load TOTP clients database file.
//!
//! Database file is encrypted with Argon2id and ChaCha20Poly1305.
//! Salt for Argon2id and nonce for ChaCha20 is also attatched to database file.

use crate::*;
use anyhow::{bail, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Algorithm, Argon2, ParamsBuilder, Version,
};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::Utc;
use data_encoding::BASE64;
use rand::distributions::Standard;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

const CHACHA20_NONCE_LEN: usize = 12;
const CHACHA20_KEY_LEN: usize = 32;

/// The collection of TOTP clients.
pub type TotpDatabase = std::collections::HashMap<String, otp::TotpClient>;

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedDatabase {
    nonce: String,
    salt: String,
    encrypted_data: String,
}

impl EncryptedDatabase {
    fn new(nonce: &[u8], salt: String, encrypted_data: &[u8]) -> EncryptedDatabase {
        let nonce = BASE64.encode(nonce);
        let encrypted_data = BASE64.encode(encrypted_data);
        EncryptedDatabase {
            nonce,
            salt,
            encrypted_data,
        }
    }
}

/// Encrypt and Save database to file.
///
/// Given password is hashed with random generated salt by Argon2id to 32 byte,
/// then passed to ChaCha20Poly1305 with nonce.
/// The 12 byte nonce is concatnation of Unix millisecond time (8 byte) and random 4 bytes,
/// because nonce must be Number used ONCE otherwise reused (or conflicted) nonce make attack easier.
///
/// Then, JSON-serialized TotpDatabase is encrypted with this ChaCha20,
/// and then base64-encoded nonce, salt, and encrypted database is saved in JSON file.
pub fn save_database<P: AsRef<Path>>(
    database: &TotpDatabase,
    path: &P,
    password: &str,
) -> Result<()> {
    let path = path.as_ref();
    let salt = SaltString::generate(&mut OsRng);
    let mut argon2param = ParamsBuilder::new();
    argon2param.output_len(CHACHA20_KEY_LEN).unwrap();
    let hasher = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2param.params().unwrap(),
    );
    let key = hasher
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .hash
        .unwrap();
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(key.as_bytes()));
    let mut nonce = Utc::now().timestamp_millis().to_be_bytes().to_vec();
    nonce.append(
        &mut (thread_rng()
            .sample_iter(Standard)
            .take(CHACHA20_NONCE_LEN - nonce.len())
            .collect()),
    );
    let nonce = Nonce::from_slice(&nonce);
    let serialized = serde_json::to_string(database)?;
    let encrypted = match cipher.encrypt(&nonce, serialized.as_bytes()) {
        Ok(c) => c,
        Err(e) => bail!("Encryption failed: {}", e),
    };
    let mut f = BufWriter::new(std::fs::File::create(path)?);
    let enc_db = EncryptedDatabase::new(nonce.as_slice(), salt.as_str().to_string(), &encrypted);
    f.write_all(serde_json::to_string(&enc_db)?.as_bytes())?;
    Ok(())
}

/// Load and Decrypt database from file.
///
/// Nonce and salt used to encrypt database when [save_database] is gained from database file.
pub fn load_database<P: AsRef<Path>>(path: &P, password: &str) -> Result<TotpDatabase> {
    let path = path.as_ref();
    let mut f = BufReader::new(std::fs::File::open(path)?);
    let mut enc_db = String::new();
    f.read_to_string(&mut enc_db)?;
    let enc_db = serde_json::from_str::<EncryptedDatabase>(&enc_db)?;
    let nonce = BASE64.decode(enc_db.nonce.as_bytes())?;
    let nonce = Nonce::from_slice(&nonce);
    let salt = SaltString::new(&enc_db.salt).unwrap();
    let encrypted = BASE64.decode(enc_db.encrypted_data.as_bytes())?;
    let mut argon2param = ParamsBuilder::new();
    argon2param.output_len(CHACHA20_KEY_LEN).unwrap();
    let hasher = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2param.params().unwrap(),
    );
    let key = hasher
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .hash
        .unwrap();
    let cipher = ChaCha20Poly1305::new(&Key::from_slice(key.as_bytes()));
    let serialized = match cipher.decrypt(nonce, encrypted.as_slice()) {
        Ok(c) => c,
        Err(e) => bail!("Decryption failed: {}", e),
    };
    let serialized = String::from_utf8(serialized)?;
    Ok(serde_json::from_str::<TotpDatabase>(&serialized)?)
}

#[cfg(test)]
mod test {

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn save_and_load() {
        let mut database = TotpDatabase::new();
        database.insert(
            "test1".to_string(),
            otp::TotpClient::new(
                "12345678901234567890".as_bytes().to_vec(),
                30,
                0,
                6,
                otp::HashType::Sha1,
            ),
        );
        database.insert(
            "test2".to_string(),
            otp::TotpClient::from_base32key(
                "JBSWY3DPEHPK3PXP".to_string(),
                30,
                0,
                6,
                otp::HashType::Sha256,
            )
            .unwrap(),
        );
        let save_dir = tempdir().unwrap();
        let save_path = save_dir.path().join("test_database.json");
        save_database(&database, &save_path, "Test key").unwrap();
        let loaded_database = load_database(&save_path, "Test key").unwrap();
        assert_eq!(loaded_database, database);
        save_dir.close().unwrap();
    }
}
