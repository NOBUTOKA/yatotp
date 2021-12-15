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

pub type TotpDatabase = std::collections::HashMap<String, otp::TotpClient>;

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedDatabase {
    nonce: String,
    salt: String,
    encrypted_data: String,
}

impl EncryptedDatabase {
    fn new(nonce: &[u8], salt: &[u8], encrypted_data: &[u8]) -> EncryptedDatabase {
        let nonce = BASE64.encode(nonce);
        let salt = BASE64.encode(salt);
        let encrypted_data = BASE64.encode(encrypted_data);
        EncryptedDatabase {
            nonce,
            salt,
            encrypted_data,
        }
    }
}

pub fn save_database(database: &TotpDatabase, path: &Path, password: &str) -> Result<()> {
    let salt = SaltString::generate(&mut OsRng);
    let mut argon2param = ParamsBuilder::new();
    argon2param.output_len(CHACHA20_KEY_LEN).unwrap();
    let key = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2param.params().unwrap(),
    )
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
    let enc_db = EncryptedDatabase::new(nonce.as_slice(), salt.as_bytes(), &encrypted);
    f.write(serde_json::to_string(&enc_db)?.as_bytes())?;
    Ok(())
}

pub fn load_database(path: &Path, password: &str) -> Result<TotpDatabase> {
    let mut f = BufReader::new(std::fs::File::open(path)?);
    let mut enc_db = String::new();
    f.read_to_string(&mut enc_db)?;
    let enc_db = serde_json::from_str::<EncryptedDatabase>(&enc_db)?;
    let nonce = BASE64.decode(enc_db.nonce.as_bytes())?;
    let nonce = Nonce::from_slice(&nonce);
    let salt =
        SaltString::new(&String::from_utf8(BASE64.decode(enc_db.salt.as_bytes())?)?).unwrap();
    let encrypted = BASE64.decode(enc_db.encrypted_data.as_bytes())?;
    let mut argon2param = ParamsBuilder::new();
    argon2param.output_len(CHACHA20_KEY_LEN).unwrap();
    let key = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        argon2param.params().unwrap(),
    )
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
            otp::TotpClient::new_from_base32key(
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
