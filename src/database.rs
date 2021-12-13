use super::otp;
use anyhow::Result;
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path;

pub type TotpDatabase = HashMap<String, otp::TotpClient>;

pub fn save_database(database: &TotpDatabase, path: &path::Path) -> Result<()> {
    let serialized = serde_json::to_string(database)?;
    let mut f = BufWriter::new(fs::File::create(path)?);
    f.write(&serialized.into_bytes())?;
    Ok(())
}

pub fn load_database(path: &path::Path) -> Result<TotpDatabase> {
    let mut f = BufReader::new(fs::File::open(path)?);
    let mut serialized = String::new();
    f.read_to_string(&mut serialized)?;
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
        save_database(&database, &save_path).unwrap();
        let loaded_database = load_database(&save_path).unwrap();
        assert_eq!(loaded_database, database);
        save_dir.close().unwrap();
    }
}
