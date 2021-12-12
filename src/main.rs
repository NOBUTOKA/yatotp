use chrono::prelude::*;
use yatotp::*;
use std::path;

fn main() {
    let mut totp = database::TotpDatabase::new();
    totp.insert(
        "test".to_string(),
        otp::TotpClient::new_from_base32key(
            "JBSWY3DPEHPK3PXP".to_string(),
            30,
            0,
            6,
            otp::HashType::Sha1,
        )
        .unwrap(),
    );
    println!("{}", totp["test"].totp(&Utc::now()));
    let save_path = path::Path::new("./clients.json");
    database::save_database(&totp, &save_path).unwrap();
}
