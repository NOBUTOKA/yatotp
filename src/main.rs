use chrono::prelude::*;
use std::collections::HashMap;
use yatotp::otp::{HashType, TotpClient};

fn main() {
    let mut totp = HashMap::new();
    totp.insert(
        "test",
        TotpClient::new_from_base32key("JBSWY3DPEHPK3PXP".to_string(), 30, 0, 6, HashType::Sha1)
            .unwrap(),
    );
    println!("{}", totp["test"].totp(&Utc::now()));
}
