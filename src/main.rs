use yatotp::otp::{TotpClient, HashType};
use chrono::prelude::*;
use std::collections::HashMap;

fn main() {
    let mut totp = HashMap::new();
    totp.insert(
        "test",
	// Base32 Encoded key is JBSWY3DPEB3W64TMMQQQ====
        TotpClient::new("Hello world!".to_string(), 30, 0, 6, HashType::Sha1)
    );
    println!("{}", totp["test"].totp(&Utc::now()));
}
