use anyhow::{Context, Result};
use chrono::prelude::*;
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use serde;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub enum HashType {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct HotpClient {
    key: Vec<u8>,
    digit: u32,
    hashtype: HashType,
}

impl HotpClient {
    fn new(key: Vec<u8>, digit: u32, hashtype: HashType) -> HotpClient {
        HotpClient {
            key,
            digit,
            hashtype,
        }
    }

    fn hotp(&self, counter: &u64) -> u32 {
        let hs = match self.hashtype {
            HashType::Sha1 => self.hmac_sha1(counter),
            HashType::Sha256 => self.hmac_sha256(counter),
            HashType::Sha512 => self.hmac_sha512(counter),
        };
        let bin_code = u32::from_be_bytes(dynamic_truncate(&hs));
        bin_code % 10u32.pow(self.digit)
    }

    fn hmac_sha1(&self, counter: &u64) -> Vec<u8> {
        let mut hasher =
            Hmac::<Sha1>::new_from_slice(&self.key).expect("HMAC can take key of any size");
        hasher.update(&counter.to_be_bytes());
        hasher.finalize().into_bytes().to_vec()
    }

    fn hmac_sha256(&self, counter: &u64) -> Vec<u8> {
        let mut hasher =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC can take key of any size");
        hasher.update(&counter.to_be_bytes());
        hasher.finalize().into_bytes().to_vec()
    }

    fn hmac_sha512(&self, counter: &u64) -> Vec<u8> {
        let mut hasher =
            Hmac::<Sha512>::new_from_slice(&self.key).expect("HMAC can take key of any size");
        hasher.update(&counter.to_be_bytes());
        hasher.finalize().into_bytes().to_vec()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub struct TotpClient {
    hotp: HotpClient,
    timestep: u64,
    t0: u64,
}

impl TotpClient {
    pub fn new(key: Vec<u8>, timestep: u64, t0: u64, digit: u32, hashtype: HashType) -> TotpClient {
        let hotp = HotpClient::new(key, digit, hashtype);
        TotpClient { hotp, timestep, t0 }
    }

    pub fn new_from_base32key(
        key: String,
        timestep: u64,
        t0: u64,
        digit: u32,
        hashtype: HashType,
    ) -> Result<TotpClient> {
        let key = BASE32
            .decode(key.as_bytes())
            .context("Failed to decode base32-encoded key.")?;
        let hotp = HotpClient::new(key, digit, hashtype);
        Ok(TotpClient { hotp, timestep, t0 })
    }

    pub fn totp(&self, datetime: &DateTime<Utc>) -> u32 {
        let t = ((datetime.timestamp() as u64) - self.t0) / self.timestep;
        self.hotp.hotp(&t)
    }
}

fn dynamic_truncate(hs: &Vec<u8>) -> [u8; 4] {
    let offset = (hs.last().unwrap() & 0xf) as usize;
    let bin_code = [
        hs[offset] & 0x7f,
        hs[offset + 1],
        hs[offset + 2],
        hs[offset + 3],
    ];
    bin_code
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rfc4226_example() {
        let hotp = HotpClient::new(
            "12345678901234567890".as_bytes().to_vec(),
            6,
            HashType::Sha1,
        );
        let result: [u32; 10] = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (c, r) in result.iter().enumerate() {
            assert_eq!(hotp.hotp(&(c as u64)), *r);
        }
    }

    #[test]
    fn rfc6238_example_sha1() {
        let totp = TotpClient::new(
            "12345678901234567890".as_bytes().to_vec(),
            30,
            0,
            8,
            HashType::Sha1,
        );

        let datetime_format = "%Y-%m-%d %H:%M:%S";
        let datetime = Utc
            .datetime_from_str("1970-01-01 00:00:59", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 94287082);
        let datetime = Utc
            .datetime_from_str("2005-03-18 01:58:29", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 07081804);
        let datetime = Utc
            .datetime_from_str("2009-02-13 23:31:30", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 89005924);
        let datetime = Utc
            .datetime_from_str("2033-05-18 03:33:20", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 69279037);
        let datetime = Utc
            .datetime_from_str("2603-10-11 11:33:20", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 65353130);
    }

    #[test]
    fn rfc6238_example_sha256() {
        let totp = TotpClient::new(
            "12345678901234567890123456789012".as_bytes().to_vec(),
            30,
            0,
            8,
            HashType::Sha256,
        );

        let datetime_format = "%Y-%m-%d %H:%M:%S";
        let datetime = Utc
            .datetime_from_str("1970-01-01 00:00:59", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 46119246);
        let datetime = Utc
            .datetime_from_str("2005-03-18 01:58:29", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 68084774);
        let datetime = Utc
            .datetime_from_str("2009-02-13 23:31:30", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 91819424);
        let datetime = Utc
            .datetime_from_str("2033-05-18 03:33:20", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 90698825);
        let datetime = Utc
            .datetime_from_str("2603-10-11 11:33:20", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 77737706);
    }

    #[test]
    fn rfc6238_example_sha512() {
        let totp = TotpClient::new(
            "1234567890123456789012345678901234567890123456789012345678901234"
                .as_bytes()
                .to_vec(),
            30,
            0,
            8,
            HashType::Sha512,
        );

        let datetime_format = "%Y-%m-%d %H:%M:%S";
        let datetime = Utc
            .datetime_from_str("1970-01-01 00:00:59", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 90693936);
        let datetime = Utc
            .datetime_from_str("2005-03-18 01:58:29", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 25091201);
        let datetime = Utc
            .datetime_from_str("2009-02-13 23:31:30", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 93441116);
        let datetime = Utc
            .datetime_from_str("2033-05-18 03:33:20", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 38618901);
        let datetime = Utc
            .datetime_from_str("2603-10-11 11:33:20", datetime_format)
            .unwrap();
        assert_eq!(totp.totp(&datetime), 47863826);
    }
}
