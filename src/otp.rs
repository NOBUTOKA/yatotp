use hmacsha1::hmac_sha1;
use chrono::prelude::*;

pub struct HotpClient {
    key: String,
    digit: u32
}

impl HotpClient{
    pub fn new(key: String, digit: u32) -> HotpClient{
	HotpClient{key, digit}
    }

    pub fn hotp(&self, counter: &u64) -> u32{
	let key = self.key.as_bytes();
	let counter = counter.to_be_bytes();
	let hs = hmac_sha1(&key, &counter);
	let bin_code = u32::from_be_bytes(dynamic_truncate(&hs));
	bin_code % 10u32.pow(self.digit)
    }
}

pub struct TotpClient {
    hotp: HotpClient,
    timestep: u64,
    t0: u64,
}

impl TotpClient {
    pub fn new(key: String, timestep: u64, t0: u64, digit: u32) -> TotpClient{
	let hotp = HotpClient::new(key, digit);
	TotpClient{hotp, timestep, t0}
    }
    
    pub fn totp(&self, datetime: &DateTime<Utc>) -> u32 {
        let t = ((datetime.timestamp() as u64) - self.t0) / self.timestep;
        self.hotp.hotp(&t)
    }
}

fn dynamic_truncate(hs: &[u8; 20]) -> [u8; 4] {
    let offset = (hs[19] & 0xf) as usize;
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
	let hotp = HotpClient::new("12345678901234567890".to_string(), 6);
        let result: [u32; 10] = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (c, r) in result.iter().enumerate() {
            assert_eq!(hotp.hotp(&(c as u64)), *r);
        }
    }

    #[test]
    fn rfc6238_example_sha1() {
	let totp = TotpClient::new("12345678901234567890".to_string(), 30, 0, 8);
	
	let datetime_format = "%Y-%m-%d %H:%M:%S";
	let datetime = Utc.datetime_from_str("1970-01-01 00:00:59", datetime_format).unwrap();
	assert_eq!(totp.totp(&datetime), 94287082);
	let datetime = Utc.datetime_from_str("2005-03-18 01:58:29", datetime_format).unwrap();
	assert_eq!(totp.totp(&datetime), 07081804);
	let datetime = Utc.datetime_from_str("2009-02-13 23:31:30", datetime_format).unwrap();
	assert_eq!(totp.totp(&datetime), 89005924);
	let datetime = Utc.datetime_from_str("2033-05-18 03:33:20", datetime_format).unwrap();
	assert_eq!(totp.totp(&datetime), 69279037);
	let datetime = Utc.datetime_from_str("2603-10-11 11:33:20", datetime_format).unwrap();
	assert_eq!(totp.totp(&datetime), 65353130);
    }
}
