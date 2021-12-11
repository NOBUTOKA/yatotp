extern crate yatotp;

fn main() {
    let k = "12345678901234567890";
    let c = 0;
    println!("{}", yatotp::otp::hotp(&c, &k, &6));
}
