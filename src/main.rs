extern crate yatotp;

use structopt::StructOpt;
use yatotp::*;

#[derive(StructOpt)]
#[structopt(about = "Yet Another TOTP Client.")]
struct Args {
    #[structopt(subcommand)]
    command: Command,
    #[structopt(short = "i", long = "database", parse(from_os_str))]
    database: std::path::PathBuf,
}

#[derive(StructOpt)]
enum Command {
    /// Add new entry to database.
    Add {
        #[structopt(short = "e", long)]
        base32_encode: bool,
    },
    /// Remove specified entry from database.
    Remove { name: String },
    /// Show TOTP value of specified entry.
    Show { name: String },
}

fn main() {
    let args = Args::from_args();
    match args.command {
        Command::Add { base32_encode } => cli::add(&args.database, base32_encode),
        _ => (),
    }
    // totp.insert(
    //     "test".to_string(),
    //     otp::TotpClient::new_from_base32key(
    //         "JBSWY3DPEHPK3PXP".to_string(),
    //         30,
    //         0,
    //         6,
    //         otp::HashType::Sha1,
    //     )
    //     .unwrap(),
    // );
    // println!("{}", totp["test"].totp(&Utc::now()));
    // let save_path = path::Path::new("./clients.json");
    // database::save_database(&totp, &save_path).unwrap();
}
