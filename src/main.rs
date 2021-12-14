extern crate yatotp;

use anyhow::Result;
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
        #[structopt(short = "e", long, help = "Treat key as base32 encoded.")]
        base32_encode: bool,
    },
    /// Remove specified entry from database.
    Remove {
        #[structopt(help = "Name of entry.")]
        name: String,
    },
    /// Show TOTP value of specified entry.
    Show {
        #[structopt(help = "Name of entry.")]
        name: String,
    },
    /// Print list of TOTP entries.
    List,
}

fn main() -> Result<()> {
    let args = Args::from_args();
    match args.command {
        Command::Add { base32_encode } => cli::add(&args.database, base32_encode)?,
        Command::Remove { name } => cli::remove(&args.database, &name)?,
        Command::Show { name } => cli::show(&args.database, &name)?,
        Command::List => cli::list(&args.database)?,
    }
    Ok(())
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
