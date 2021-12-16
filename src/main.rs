// yatotp: Yet Another Time-Based OTP client.
// Copyright 2021, Nobuto Kaitoh
//
// This file is part of yatotp.
//
// Yatotp is free software: you can redistribute it and/or
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Yatotp is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with yatotp.  If not, see <https://www.gnu.org/licenses/>.

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
    /// Create new database,
    Create,
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
    /// Change database password to new one.
    Newpass,
}

fn main() -> Result<()> {
    let args = Args::from_args();
    match args.command {
        Command::Create => cli::create(&args.database),
        Command::Add { base32_encode } => cli::add(&args.database, base32_encode),
        Command::Remove { name } => cli::remove(&args.database, &name),
        Command::Show { name } => cli::show(&args.database, &name),
        Command::List => cli::list(&args.database),
        Command::Newpass => cli::change_password(&args.database),
    }?;
    Ok(())
}
