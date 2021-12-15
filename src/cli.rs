use crate::*;
use anyhow::{ensure, Context, Result};
use chrono::Utc;
use std::path::Path;

pub fn add<P: AsRef<Path>>(db_path: &P, base32_encode: bool) -> Result<()> {
    let db_path = db_path.as_ref();
    let (mut db, password) = match db_path.is_file() {
        true => {
            let password: String = dialoguer::Password::new()
                .with_prompt("Database password")
                .interact()
                .unwrap();
            let db = database::load_database(db_path, &password)
                .context(format!("Failed to load database from {:?}.", db_path))?;
            (db, password)
        }
        false => {
            println!("Database file does not exist.");
            if dialoguer::Confirm::new()
                .with_prompt("Create new one?")
                .default(true)
                .interact()
                .unwrap()
            {
                let password: String = dialoguer::Password::new()
                    .with_prompt("Please enter password for new database")
                    .with_confirmation("Confirm new password", "Passwords don't match.")
                    .interact()
                    .unwrap();
                let db = database::TotpDatabase::new();
                (db, password)
            } else {
                return Ok(());
            }
        }
    };
    let name: String = dialoguer::Input::new()
        .with_prompt("Name")
        .interact_text()
        .unwrap();
    ensure!(
        !db.contains_key(&name),
        "Entry named {} does already exist in the database",
        &name
    );
    let key = dialoguer::Password::new()
        .with_prompt("Secret key")
        .interact()
        .unwrap();
    let timestep: u64 = dialoguer::Input::new()
        .with_prompt("Time step")
        .default(30)
        .interact_text()
        .unwrap();
    let t0: u64 = dialoguer::Input::new()
        .with_prompt("T0")
        .default(0)
        .interact_text()
        .unwrap();
    let digit: u32 = dialoguer::Input::new()
        .with_prompt("Digits")
        .default(6)
        .validate_with(|input: &u32| -> Result<(), &str> {
            if *input <= 10 {
                Ok(())
            } else {
                Err("Please input betweeen 0 to 10.")
            }
        })
        .interact_text()
        .unwrap();
    let hashtypes = vec!["SHA-1", "SHA-256", "SHA-512"];
    let selection = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .items(&hashtypes)
        .default(0)
        .interact()
        .unwrap();
    let hashtype = match hashtypes[selection] {
        "SHA-1" => otp::HashType::Sha1,
        "SHA-256" => otp::HashType::Sha256,
        "SHA-512" => otp::HashType::Sha512,
        &_ => otp::HashType::Sha1,
    };
    let client = match base32_encode {
        true => otp::TotpClient::new_from_base32key(key, timestep, t0, digit, hashtype)?,
        false => otp::TotpClient::new(key.as_bytes().to_vec(), timestep, t0, digit, hashtype),
    };
    db.insert(name.clone(), client);
    database::save_database(&db, db_path, &password)
        .context(format!("Failed to save database to {:?}", db_path))?;
    println!("Success to add item: {}", name);
    Ok(())
}

pub fn remove<P: AsRef<Path>>(db_path: &P, name: &str) -> Result<()> {
    let db_path = db_path.as_ref();
    let password: String = dialoguer::Password::new()
        .with_prompt("Database password")
        .interact()
        .unwrap();
    let mut db = database::load_database(&db_path, &password)
        .context(format!("Failed to load database from {:?}.", db_path))?;
    db.remove(name);
    database::save_database(&db, &db_path, &password)
        .context(format!("Failed to save database to {:?}", db_path))?;
    println!("Success to remove item: {}", name);
    Ok(())
}

pub fn show<P: AsRef<Path>>(db_path: &P, name: &str) -> Result<()> {
    let db_path = db_path.as_ref();
    let password: String = dialoguer::Password::new()
        .with_prompt("Database password")
        .interact()
        .unwrap();
    let db = database::load_database(&db_path, &password)
        .context(format!("Failed to load database from {:?}.", db_path))?;
    let client = &db[name];
    println!(
        "{:0>digit$}",
        client.totp(&Utc::now()),
        digit = *client.digit() as usize
    );
    Ok(())
}

pub fn list<P: AsRef<Path>>(db_path: &P) -> Result<()> {
    let db_path = db_path.as_ref();
    let password: String = dialoguer::Password::new()
        .with_prompt("Database password")
        .interact()
        .unwrap();
    let db = database::load_database(&db_path, &password)
        .context(format!("Failed to load database from {:?}.", db_path))?;
    for name in db.keys() {
        println!("{}", name);
    }
    Ok(())
}
