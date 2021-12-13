use crate::*;

pub fn add(input_path: &std::path::PathBuf, base32_encode: bool) {
    let mut db: database::TotpDatabase;
    if !input_path.is_file() {
        println!("Database file does not exist.");
        if dialoguer::Confirm::new()
            .with_prompt("Create new one?")
            .default(true)
            .interact()
            .unwrap()
        {
            db = database::TotpDatabase::new();
        } else {
            std::process::exit(0);
        }
    } else {
        db = database::load_database(input_path).unwrap();
    }
    let name: String = dialoguer::Input::new()
        .with_prompt("Name")
        .interact_text()
        .unwrap();
    if db.contains_key(&name) {
        panic!(
            "Totp of given name is already exist in the database: {}",
            name
        );
    }
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
        true => otp::TotpClient::new_from_base32key(key, timestep, t0, digit, hashtype).unwrap(),
        false => otp::TotpClient::new(key.as_bytes().to_vec(), timestep, t0, digit, hashtype),
    };
    db.insert(name, client);
    database::save_database(&db, input_path).unwrap();
}
