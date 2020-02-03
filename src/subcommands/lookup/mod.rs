use crate::haveibeenpwned::DatabaseReader;
use crate::PasswordHashEntry;
use clap::ArgMatches;
use log::{debug, error, info};
use rpassword::read_password_from_tty;
use std::path::Path;
use std::process::exit;

pub fn run_subcommand(matches: &ArgMatches) {
    // get the path to the optimized password database
    let password_hash_folder = match matches.value_of("optimized-db-folder") {
        Some(path) => path,
        None => {
            error!("It seems that the path to the folder for the optimized password hash files was not provided, please see the help for usage instructions.");
            exit(-1);
        }
    };

    // try to read the password from the user
    let read_password =
        match read_password_from_tty(Some("Enter the password you are looking for: ")) {
            Ok(password) => password,
            Err(_) => {
                error!("Could not read the password from the user.");
                return;
            }
        };

    // get the SHA-1 hashed password
    let password_entry = PasswordHashEntry::from_password(&read_password);
    debug!(
        "Looking up password in {}.txt...",
        password_entry.get_prefix()
    );

    // try to get the reader for the database
    let file_path =
        Path::new(password_hash_folder).join(format!("{}.txt", password_entry.get_prefix()));
    let read_database = match DatabaseReader::from_file(&file_path) {
        Ok(parser) => parser,
        Err(error) => {
            error!("Could not open the database. The error was: {}", error);
            return;
        }
    };

    //
    match read_database.get_password_count(password_entry.get_hash()) {
        Some(count) => info!(
            "The password was found {} times in password breaches. Please change the password!",
            count
        ),
        None => {
            info!("Perfect! Could not find the password in any of the available breaches. Go on!")
        }
    }
}
