use crate::haveibeenpwned::DatabaseReader;
use crate::PasswordHashEntry;
use clap::ArgMatches;
use log::{debug, error};
use rpassword::read_password_from_tty;
use std::path::Path;

pub fn run_subcommand(_matches: &ArgMatches) {
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
    let file_path = Path::new("").join(format!("{}.txt", password_entry.get_prefix()));
    let _database_reader = match DatabaseReader::from_file(&file_path) {
        Ok(parser) => parser,
        Err(error) => {
            error!("Could not open the database. The error was: {}", error);
            return;
        }
    };
}
