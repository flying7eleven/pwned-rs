use crate::PasswordHashEntry;
use clap::ArgMatches;
use log::{error, info};
use rpassword::read_password_from_tty;
use std::path::Path;
use std::process::exit;

struct DivideAndConquerLookup;

impl DivideAndConquerLookup {
    pub fn from_file(_password_file: &Path) -> Option<DivideAndConquerLookup> {
        None
    }

    pub fn get_password_count(&self, _password: &PasswordHashEntry) -> Option<u64> {
        None
    }
}

pub fn run_subcommand(matches: &ArgMatches) {
    // get the path to the password database
    let password_hash_file_path = match matches.value_of("password-database") {
        Some(path) => Path::new(path),
        None => {
            error!("It seems that the path to the file for the password hashes was not provided, please see the help for usage instructions.");
            exit(-1);
        }
    };

    // try to read the password from the user
    let read_password =
        match read_password_from_tty(Some("Enter the password you are looking for: ")) {
            Ok(password) => PasswordHashEntry::from_password(password.as_str()),
            Err(_) => {
                error!("Could not read the password from the user.");
                return;
            }
        };

    // get the lookup instance
    let divide_and_conquer_lookup = match DivideAndConquerLookup::from_file(password_hash_file_path)
    {
        Some(lookup) => lookup,
        None => {
            error!("Could not get instace of the divide and conquer lookup algorithm.");
            exit(-2);
        }
    };

    // try to lookup the password
    match divide_and_conquer_lookup.get_password_count(&read_password) {
        Some(count) => info!(
            "The password was found {} in password breaches. Please change the password!",
            count
        ),
        None => {
            info!("Perfect! Could not find the password in any of the available breaches. Go on!")
        }
    }
}
