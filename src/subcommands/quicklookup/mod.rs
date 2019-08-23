use clap::ArgMatches;
use std::process::exit;
use rpassword::read_password_from_tty;
use log::error;

pub fn run_subcommand(matches: &ArgMatches) {
    //
    let _password_hash_folder = match matches.value_of("password-database") {
        Some(path) => path,
        None => {
            error!("It seems that the path to the file for the password hashes was not provided, please see the help for usage instructions.");
            exit(-1);
        }
    };

    // try to read the password from the user
    let _read_password =
        match read_password_from_tty(Some("Enter the password you are looking for: ")) {
            Ok(password) => password,
            Err(_) => {
                error!("Could not read the password from the user.");
                return;
            }
        };
}
