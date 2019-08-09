use crate::HaveIBeenPwnedParser;
use clap::ArgMatches;
use log::{debug, error};
use std::process::exit;

pub fn run_subcommand(matches: &ArgMatches) {
    // get the path to the password file
    let password_hash_path = match matches.value_of("password-hashes") {
        Some(path) => path,
        None => {
            error!("It seems that the path to the file for the password hashes was not provided, please see the help for usage instructions.");
            exit(-1);
        }
    };
    debug!("Got {} as a password hash file", password_hash_path);

    // get the output folder where the optimized results should be stored
    let output_folder = match matches.value_of("output-folder") {
        Some(path) => path,
        None => {
            error!("It seems that the path where the optimized hashes should be stored was not provided, please see the help for usage instructions.");
            exit(-1);
        }
    };
    debug!("Got {} as the output folder", output_folder);

    // get an instance of the password parser
    let _parser = match HaveIBeenPwnedParser::from_file(password_hash_path) {
        Ok(parser) => parser,
        Err(error) => {
            error!(
                "Could not get an instance of the parser. The error was: {}",
                error
            );
            exit(-2);
        }
    };
}
