use crate::HaveIBeenPwnedParser;
use clap::ArgMatches;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info};
use std::cmp::min;
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
    let mut parser = match HaveIBeenPwnedParser::from_file(password_hash_path) {
        Ok(parser) => parser,
        Err(error) => {
            error!(
                "Could not get an instance of the parser. The error was: {}",
                error
            );
            exit(-2);
        }
    };

    // try to get the size of the whole password file
    let file_size = match parser.get_file_size() {
        Some(size) => size,
        None => {
            error!("Could not determine the size of the original password file.");
            exit(-3);
        }
    };

    // get an instance from  the progress bar to indicate the optimization progress
    let progress_bar = ProgressBar::new(file_size);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .progress_chars("#>-"));

    // start processing (and optimizing) the information stored in the password hash file
    let mut processed_bytes = 0;
    let mut last_prefix = "".to_string();
    let mut number_of_subfiles = 0;
    while processed_bytes < file_size {
        // get the entry or exit the loop if there is no next entry
        let password_hash_entry = match parser.next() {
            Some(entry) => entry,
            None => break,
        };

        //
        let current_prefix = password_hash_entry.get_prefix();
        if !last_prefix.eq_ignore_ascii_case(current_prefix.as_str()) {
            number_of_subfiles += 1;
            last_prefix = current_prefix;
        }

        // set the new current position for the progress bar
        let new = min(
            processed_bytes + password_hash_entry.get_size_in_bytes(),
            file_size,
        );
        processed_bytes = new;
        progress_bar.set_position(new);
    }
    progress_bar.finish_with_message("optimized");

    info!(
        "Optimized password database and splitted it into {} files",
        number_of_subfiles
    );
}
