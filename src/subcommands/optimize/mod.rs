use crate::haveibeenpwned::DatabaseIterator;
use clap::ArgMatches;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info};
use std::cmp::min;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
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
        Some(path) => {
            if !Path::new(path).exists() {
                error!(
                    "The supplied path ('{}') does not exists. Please select an existing folder.",
                    path
                );
                exit(-1);
            }
            path
        }
        None => {
            error!("It seems that the path where the optimized hashes should be stored was not provided, please see the help for usage instructions.");
            exit(-2);
        }
    };
    debug!("Got {} as the output folder", output_folder);

    // get an instance of the password parser
    let mut parser = match DatabaseIterator::from_file(password_hash_path) {
        Ok(parser) => parser,
        Err(error) => {
            error!(
                "Could not get an instance of the parser. The error was: {}",
                error
            );
            exit(-3);
        }
    };

    // try to get the size of the whole password file
    let file_size = match parser.get_file_size() {
        Some(size) => size,
        None => {
            error!("Could not determine the size of the original password file.");
            exit(-4);
        }
    };

    // get an instance from  the progress bar to indicate the optimization progress
    let progress_bar = ProgressBar::new(file_size);
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta_precise})")
        .progress_chars("#>-"));
    progress_bar.set_draw_delta(1024 * 1024 * 8);

    // start processing (and optimizing) the information stored in the password hash file
    let mut processed_bytes = 0;
    let mut last_prefix = "".to_string();
    let mut number_of_subfiles = 0;
    let mut output_file_name = Path::new(output_folder).join("tmp_file.txt");
    let mut current_output_file: File = OpenOptions::new()
        .write(true)
        .append(false)
        .read(false)
        .create(true)
        .open(output_file_name)
        .unwrap();
    while processed_bytes < file_size {
        // get the entry or exit the loop if there is no next entry
        let password_hash_entry = match parser.next() {
            Some(entry) => entry,
            None => break,
        };

        // if the hash prefix changed, we have to change the output file into we which are writing
        let current_prefix = password_hash_entry.get_prefix();
        if !last_prefix.eq_ignore_ascii_case(current_prefix.as_str()) {
            output_file_name = Path::new(output_folder).join(format!("{}.txt", current_prefix));
            current_output_file = match OpenOptions::new()
                .write(true)
                .append(false)
                .read(false)
                .create(true)
                .open(output_file_name)
            {
                Ok(file_handle) => file_handle,
                Err(_) => {
                    error!("Could not open the output file for the optimized data set.");
                    exit(-5);
                }
            };
            number_of_subfiles += 1;
            last_prefix = current_prefix;
        }

        // write the current entry to the file
        let _ = match current_output_file.write(password_hash_entry.get_line_to_write().as_bytes())
        {
            Ok(count) => count,
            Err(_) => {
                error!("Could not write a password entry into the new file.");
                exit(-6);
            }
        };

        // set the new current position for the progress bar
        let new = min(
            processed_bytes + password_hash_entry.get_size_in_bytes(),
            file_size,
        );
        processed_bytes = new;
        progress_bar.set_position(processed_bytes);
    }
    progress_bar.finish_with_message("optimized");

    info!(
        "Optimized password database and splitted it into {} files",
        number_of_subfiles
    );
}
