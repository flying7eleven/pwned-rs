use crate::PasswordHashEntry;
use clap::ArgMatches;
use log::{error, info};
use rpassword::read_password_from_tty;
use std::fs::{metadata, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::process::exit;
use std::str::FromStr;

struct DivideAndConquerLookup {
    file_handle: BufReader<File>,
    file_size: u64,
    head_position: u64,
    tail_position: u64,
}

impl DivideAndConquerLookup {
    pub fn from_file(password_file: &Path) -> Option<DivideAndConquerLookup> {
        let file_size = match metadata(password_file) {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                error!(
                    "Could not determine the size of the file. The error was: {}",
                    error.to_string()
                );
                return None;
            }
        };

        let file_handle = match OpenOptions::new()
            .append(false)
            .write(false)
            .read(true)
            .open(password_file)
        {
            Ok(handle) => BufReader::new(handle),
            Err(_) => {
                error!(
                    "Could not open {} for reading passwords from it.",
                    password_file.to_str().unwrap()
                );
                return None;
            }
        };
        Some(DivideAndConquerLookup {
            file_handle,
            file_size,
            head_position: 0,
            tail_position: 0,
        })
    }

    pub fn get_password_count(&mut self, seeked_password_hash: &PasswordHashEntry) -> Option<u64> {
        if self.tail_position == 0 {
            self.head_position = 0;
            self.tail_position = self.file_size;
        }
        let mid = (self.tail_position - self.head_position) / 2 + self.head_position;

        if self.file_handle.seek(SeekFrom::Start(mid)).is_err() {
            error!("Could not seek to byte: {}", mid);
            return None;
        }

        let mut line_read_buffer = String::new();

        // first read seeks to next new line
        if self.file_handle.read_line(&mut line_read_buffer).is_err() {
            error!("Could not seek to the next line of the file");
            return None;
        }
        line_read_buffer.clear();

        // second read does the actual read of the current data set
        if self.file_handle.read_line(&mut line_read_buffer).is_err() {
            error!("Could not read a full line for parsing a password entry");
            return None;
        }

        // try to parse the current line and extract the password hash
        let password_hash_at_current_line =
            match PasswordHashEntry::from_str(line_read_buffer.replace("\r\n", "").as_str()) {
                Ok(entry) => entry,
                Err(error) => {
                    error!(
                        "Could not extract the password hash from the read line. The error was: {}",
                        error.to_string()
                    );
                    return None;
                }
            };

        // if the last read hash is the searched one, we are done here
        if password_hash_at_current_line == *seeked_password_hash {
            return Some(password_hash_at_current_line.occurrences);
        }

        // determine in which block we should continue our search
        if password_hash_at_current_line < *seeked_password_hash {
            self.head_position = mid;
        } else {
            self.tail_position = mid;
        }

        // 40 Bytes sha1 + 1 Byte seperator + 1 Byte single digit occurrence
        if self.tail_position - self.head_position < 42 {
            return None;
        }

        // continue with the divide and conquer method
        self.get_password_count(seeked_password_hash)
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
    let mut divide_and_conquer_lookup =
        match DivideAndConquerLookup::from_file(password_hash_file_path) {
            Some(lookup) => lookup,
            None => {
                error!("Could not get instace of the divide and conquer lookup algorithm.");
                exit(-2);
            }
        };

    // try to lookup the password
    match divide_and_conquer_lookup.get_password_count(&read_password) {
        Some(count) => info!(
            "Choose a different password - the one you entered appears {} times in a list of hacked password!",
            count
        ),
        None => {
            info!("Perfect! Could not find the password in any of the available breaches. Go on!")
        }
    }
}
