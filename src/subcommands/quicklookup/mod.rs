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
    top: u64,
    end: u64,
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
            top: 0,
            end: 0,
        })
    }

    pub fn get_password_count(&mut self, seeked_password_hash: &PasswordHashEntry) -> Option<u64> {
        if self.end == 0 {
            self.top = 0;
            self.end = self.file_size;
        }
        let mid = (self.end - self.top) / 2 + self.top;

        if self.file_handle.seek(SeekFrom::Start(mid)).is_err() {
            error!("Could not seek to byte: {}", mid);
            return None;
        }

        let mut line_read_buffer = String::new();

        // First read seeks to next new line
        let _ = self.file_handle.read_line(&mut line_read_buffer);
        line_read_buffer.clear();

        let _ = self.file_handle.read_line(&mut line_read_buffer);

        let password_hash_at_current_line =
            match PasswordHashEntry::from_str(line_read_buffer.replace("\r\n", "").as_str()) {
                Ok(entry) => entry,
                Err(error) => {
                    error!("{}", error.to_string());
                    return None;
                }
            };

        if password_hash_at_current_line == *seeked_password_hash {
            return Some(password_hash_at_current_line.occurrences);
        }

        if password_hash_at_current_line < *seeked_password_hash {
            self.top = mid;
        } else {
            self.end = mid;
        }

        // 40 Bytes sha1 + 1 Byte seperator + 1 Byte single digit occurrence
        if self.end - self.top < 42 {
            return None;
        }
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
            "The password was found {} in password breaches. Please change the password!",
            count
        ),
        None => {
            info!("Perfect! Could not find the password in any of the available breaches. Go on!")
        }
    }
}
