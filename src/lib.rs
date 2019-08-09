pub mod subcommands;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use log::debug;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Error};
use std::str::FromStr;

/// The possible errors which can occur on instantiation of the [HaveIBeenPwnedParser](struct.HaveIBeenPwnedParser.html) class.
#[derive(Debug)]
pub enum CreateInstanceError {
    /// It seems that the format of the file is not as expected.
    Format(FormatErrorKind),
    /// There was a generic IO error.
    Io(Error),
}

/// The more specific error if the format could not be read.
#[derive(Debug)]
pub enum FormatErrorKind {
    /// It seems that the file is not a plain text file.
    NotATextFile,
    /// It seems that the format of at least one of the lines in the file is invalid.
    LineFormatNotCorrect,
}

impl FormatErrorKind {
    fn to_string(&self) -> &str {
        match *self {
            FormatErrorKind::NotATextFile => "not a text file which can be parsed",
            FormatErrorKind::LineFormatNotCorrect => {
                "format of lines does not match the required format"
            }
        }
    }
}

impl Display for CreateInstanceError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            CreateInstanceError::Format(ref err_kind) => {
                write!(f, "Format error: {}", err_kind.to_string())
            }
            CreateInstanceError::Io(ref err) => write!(f, "IO error: {}", err),
        }
    }
}

/// This class can be used to parse the password files provided by https://haveibeenpwned.com.
pub struct HaveIBeenPwnedParser {
    known_password_hashes: Option<HashMap<String, u64>>,
}

impl HaveIBeenPwnedParser {
    /// Get a new instance of the file parsed based on the provided file path.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations, but is not
    /// limited to just these cases:
    ///
    ///  * The user does not have the access rights to access the provided file.
    ///  * The file does not exist.
    ///  * The file is not a plain text file.
    ///  * The format of the lines in the text file does not match the required format.
    ///
    /// # Example
    /// ```
    /// use pwned_rs::HaveIBeenPwnedParser;
    ///
    /// match HaveIBeenPwnedParser::from_file("/path/to/the/hash/file.txt") {
    ///     Ok(instance) => println!("Got an instance of the file parser!"),
    ///     Err(error) => println!("Could not get an instance, the error was: {}", error)
    /// }
    /// ```
    pub fn from_file(path_to_file: &str) -> Result<HaveIBeenPwnedParser, CreateInstanceError> {
        // be sure that the file exists, if not we should return a proper error which the caller can deal with
        let _file_meta_data = match std::fs::metadata(path_to_file) {
            Ok(data) => data,
            Err(error) => return Err(CreateInstanceError::Io(error)),
        };

        // try to figure our how many entries are stored in the file
        let number_of_entries = match OpenOptions::new()
            .append(false)
            .create(false)
            .read(true)
            .open(&path_to_file)
        {
            Ok(file_handle) => BufReader::new(file_handle).lines().count(),
            Err(error) => return Err(CreateInstanceError::Io(error)),
        };
        debug!(
            "Found {} entries in the password hash file",
            number_of_entries
        );

        // return the successfully created instance of the parser
        Ok(HaveIBeenPwnedParser {
            known_password_hashes: None,
        })
    }

    /// Get the number of occurrences of a password according to the loaded hash file.
    ///
    /// # Example
    /// ```
    /// use pwned_rs::HaveIBeenPwnedParser;
    ///
    /// match HaveIBeenPwnedParser::from_file("/path/to/the/hash/file.txt") {
    ///     Ok(instance) => {
    ///         let number_of_occurrences = instance.get_usage_count("password");
    ///         println!("The password 'password' was used {} times", number_of_occurrences);
    ///     },
    ///     Err(error) => println!("Could not get an instance, the error was: {}", error)
    /// }
    /// ```
    pub fn get_usage_count(&self, password: &str) -> u64 {
        match self.known_password_hashes {
            Some(ref hash_map) => {
                // get the SHA-1 hashed password
                let mut hasher = Sha1::new();
                hasher.input_str(password);
                let password_hash = hasher.result_str();

                // return the number of occurrences in the hash map
                match hash_map.get(password_hash.as_str()) {
                    Some(number) => *number,
                    None => 0,
                }
            }
            None => 0,
        }
    }
}

impl FromStr for HaveIBeenPwnedParser {
    type Err = CreateInstanceError;

    /// Get a new instance of the parser based on a provided content string.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations, but is not
    /// limited to just these cases:
    ///
    ///  * The format of the lines in the text file does not match the required format.
    ///
    /// # Example
    /// ```
    /// use pwned_rs::HaveIBeenPwnedParser;
    /// use std::str::FromStr;
    ///
    /// let sample_list = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:4\ne731a7b612ab389fcb7f973c452f33df3eb69c99:24";
    ///
    /// match HaveIBeenPwnedParser::from_str(sample_list) {
    ///     Ok(instance) => println!("Got an instance of the file parser!"),
    ///     Err(error) => println!("Could not get an instance, the error was: {}", error)
    /// }
    /// ```
    fn from_str(_input_data: &str) -> Result<Self, Self::Err> {
        let splitted_input = _input_data.split('\n');
        let mut new_hash_map: HashMap<String, u64> = HashMap::new();

        // loop through all password lines and add them to our new hash map
        for password_line in splitted_input {
            // if at least one of the lines does not contain the required colon as separator, the input is invalid
            if !password_line.contains(':') {
                return Err(CreateInstanceError::Format(
                    FormatErrorKind::LineFormatNotCorrect,
                ));
            }

            // split the line at the colon. left side is the hash and the right side is the # of occurrences
            let mut entry_splitted = password_line.split(':');

            // get the hash for
            let key = match entry_splitted.next() {
                Some(key_text) => key_text.to_lowercase(),
                None => {
                    return Err(CreateInstanceError::Format(
                        FormatErrorKind::LineFormatNotCorrect,
                    ))
                }
            };

            // try to get the number of occurrences of the password hash
            let value = match entry_splitted.next() {
                Some(value_text) => match value_text.parse::<u64>() {
                    Ok(value_as_int) => value_as_int,
                    Err(_) => {
                        return Err(CreateInstanceError::Format(
                            FormatErrorKind::LineFormatNotCorrect,
                        ))
                    }
                },
                None => {
                    return Err(CreateInstanceError::Format(
                        FormatErrorKind::LineFormatNotCorrect,
                    ))
                }
            };

            // add the newly parsed entry to our hash map
            new_hash_map.insert(key.to_string(), value);
        }
        debug!(
            "Found {} entries in the password hash string",
            new_hash_map.len()
        );

        // return the newly created instance
        Ok(HaveIBeenPwnedParser {
            known_password_hashes: Some(new_hash_map),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creating_instance_with_invalid_path_fails() {
        let maybe_instance = HaveIBeenPwnedParser::from_file("/this/file/does/not/exist.txt");

        assert_eq!(true, maybe_instance.is_err());
        let error = maybe_instance.err().unwrap();
        assert_eq!(true, error.to_string().contains("IO error:"));
    }

    #[test]
    fn getting_instance_from_invalid_string_input_deals_with_it_correctly() {
        let sample_list =
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\ne731a7b612ab389fcb7f973c452f33df3eb69c99";
        let maybe_instance = HaveIBeenPwnedParser::from_str(sample_list);

        assert_eq!(true, maybe_instance.is_err());
        let instance = maybe_instance.err().unwrap();
        assert_eq!(
            true,
            instance
                .to_string()
                .contains("format of lines does not match the required format")
        );
    }

    #[test]
    fn getting_instance_from_string_with_invalid_hash_count_format_will_be_handles_correctly() {
        let sample_list =
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:10\ne731a7b612ab389fcb7f973c452f33df3eb69c99:SDSDSDSD";
        let maybe_instance = HaveIBeenPwnedParser::from_str(sample_list);

        assert_eq!(true, maybe_instance.is_err());
        let instance = maybe_instance.err().unwrap();
        assert_eq!(
            true,
            instance
                .to_string()
                .contains("format of lines does not match the required format")
        );
    }

    #[test]
    fn getting_the_usage_count_from_a_string_instance_works() {
        let sample_list = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:4\ne731a7b612ab389fcb7f973c452f33df3eb69c99:24";
        let maybe_instance = HaveIBeenPwnedParser::from_str(sample_list);

        assert_eq!(true, maybe_instance.is_ok());
        let instance = maybe_instance.unwrap();
        assert_eq!(4, instance.get_usage_count("password"));
        assert_eq!(24, instance.get_usage_count("p4ssw0rd"));
        assert_eq!(0, instance.get_usage_count("not_included"));
    }

    #[test]
    fn getting_the_usage_count_from_a_string_instance_works_case_insensitive() {
        let sample_list = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:4\nE731A7B612AB389FCB7F973C452F33DF3EB69C99:24";
        let maybe_instance = HaveIBeenPwnedParser::from_str(sample_list);

        assert_eq!(true, maybe_instance.is_ok());
        let instance = maybe_instance.unwrap();
        assert_eq!(4, instance.get_usage_count("password"));
        assert_eq!(24, instance.get_usage_count("p4ssw0rd"));
        assert_eq!(0, instance.get_usage_count("not_included"));
    }
}
