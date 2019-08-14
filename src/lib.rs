pub mod subcommands;

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use log::{debug, error};
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::{File, OpenOptions};
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

#[derive(Debug, PartialEq)]
pub enum HashLineFormatError {
    NoOccurrenceCountFound,
    NotAValidSha1Hash,
    MultipleHashLines,
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

impl Display for HashLineFormatError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            HashLineFormatError::NotAValidSha1Hash => write!(
                f,
                "It seems that the supplied hash string is not a valid SHA-1 hash"
            ),
            HashLineFormatError::MultipleHashLines => write!(
                f,
                "It seems that the supplied string contains more than one line"
            ),
            HashLineFormatError::NoOccurrenceCountFound => write!(
                f,
                "Could not find a occurrence count in the supplied string"
            ),
        }
    }
}

/// This class can be used to parse the password files provided by https://haveibeenpwned.com.
pub struct HaveIBeenPwnedParser {
    known_password_hashes: Option<HashMap<String, u64>>,
    file_size: u64,
    password_file: Option<BufReader<File>>,
}

/// This struct is used to represent a single password hash entry.
pub struct PasswordHashEntry {
    hash: String,
    occurrences: u64,
    entry_size: u64,
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
        let file_meta_data = match std::fs::metadata(path_to_file) {
            Ok(data) => data,
            Err(error) => return Err(CreateInstanceError::Io(error)),
        };

        // try to figure our how many entries are stored in the file
        let file_reader = match OpenOptions::new()
            .append(false)
            .create(false)
            .read(true)
            .open(&path_to_file)
        {
            Ok(file_handle) => BufReader::new(file_handle),
            Err(error) => return Err(CreateInstanceError::Io(error)),
        };

        // return the successfully created instance of the parser
        Ok(HaveIBeenPwnedParser {
            known_password_hashes: None,
            password_file: Some(file_reader),
            file_size: file_meta_data.len(),
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

    /// Get the size of the original password file.
    ///
    /// # Example
    /// ```
    /// use pwned_rs::HaveIBeenPwnedParser;
    ///
    /// match HaveIBeenPwnedParser::from_file("/path/to/the/hash/file.txt") {
    ///     Ok(instance) => {
    ///         let file_size = match instance.get_file_size() {
    ///             Some(size) => size,
    ///             None => panic!("It seems that the instance of this object was not created using a file."),
    ///         };
    ///         println!("The original password file is {} bytes long", file_size);
    ///     },
    ///     Err(error) => println!("Could not get an instance, the error was: {}", error)
    /// }
    /// ```
    pub fn get_file_size(&self) -> Option<u64> {
        if self.password_file.is_some() {
            return Some(self.file_size);
        }
        None
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
            password_file: None,
            file_size: 0,
        })
    }
}

impl Iterator for HaveIBeenPwnedParser {
    type Item = PasswordHashEntry;

    fn next(&mut self) -> Option<Self::Item> {
        // be sure that we are running in file mode, otherwise we can return immediately
        let password_file_reader = match &mut self.password_file {
            Some(reader) => reader,
            None => return None,
        };

        // get the next line from the file
        let mut entry_line = String::new();
        let line_length = match password_file_reader.read_line(&mut entry_line) {
            Ok(length) => length,
            Err(_) => return None,
        };

        //
        let mut entry_splitted = entry_line.trim().split(':');

        //
        let password_hash = match entry_splitted.next() {
            Some(key_text) => key_text.to_lowercase(),
            None => {
                error!("Could not get the password hash part of the entry!");
                return None;
            }
        };

        // try to get the number of occurrences of the password hash
        let occurrences = match entry_splitted.next() {
            Some(value_text) => match value_text.parse::<u64>() {
                Ok(value_as_int) => value_as_int,
                Err(_) => {
                    error!("Could not parse the number of occurrences of the password. Maybe \"{}\" not a number.", value_text);
                    return None;
                }
            },
            None => {
                error!("Could not get the occurrence count.");
                return None;
            }
        };

        // return the parsed password entry
        Some(PasswordHashEntry {
            hash: password_hash,
            occurrences,
            entry_size: line_length as u64,
        })
    }
}

impl PasswordHashEntry {
    pub fn get_size_in_bytes(&self) -> u64 {
        self.entry_size
    }

    pub fn get_prefix(&self) -> String {
        let cloned_hash = self.hash.clone();
        cloned_hash[..4].to_string()
    }

    pub fn get_occurrences(&self) -> u64 {
        self.occurrences
    }

    pub fn get_hash(&self) -> String {
        self.hash.clone()
    }

    pub fn get_line_to_write(&self) -> String {
        format!("{}:{}\n", self.hash, self.occurrences)
    }
}

impl FromStr for PasswordHashEntry {
    type Err = HashLineFormatError;

    /// Parse a entry from the database and return an instance to the PasswordHashEntry.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations, but is not
    /// limited to just these cases:
    ///
    ///  * The hash part of the line does not seem to be valid
    ///  * There is a missing seperator for suppling the occurrences of the password
    ///  * The format of the occurences is not valid
    ///
    /// # Example
    /// ```
    /// use pwned_rs::PasswordHashEntry;
    /// use std::str::FromStr;
    ///
    /// let sample_list = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:4";
    ///
    /// match PasswordHashEntry::from_str(sample_list) {
    ///     Ok(instance) => println!("Got an instance of the parsed password hash!"),
    ///     Err(error) => println!("Could not get an instance, the error was: {}", error)
    /// }
    /// ```
    fn from_str(input_str: &str) -> Result<Self, Self::Err> {
        // if there is at least one new line indicator, the input is not valid for us
        if input_str.contains('\n') {
            return Err(HashLineFormatError::MultipleHashLines);
        }

        // if at least one of the lines does not contain the required colon as separator, the input is invalid
        if !input_str.contains(':') {
            return Err(HashLineFormatError::NoOccurrenceCountFound);
        }

        // split the line at the colon. left side is the hash and the right side is the # of occurrences
        let mut entry_splitted = input_str.split(':');

        // get the hash for the current entry
        let hash = match entry_splitted.next() {
            Some(key_text) => key_text.to_lowercase(),
            None => return Err(HashLineFormatError::NoOccurrenceCountFound),
        };

        // try to get the number of occurrences of the password hash
        let occurrences = match entry_splitted.next() {
            Some(value_text) => match value_text.parse::<u64>() {
                Ok(value_as_int) => value_as_int,
                Err(_) => return Err(HashLineFormatError::NoOccurrenceCountFound),
            },
            None => return Err(HashLineFormatError::NoOccurrenceCountFound),
        };

        // a SHA-1 hash has to be 40 hexadecimal characters
        if hash.len() != 40 {
            return Err(HashLineFormatError::NotAValidSha1Hash);
        }

        // return the created entry
        Ok(PasswordHashEntry {
            hash,
            occurrences,
            entry_size: input_str.len() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creating_a_password_hash_entry_from_valid_input_works_as_intended() {
        let input_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
        let input_occurrences = 13;
        let input_string = format!("{}:{}", input_hash, input_occurrences);

        let maybe_instance = PasswordHashEntry::from_str(input_string.as_str());
        assert_eq!(false, maybe_instance.is_err());
        let instance = maybe_instance.unwrap();

        assert_eq!(43, instance.get_size_in_bytes());
        assert_eq!(input_hash[..4].to_string(), instance.get_prefix());
        assert_eq!(input_hash, instance.get_hash());
        assert_eq!(input_occurrences, instance.get_occurrences());
    }

    #[test]
    fn creating_a_password_hash_entry_from_input_with_missing_occurrences_is_handled_correctly() {
        let input_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";

        let maybe_instance = PasswordHashEntry::from_str(input_hash);
        assert_eq!(true, maybe_instance.is_err());
        assert_eq!(
            HashLineFormatError::NoOccurrenceCountFound,
            maybe_instance.err().unwrap()
        );
    }

    #[test]
    fn creating_a_password_hash_entry_from_input_with_invalid_hash_is_handled_correctly() {
        let input_hash = "5baa61e4c9b93f0682250bcf8331b7ee68fd8";
        let input_occurrences = 13;
        let input_string = format!("{}:{}", input_hash, input_occurrences);

        let maybe_instance = PasswordHashEntry::from_str(input_string.as_str());
        assert_eq!(true, maybe_instance.is_err());
        assert_eq!(
            HashLineFormatError::NotAValidSha1Hash,
            maybe_instance.err().unwrap()
        );
    }

    #[test]
    fn creating_a_password_hash_entry_from_multiple_valid_lines_of_entries_is_handled_correctly() {
        let input_hash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
        let input_occurrences = 13;
        let input_string = format!(
            "{}:{}\n{}:{}",
            input_hash, input_occurrences, input_hash, input_occurrences
        );

        let maybe_instance = PasswordHashEntry::from_str(input_string.as_str());
        assert_eq!(true, maybe_instance.is_err());
        assert_eq!(
            HashLineFormatError::MultipleHashLines,
            maybe_instance.err().unwrap()
        );
    }

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
