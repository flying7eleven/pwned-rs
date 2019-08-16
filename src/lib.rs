use crypto::digest::Digest;
use crypto::sha1::Sha1;
use std::fmt::Result as FmtResult;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

pub mod haveibeenpwned;
pub mod subcommands;

#[derive(Debug, PartialEq)]
pub enum HashLineFormatError {
    NoOccurrenceCountFound,
    NotAValidSha1Hash,
    MultipleHashLines,
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

/// This struct is used to represent a single password hash entry.
pub struct PasswordHashEntry {
    hash: String,
    occurrences: u64,
    entry_size: u64,
}

impl PasswordHashEntry {
    pub fn get_size_in_bytes(&self) -> u64 {
        self.entry_size
    }

    pub fn get_prefix(&self) -> String {
        let cloned_hash = self.hash.clone();
        cloned_hash[..3].to_string()
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

    pub fn from_password(password: &str) -> PasswordHashEntry {
        // hash the input password
        let mut hasher = Sha1::new();
        hasher.input_str(password);
        let hashed_password = hasher.result_str();

        // return the created object
        PasswordHashEntry {
            hash: hashed_password.clone(),
            occurrences: 0,
            entry_size: 2 + hashed_password.len() as u64,
        }
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
        assert_eq!(input_hash[..3].to_string(), instance.get_prefix());
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
}
