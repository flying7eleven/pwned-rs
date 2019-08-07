use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::Error;

#[derive(Debug)]
pub enum CreateInstanceError {
    Format(FormatErrorKind),
    Io(Error),
}

#[derive(Debug)]
pub enum FormatErrorKind {
    NotATextFile,
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

pub struct HaveIBeenPwnedParser;

impl HaveIBeenPwnedParser {
    pub fn from_file(path_to_file: &str) -> Result<HaveIBeenPwnedParser, CreateInstanceError> {
        // be sure that the file exists, if not we should return a proper error which the caller can deal with
        let _file_meta_data = match std::fs::metadata(path_to_file) {
            Ok(data) => data,
            Err(error) => return Err(CreateInstanceError::Io(error)),
        };

        // return the successfully created instance of the parser
        Ok(HaveIBeenPwnedParser {})
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
}
