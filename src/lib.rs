use std::{error, fmt};

#[derive(Debug, Clone)]
pub struct CreateError;

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "could not create instance due to unknown error")
    }
}

impl error::Error for CreateError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

pub struct HaveIBeenPwnedParser;

impl HaveIBeenPwnedParser {
    pub fn from_file(_path_to_file: &str) -> Result<HaveIBeenPwnedParser, CreateError> {
        Err(CreateError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creating_instance_with_invalid_path_fails() {
        let maybe_instance = HaveIBeenPwnedParser::from_file("/this/file/does/not/exist.txt");

        assert_eq!(true, maybe_instance.is_err());
    }
}
