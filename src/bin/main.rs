use chrono::Local;
use clap::{crate_authors, crate_description, crate_name, crate_version, load_yaml, App};
use log::{error, LevelFilter, debug};
use pwned_rs::HaveIBeenPwnedParser;
use std::process::exit;

fn initialize_logging() {
    // configure the logging framework and set the corresponding log level
    let logging_framework = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply();

    // ensure the logging framework was successfully initialized
    if logging_framework.is_err() {
        panic!("Could not initialize the logging framework. Terminating!");
    }
}

fn main() {
    initialize_logging();

    // configure the command line parser
    let configuration_parser_config = load_yaml!("cli.yml");
    let matches = App::from_yaml(configuration_parser_config)
        .author(crate_authors!())
        .version(crate_version!())
        .name(crate_name!())
        .about(crate_description!())
        .get_matches();

    // get the path to the password file
    let password_hash_path = match matches.value_of("password-hashes") {
        Some(path) => path,
        None => {
            error!("It seems that the path the the password hashes was not provided, please see the help for usage instructions.");
            exit(-1);
        }
    };
    debug!("Got {} as a password hash file", password_hash_path);

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
