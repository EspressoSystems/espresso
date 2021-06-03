// Copyright © 2020 Translucence Research, Inc. All rights reserved.
#![deny(warnings)]
#![allow(dead_code)]

pub use crate::ip::IpPort;

use serde_derive::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::fs::{create_dir_all, read_to_string};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::exit;
use structopt::StructOpt;
use tracing::error;

/// Configuration file version. (Currently unused.)
///
/// The configuration file is a TOML file.  The code will panic if the
/// contents of the file do not match the [ConfigFile](ConfigFile)
/// struct below.
pub const CONFIG_VERSION: &str = "0";

/// Default data directory
pub const COMPANY_DATA_DIR: &str = "~/tri";

/// Base name for the localization and discoverability message catalog file
pub const MESSAGES_BASENAME: &str = "messages";

pub const DEFAULT_IP_PORT: u16 = 8000;

/// Operating system exit status for invalid arguments
pub const EXIT_2_ARG_ERROR: i32 = 2;

// Since we're using both cargo doc and structopt, we need a way
// to signal that a doc comment does not belong to both.
// This workaround comes from https://github.com/TeXitoi/structopt/issues/333
#[cfg_attr(not(doc), allow(missing_docs))]
#[cfg_attr(
    doc,
    doc = r#"
Configuration file contents

Note: When adding fields, review functions
- [default](ConfigFile::default)
- [compose_config](compose_config)
"#
)]
#[derive(Debug, Deserialize, Serialize, StructOpt)]
pub struct ConfigFile {
    #[structopt(skip)]
    file_format_version: String,

    /// Network port. Defaults to 8000.
    #[structopt(short, long)]
    pub port: Option<IpPort>,
}

impl Default for ConfigFile {
    /// Default configuration file contents
    fn default() -> ConfigFile {
        ConfigFile {
            file_format_version: CONFIG_VERSION.to_string(),
            port: Some(IpPort(DEFAULT_IP_PORT)),
        }
    }
}

/// Demo 1 - Anonymous transaction generation and validation
#[derive(Debug, Deserialize, Serialize, StructOpt)]
pub struct Args {
    /// Configuration path. Defaults to
    ///    ~/tri/webservice/webservice.toml
    #[structopt(verbatim_doc_comment, long = "config", parse(from_os_str))]
    pub path: Option<PathBuf>,

    #[structopt(flatten)]
    config_file: ConfigFile,

    /// Writes the default configuration to
    ///    ~/tri/webservice/webservice.toml
    /// unless it is already present or --config is
    /// specified
    #[structopt(verbatim_doc_comment, long)]
    pub write_config: bool,
}

// todo !corbett Simplify with the figment library?
/// Configuration source. See [compose_config()](compose_config) below.
pub enum ConfigSource {
    /// At least some configuration from the command line
    CommandLine,

    /// Configuration exclusively from defaults in the source
    Default,

    /// Configuration from a file
    File,
}

/// Gets the server configuration.
///
/// There are three sources of configuration in order from highest
/// precedence to lowest (first one wins)
/// - Command line arguments
/// - A configuration file
/// - The function default_args()
pub fn compose_config() -> (ConfigFile, ConfigSource) {
    let args = Args::from_args();
    let mut source = ConfigSource::CommandLine;
    let mut got_path_from_args = true;
    let path = args.path.unwrap_or_else(|| {
        source = ConfigSource::File;
        got_path_from_args = false;
        default_config_path()
    });

    let mut config_and_source: (ConfigFile, _) = match read_to_string(&path) {
        Ok(config_str) => (
            toml::from_str(&config_str).unwrap_or_else(|_| panic!("Syntax error in {:?}", &path)),
            source,
        ),
        Err(_) => (
            Default::default(),
            if got_path_from_args {
                ConfigSource::CommandLine
            } else {
                ConfigSource::Default
            },
        ),
    };
    if args.config_file.port.is_some() {
        config_and_source.0.port = args.config_file.port;
    }

    config_and_source
}

/// Writes the given configuration to the given path, but only if
/// the target file does not exist yet.
pub fn write_config_file(config_file: &ConfigFile, path: &Path) {
    let config_str = toml::to_string(&config_file).expect("Failed to serialize configuration");
    // This shouldn't fail if path is reasonable.
    // todo !corbett But the input might come from the user so...
    let dir = path
        .parent()
        .unwrap_or_else(|| panic!("Failed to get parent directory of {:?}", &path));
    // This could fail if permissions are wonky, etc.
    create_dir_all(&dir).unwrap_or_else(|_| panic!("Failed to create directory {:?}", &dir));

    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => file
            .write_all(config_str.as_bytes())
            .expect("Failed to write configuration"),
        Err(_) => {
            error!("File already exists: {:?}", &path);
            // todo !corbett return a Result and let main() exit.
            exit(EXIT_2_ARG_ERROR);
        }
    };
}

/// Attempts to get the executable name. (Not supported on all
/// platforms, e.g. BSD.)
///
/// Note, if this function fails, there's no reasonable recovery, so
/// the unwraps will cause a crash.
///
/// Note, under `cargo test`, the executable is different than normal.
/// If the tests are inside the application, the name has a hash
/// appended to the name, so it can't be used directly to locate the
/// config file.
///
/// For example,
/// ```
///    ~/tri/webservice/target/debug/deps/webservice-2e242c004e9a3cea
/// ```
/// If the tests are separated into their own crate, the name uses
/// the crate name and a hash, e.g.
/// ```
///    ~/tri/webservice/target/debug/deps/tests-c9123e859c934be8
/// ```
pub fn executable_name() -> String {
    std::env::current_exe()
        .expect("current_exe() returned an error")
        .file_stem()
        .expect("file_stem() returned None")
        .to_str()
        .expect("Failed to convert the executable name to UTF-8")
        .to_string()
}

/// Returns "~/tri/<appname>/<appname>.toml" where <appname> is
/// the basename without the extension of the current executable.
///
/// For example, the default example is
/// ```
///    ~/tri/webservice/webservice.toml
/// ```
pub fn default_config_path() -> PathBuf {
    let home_dir = shellexpand::tilde(COMPANY_DATA_DIR).to_string();
    let app_name = executable_name();
    let mut path: PathBuf = [&home_dir, &app_name, &app_name].iter().collect();
    let is_valid = path.set_extension("toml");
    if !is_valid {
        panic!("Failed to compose default configuration path.");
    }
    path
}
