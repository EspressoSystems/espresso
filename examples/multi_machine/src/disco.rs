// Copyright © 2020 Translucence Research, Inc. All rights reserved.

//use rocket::{get, http::RawStr, response::content::Html, State};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter};
use tracing::error;

use crate::config::{executable_name, COMPANY_DATA_DIR, MESSAGES_BASENAME};
use crate::routes::check_api;

const DISCO_PREFIX: &str = "DISCO_";

/// Index entries for documentation fragments
#[allow(non_camel_case_types)]
#[derive(AsRefStr, Copy, Clone, Debug, EnumIter)]
pub enum DocKey {
    /// Route discoverability help text. See routes().
    // The routes() function lists these in the order below.
    DISCO_health,
    DISCO_help,
    DISCO_routes,
    DISCO_version,

    // In-line messages
    NO_SUCH_ROUTE,
    ONE,
    THE_FOLLOWING_ROUTES,
    WEB_SERVICE_API_DOCUMENTATION,
}

/// Lists all the routes by collecting DocKey enumeration items
/// prefixed by DISCO_.
pub fn doc_key_routes() -> Vec<DocKey> {
    DocKey::iter()
        .filter(|k| k.as_ref().starts_with(DISCO_PREFIX))
        .collect()
}

/// Loads the message catalog or dies trying.
pub fn load_messages(path: &Path) -> toml::Value {
    let messages = read_to_string(&path).expect(&format!("Unable to read {:?}.", &path));
    let api: toml::Value =
        toml::from_str(&messages).expect(&format!("Unable to parse {:?}.", &path));
    check_api(api.clone());
    api
}

/// Looks up the documentation fragment associated with the given key.
/// Returns an error string if the key is not found in the message catalog.
/// See [load_messages()](load_messages) regarding what happens if the
/// catalog is not readable.
pub fn localize(key: DocKey, messages: &toml::Value) -> String {
    match messages.get(key.as_ref()) {
        Some(value) => match value.as_str() {
            Some(str) => str.to_string(),
            None => {
                let err_str = format!("MISSING QUOTES for DocKey {:?}", key);
                error!("{}", &err_str);
                err_str
            }
        },
        None => {
            let err_str = format!("MISSING MESSAGE for DocKey {:?}", key);
            error!("{}", &err_str);
            err_str
        }
    }
}

/// Information needed for discoverability
///
/// The DocKey list provides the keys and the path segments. The
/// keys are simply the enumeration constant names. The path segment names are
/// the key names without the DISCO_ prefix.
///
/// Note, the AsRefStr trait enables us to get the identifer names as
/// strings.
pub struct Disco {
    pub route_names: Vec<DocKey>,
    pub messages: toml::Value,
}

/// Composes the path to the message catalog.
///
/// For example, if the executable name is webservice,
/// ```
///    ~/tri/webservice/messages.toml
/// ```
pub fn messages_path() -> PathBuf {
    let home_dir = shellexpand::tilde(COMPANY_DATA_DIR).to_string();
    let app_name = executable_name();
    let mut path: PathBuf = [&home_dir, &app_name, &MESSAGES_BASENAME.to_string()]
        .iter()
        .collect();
    path.set_extension("toml");
    path
}

/// Extracts the route name from a DocKey enum as a string.
// Failure here indicates an error in the program logic.
pub fn route_from_key(disco_route: DocKey) -> String {
    disco_route
        .as_ref()
        .strip_prefix(DISCO_PREFIX)
        .expect("Invalid argument")
        .to_string()
}
