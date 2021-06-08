// Copyright © 2020 Translucence Research, Inc. All rights reserved.
#![deny(warnings)]
#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]

use rocket::{get, response::content::Html, State};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter};

use crate::config::{executable_name, COMPANY_DATA_DIR, MESSAGES_BASENAME};

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
    let messages = read_to_string(&path).unwrap_or_else(|_| panic!("Unable to read {:?}.", &path));
    toml::from_str(&messages).unwrap_or_else(|_| {
        panic!(
            "Unable to parse {:?}. Probably out of sync with enum DocKey.",
            &path
        )
    })
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

/* TODO !corbett Somehow this doesn't compile.

/// Provides help for a route. The disco parameter has a vector of enums
/// that associate path segments with documentation.
#[get("/<path_segment>/help")]
pub fn route_help(path_segment: &RawStr, disco: State<Disco>) -> Html<String> {
    let decoded_path_segment = path_segment.percent_decode_lossy();
    for name in &disco.route_names {
        if name.as_ref().ends_with(&decoded_path_segment.to_string()) {
            return Html(localize(*name, &disco.messages));
        }
    }
    Html(format!(
        "{}'{}'.\n{}",
        localize(DocKey::NO_SUCH_ROUTE, &disco.messages),
        &decoded_path_segment.to_string(),
        localize(DocKey::WEB_SERVICE_API_DOCUMENTATION, &disco.messages)
    ))
}
*/

/// Provides last ditch help.
// todo !corbett Can't add disco: State<Disco> to the parameters
#[catch(404)]
pub fn not_found(req: &rocket::Request) -> Html<String> {
    // Grossly inefficient while we figure out how to pass state in here.
    let messages = load_messages(&messages_path());
    Html(format!(
        "<p>{} '<code>{}</code>'</p><p>{}</p>",
        localize(DocKey::NO_SUCH_ROUTE, &messages),
        req.uri(),
        localize(DocKey::WEB_SERVICE_API_DOCUMENTATION, &messages)
    ))
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

/// Reports the documentation keys for the routes.
#[get("/routes")]
pub fn routes(disco: &State<Disco>) -> Html<String> {
    Html(format!(
        "{}<ul>{}</ul>",
        localize(DocKey::THE_FOLLOWING_ROUTES, &disco.messages),
        disco
            .route_names
            .iter()
            .fold(String::new(), |acc, disco_route| {
                if let DocKey::DISCO_routes = disco_route {
                    acc
                } else {
                    let route = route_from_key(*disco_route);
                    acc + "<li><a href='" + &route + "'>" + &route + "</a></li>"
                }
            })
    ))
}

/// Responds with the top-level help.
#[get("/help")]
pub fn help(disco: &State<Disco>) -> Html<String> {
    Html(localize(
        DocKey::WEB_SERVICE_API_DOCUMENTATION,
        &disco.messages,
    ))
}
