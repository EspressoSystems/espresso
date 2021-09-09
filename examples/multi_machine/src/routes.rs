// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter, EnumString};
use tagged_base64::TaggedBase64;
use tide;

#[derive(Debug, EnumString)]
pub enum UrlSegmentType {
    Boolean,
    Hexadecimal,
    Integer,
    TaggedBase64,
    Literal,
}

#[derive(Debug)]
pub enum UrlSegmentValue {
    Boolean(bool),
    Hexadecimal(u128),
    Integer(u128),
    Identifier(TaggedBase64),
    Unparsed(String),
    ParseFailed(UrlSegmentType, String),
    Literal(String),
}

#[derive(Debug)]
pub struct RouteBinding {
    /// Placeholder from the route pattern, e.g. :id
    pub parameter: String,

    /// Type for parsing
    pub ptype: UrlSegmentType,

    /// Value
    pub value: UrlSegmentValue,
}

/// Index entries for documentation fragments
#[allow(non_camel_case_types)]
#[derive(AsRefStr, Copy, Clone, Debug, EnumIter, EnumString)]
pub enum ApiRouteKey {
    getblock,
    getblockcount,
    getblockhash,
    getblockid,
    getinfo,
    getmempool,
    gettransaction,
    getunspentrecord,
    getunspentrecordsetinfo,
}

/// Verifiy that every variant of enum ApiRouteKey is defined in api.toml
// TODO !corbett Check all the other things that might fail after startup.
pub fn check_api(api: toml::Value) -> bool {
    let mut missing_definition = false;
    for key in ApiRouteKey::iter() {
        let key_str = key.as_ref();
        if api["route"].get(key_str).is_none() {
            println!("Missing API definition for [route.{}]", key_str);
            missing_definition = true;
        }
    }
    if missing_definition {
        panic!("api.toml is inconsistent with enum ApiRoutKey");
    }
    !missing_definition
}

pub fn dummy_url_eval(
    route_pattern: &str,
    bindings: Option<&RouteBinding>,
) -> Result<tide::Response, tide::Error> {
    Ok(tide::Response::builder(200)
        .body(tide::Body::from_string(format!(
            "<!DOCTYPE html>
<html lang='en'>
  <head>
    <meta charset='utf-8'>
    <title>{}</title>
    <link rel='stylesheet' href='style.css'>
    <script src='script.js'></script>
  </head>
  <body>
    <h1>{}</h1>
    <p>{:?}</p>
  </body>
</html>",
            route_pattern.split_once('/').unwrap().0,
            route_pattern.to_string(),
            bindings
        )))
        .content_type(tide::http::mime::HTML)
        .build())
}

pub async fn dispatch_url(
    route_pattern: &str,
    bindings: Option<&RouteBinding>,
) -> Result<tide::Response, tide::Error> {
    let first_segment = route_pattern.split_once('/').unwrap().0;
    let key = ApiRouteKey::from_str(first_segment).expect("Unknown route");
    match key {
        ApiRouteKey::getblock => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getblockcount => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getblockhash => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getblockid => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getinfo => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getmempool => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::gettransaction => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getunspentrecord => dummy_url_eval(route_pattern, bindings),
        ApiRouteKey::getunspentrecordsetinfo => dummy_url_eval(route_pattern, bindings),
    }
}
