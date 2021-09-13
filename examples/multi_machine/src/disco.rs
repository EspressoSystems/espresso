// Copyright © 2021 Translucence Research, Inc. All rights reserved.

use crate::routes::check_api;
use std::fs::read_to_string;
use std::path::Path;

/// Loads the message catalog or dies trying.
pub fn load_messages(path: &Path) -> toml::Value {
    let messages = read_to_string(&path).unwrap_or_else(|_| panic!("Unable to read {:?}.", &path));
    let api: toml::Value =
        toml::from_str(&messages).unwrap_or_else(|_| panic!("Unable to parse {:?}.", &path));
    check_api(api.clone());
    api
}
