// Copyright © 2021 Translucence Research, Inc. All rights reserved.

pub use crate::ip::IpPort;

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
