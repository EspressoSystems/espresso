#![allow(dead_code)]
// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU
// General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not,
// see <https://www.gnu.org/licenses/>.

use async_std::task::{block_on, sleep, spawn_blocking};
use escargot::CargoBuild;
use espresso_validator::MINIMUM_NODES;
use espresso_validator::{testing::AddressBook, ConsensusConfig};
use jf_cap::keys::UserPubKey;
use portpicker::pick_unused_port;
use regex::Regex;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;
use surf::Url;
use tempdir::TempDir;

/// Set up and run a test of the keystore CLI.
///
/// This function initializes a [CliClient] for a new network of keystores and passes it to the test
/// function. The result is converted to an error as if by unwrapping.
///
/// It is important that CLI tests fail by returning an [Err] [Result], rather than by panicking,
/// because panicking while borrowing from a [CliClient] can prevent the [CliClient] destructor from
/// running, which can leak long-lived processes. This function will ensure the [CliClient] is
/// dropped before it panics.
pub fn cli_test(test: impl Fn(&mut CliClient) -> Result<(), String>) {
    if let Err(msg) = test(&mut CliClient::new().unwrap()) {
        panic!("{}", msg);
    }
}

pub struct CliClient {
    validators: Vec<Validator>,
    keystores: Vec<Keystore>,
    address_book: AddressBook,
    variables: HashMap<String, String>,
    prev_output: Vec<String>,
    server_port: u16,
    _tmp_dir: TempDir,
}

impl CliClient {
    pub fn new() -> Result<Self, String> {
        // Generate keys for the primary keystore.
        let tmp_dir = TempDir::new("test_keystore_cli").map_err(err)?;
        let mut key_path = PathBuf::from(tmp_dir.path());
        key_path.push("primary_key");
        Keystore::key_gen(&key_path)?;
        let mut pub_key_path = key_path.clone();
        pub_key_path.set_extension("pub");
        let pub_key = bincode::deserialize(&fs::read(&pub_key_path).unwrap()).unwrap();

        // Each validator gets two ports: one for its HotShot node and one for the web sever.
        let mut ports = [(0, 0); 6];
        for p in &mut ports {
            *p = (
                pick_unused_port().ok_or_else(|| "no available ports".to_owned())?,
                pick_unused_port().ok_or_else(|| "no available ports".to_owned())?,
            );
        }

        let mut state = Self {
            keystores: Default::default(),
            variables: Default::default(),
            prev_output: Default::default(),
            validators: Self::start_validators(tmp_dir.path(), pub_key, &ports)?,
            address_book: block_on(AddressBook::init()),
            server_port: ports[0].1,
            _tmp_dir: tmp_dir,
        };
        state.load(Some(key_path))?;
        Ok(state)
    }

    pub fn open(&mut self, keystore: usize) -> Result<&mut Self, String> {
        self.open_with_args(keystore, [""; 0])
    }

    pub fn open_with_args<I, S>(&mut self, keystore: usize, args: I) -> Result<&mut Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        while keystore >= self.keystores.len() {
            self.load(None)?;
        }
        self.prev_output = self.keystores[keystore].open(args)?;
        Ok(self)
    }

    pub fn close(&mut self, keystore: usize) -> Result<&mut Self, String> {
        if let Some(keystore) = self.keystores.get_mut(keystore) {
            keystore.close();
        }
        Ok(self)
    }

    pub fn keystore_key_path(&mut self, keystore: usize) -> Result<PathBuf, String> {
        while keystore >= self.keystores.len() {
            self.load(None)?;
        }
        Ok(self.keystores[keystore].key_path.clone())
    }

    pub fn open_validator(&mut self, v: usize) -> Result<&mut Self, String> {
        block_on(
            self.validators
                .get_mut(v)
                .ok_or_else(|| format!("no such validator {}", v))?
                .open(),
        )?;
        Ok(self)
    }

    pub fn close_validator(&mut self, v: usize) -> Result<&mut Self, String> {
        self.validators
            .get_mut(v)
            .ok_or_else(|| format!("no such validator {}", v))?
            .close();
        Ok(self)
    }

    /// Issue a command to the keystore identified by `keystore`.
    ///
    /// The command string will be preprocessed by replacing each occurrence of `$var` in the
    /// command with the value of the variable `var`. See [output] for how variables can be bound to
    /// values using named capture groups in regexes.
    ///
    /// If `keystore` refers to a keystore that has not yet been created, a new one will be created. The
    /// `TestState` always starts off with one keystore, index 0, which gets an initial grant of 2^32
    /// native tokens. So `command(0, "command")` will not load a new keystore. But the first time
    /// `command(1, "command")` is called, it will block until keystore 1 is created.
    ///
    /// [output]: #method.output
    pub fn command(&mut self, id: usize, command: impl AsRef<str>) -> Result<&mut Self, String> {
        let command = self.substitute(command)?;
        let keystore = self
            .keystores
            .get_mut(id)
            .ok_or_else(|| format!("keystore {} is not open", id))?;
        println!("{}> {}", id, command);
        self.prev_output = keystore.command(&command)?;
        Ok(self)
    }

    /// Match the output of the previous command against a regex.
    ///
    /// `regex` always matches a whole line (and only a line) of output. The order of the output
    /// does not matter; `regex` will be matched against each line of output until finding one that
    /// matches.
    ///
    /// Strings matched by named captures groups in `regex` (syntax "(?P<name>exp)") will be
    /// assigned to variables based on the name of the capture group. The values of these variables
    /// can then be substituted into commands and regular expressions using `$name`.
    pub fn output(&mut self, regex: impl AsRef<str>) -> Result<&mut Self, String> {
        let regex = Regex::new(&self.substitute(regex)?).map_err(err)?;
        for line in &self.prev_output {
            if let Some(re_match) = regex.captures(line) {
                for var in regex.capture_names().flatten() {
                    if let Some(var_match) = re_match.name(var) {
                        self.variables
                            .insert(String::from(var), String::from(var_match.as_str()));
                    }
                }
                return Ok(self);
            }
        }

        Err(format!(
            "regex \"{}\" did not match output:\n{}",
            regex,
            self.prev_output.join("\n")
        ))
    }

    pub fn last_output(&self) -> impl Iterator<Item = &String> {
        self.prev_output.iter()
    }

    pub fn var(&self, var: impl AsRef<str>) -> Result<String, String> {
        self.variables
            .get(var.as_ref())
            .cloned()
            .ok_or_else(|| format!("no such variable {}", var.as_ref()))
    }

    pub fn validators(&self) -> impl Iterator<Item = &Validator> {
        self.validators.iter()
    }

    pub fn validator(&self, validator: usize) -> Result<&Validator, String> {
        self.validators
            .get(validator)
            .ok_or_else(|| format!("no such validator {}", validator))
    }

    pub fn keystores(&self) -> impl Iterator<Item = &Keystore> {
        self.keystores.iter()
    }

    fn load(&mut self, key_path: Option<PathBuf>) -> Result<&mut Self, String> {
        self.keystores.push(Keystore::new(
            format!("http://localhost:{}", self.server_port)
                .parse()
                .unwrap(),
            self.address_book.url(),
            key_path,
        )?);
        Ok(self)
    }

    fn substitute(&self, string: impl AsRef<str>) -> Result<String, String> {
        let mut undefined = Vec::new();
        let replaced = Regex::new("\\$([a-zA-Z0-9_]+)").map_err(err)?.replace_all(
            string.as_ref(),
            |captures: &regex::Captures<'_>| {
                let var = captures.get(1).unwrap();
                match self.variables.get(var.as_str()) {
                    Some(val) => val.clone(),
                    None => {
                        undefined.push(String::from(var.as_str()));
                        String::new()
                    }
                }
            },
        );
        if !undefined.is_empty() {
            return Err(format!(
                "undefined variables in substitution: {}",
                undefined.join(", ")
            ));
        }
        Ok(String::from(replaced))
    }

    fn start_validators(
        tmp_dir: &Path,
        pub_key: UserPubKey,
        ports: &[(u16, u16)],
    ) -> Result<Vec<Validator>, String> {
        let (hotshot_ports, server_ports): (Vec<_>, Vec<_>) = ports.iter().cloned().unzip();
        assert!(
            ports.len() >= MINIMUM_NODES,
            "At least {} nodes are needed for consensus. We only have {} nodes",
            MINIMUM_NODES,
            ports.len()
        );
        let config = ConsensusConfig {
            seed: [
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
                5, 6, 7, 8,
            ]
            .into(),
            bootstrap_nodes: hotshot_ports
                .into_iter()
                .map(|port| {
                    Url::parse(&format!("http://localhost:{}", port))
                        .unwrap()
                        .into()
                })
                .collect(),
            // NOTE these are arbitrarily chosen.
            num_bootstrap: 4,
            replication_factor: ports.len() - 2,
            bootstrap_mesh_n_high: 50,
            bootstrap_mesh_n_low: 10,
            bootstrap_mesh_outbound_min: 5,
            bootstrap_mesh_n: 15,
            mesh_n_high: 15,
            mesh_n_low: 8,
            mesh_outbound_min: 4,
            mesh_n: 12,
            base_port: 9000,
        };
        let mut config_file = tmp_dir.to_path_buf();
        config_file.push("node-config.toml");
        File::create(&config_file)
            .unwrap()
            .write_all(toml::to_string(&config).unwrap().as_bytes())
            .unwrap();

        let ret = block_on(futures::future::join_all(
            server_ports.into_iter().enumerate().map(|(i, port)| {
                let mut v = Validator::new(&config_file, pub_key.clone(), i, port);
                async move {
                    v.open().await?;
                    Ok(v)
                }
            }),
        ))
        .into_iter()
        .collect::<Result<_, _>>();

        println!("All validators started");
        ret
    }
}

struct OpenKeystore {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    process: Child,
}

pub struct Keystore {
    process: Option<OpenKeystore>,
    key_path: PathBuf,
    storage: TempDir,
    validator: Url,
    address_book: Url,
}

impl Keystore {
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(|p| p.process.id())
    }

    pub fn storage(&self) -> PathBuf {
        PathBuf::from(self.storage.path())
    }

    pub fn validator(&self) -> Url {
        self.validator.clone()
    }

    pub fn address_book(&self) -> Url {
        self.address_book.clone()
    }

    fn key_gen(key_path: &Path) -> Result<(), String> {
        cargo_run("zerok_client", "wallet-cli")?
            .args([
                "-g",
                key_path
                    .as_os_str()
                    .to_str()
                    .ok_or("failed to convert key path to string")?,
            ])
            .spawn()
            .map_err(err)?
            .wait()
            .map_err(err)?;
        Ok(())
    }

    fn new(validator: Url, address_book: Url, key_path: Option<PathBuf>) -> Result<Self, String> {
        let storage = TempDir::new("test_keystore").map_err(err)?;
        let key_path = match key_path {
            Some(path) => path,
            None => {
                let mut path = PathBuf::from(storage.path());
                path.push("key");
                Self::key_gen(&path)?;
                path
            }
        };
        Ok(Self {
            process: None,
            key_path,
            storage,
            validator,
            address_book,
        })
    }

    fn open<I, S>(&mut self, args: I) -> Result<Vec<String>, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        if self.process.is_some() {
            return Err(String::from("keystore is already open"));
        }
        let mut child = cargo_run("zerok_client", "wallet-cli")?
            .args([
                "--storage",
                self.storage.path().as_os_str().to_str().ok_or_else(|| {
                    format!(
                        "failed to convert storage path {:?} to string",
                        self.storage.path()
                    )
                })?,
            ])
            .arg("--non-interactive")
            .args(args)
            .arg("--esqs-url")
            .arg(&self.validator.to_string())
            .arg("--submit-url")
            .arg(&self.validator.to_string())
            .arg("--address-book-url")
            .arg(&self.address_book.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(err)?;
        let stdin = child
            .stdin
            .take()
            .ok_or("failed to open stdin for keystore")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to open stdout for keystore")?;
        self.process = Some(OpenKeystore {
            process: child,
            stdin,
            stdout: BufReader::new(stdout),
        });
        self.read_until_prompt()
    }

    fn close(&mut self) {
        if let Some(mut child) = self.process.take() {
            drop(child.stdin);
            child.process.wait().ok();
        }
    }

    fn command(&mut self, command: &str) -> Result<Vec<String>, String> {
        if let Some(child) = &mut self.process {
            writeln!(child.stdin, "{}", command).map_err(err)?;
            self.read_until_prompt()
        } else {
            Err(String::from("keystore is not open"))
        }
    }

    fn read_until_prompt(&mut self) -> Result<Vec<String>, String> {
        if let Some(child) = &mut self.process {
            let mut lines = Vec::new();
            let mut line = String::new();
            loop {
                if child.stdout.read_line(&mut line).map_err(err)? == 0 {
                    return Err("wallet reached EOF before printing prompt".to_string());
                }
                let line = std::mem::take(&mut line);
                let line = line.trim();
                println!("< {}", line);
                if line.starts_with("Error loading keystore") {
                    return Err(String::from(line));
                }
                if !line.is_empty() {
                    lines.push(String::from(line));
                }
                match line {
                    ">"
                    | "Enter password:"
                    | "Create password:"
                    | "Retype password:"
                    | "Enter mnemonic phrase:" => {
                        break;
                    }
                    _ => {}
                }
            }
            Ok(lines)
        } else {
            Err(String::from("keystore is not open"))
        }
    }
}

impl Drop for Keystore {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct Validator {
    process: Option<Child>,
    id: usize,
    cfg_path: PathBuf,
    store_path: PathBuf,
    pub_key: UserPubKey,
    port: u16,
}

impl Validator {
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(|p| p.id())
    }

    pub fn hostname(&self) -> String {
        String::from("localhost")
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    fn new(cfg_path: &Path, pub_key: UserPubKey, id: usize, port: u16) -> Self {
        let cfg_path = PathBuf::from(cfg_path);
        let mut store_path = cfg_path.clone();
        store_path.pop(); // remove config toml file
        store_path.push(format!("store_for_{}", id));
        println!(
            "Launching validator with store path {}",
            store_path.as_os_str().to_str().unwrap()
        );

        Self {
            process: None,
            id,
            cfg_path,
            store_path,
            pub_key,
            port,
        }
    }

    async fn open(&mut self) -> Result<(), String> {
        if self.process.is_some() {
            return Err(format!("validator {} is already open", self.id));
        }

        let cfg_path = self.cfg_path.clone();
        let store_path = self.store_path.clone();
        let pub_key = self.pub_key.clone();
        let id = self.id;
        let port = self.port;
        let mut child = spawn_blocking(move || {
            cargo_run("espresso-validator", "espresso-validator")
                .map_err(err)?
                .args([
                    "--config",
                    cfg_path.as_os_str().to_str().unwrap(),
                    "--store-path",
                    store_path.as_os_str().to_str().unwrap(),
                    "--full",
                    "--id",
                    &id.to_string(),
                    "--faucet-pub-key",
                    &pub_key.to_string(),
                ])
                .env("ESPRESSO_VALIDATOR_PORT", port.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(err)
        })
        .await?;

        // Spawn a detached task to consume the validator's stdout. If we
        // don't do this, the validator will eventually fill up its output
        // pipe and block.
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        spawn_blocking(move || {
            for line in lines {
                if line.is_ok() {
                    println!("[id {}]{}", id, line.unwrap());
                } else {
                    println!("[id {}]{:?}", id, line.err())
                }
            }
        });

        // Wait for the child to initialize its web server.
        wait_for_connect(port).await?;

        self.process = Some(child);
        println!("Leaving Validator::new for {}", id);
        Ok(())
    }

    fn close(&mut self) {
        if let Some(mut child) = self.process.take() {
            child.kill().ok();
            child.wait().ok();
        }
    }
}

impl Drop for Validator {
    fn drop(&mut self) {
        self.close();
    }
}

fn err(err: impl std::fmt::Display) -> String {
    err.to_string()
}

fn cargo_run(package: impl AsRef<str>, bin: impl AsRef<str>) -> Result<Command, String> {
    Ok(CargoBuild::new()
        .package(package.as_ref())
        .bin(bin.as_ref())
        .current_release()
        .current_target()
        .run()
        .map_err(err)?
        .command())
}

async fn wait_for_connect(port: u16) -> Result<(), String> {
    let url: Url = format!("http://localhost:{}", port).parse().unwrap();
    let mut backoff = Duration::from_millis(500);
    for _ in 0..10 {
        if surf::connect(&url).await.is_ok() {
            return Ok(());
        }
        sleep(backoff).await;
        backoff *= 2;
    }
    Err(format!(
        "failed to connect to port {} in {:?}",
        port, backoff
    ))
}
