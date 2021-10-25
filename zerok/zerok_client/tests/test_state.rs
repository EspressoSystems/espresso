use async_std::task::{block_on, spawn_blocking};
use escargot::CargoBuild;
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use tempdir::TempDir;
use toml::Value;

/// Set up and run a test of the wallet CLI.
///
/// This function initializes a [TestState] for a new network of wallets and passes it to the test
/// function. The result is converted to an error as if by unwrapping.
///
/// It is important that CLI tests fail by returning an [Err] [Result], rather than by panicking,
/// because panicking while borrowing from a [TestState] can prevent the [TestState] destructor from
/// running, which can leak long-lived processes. This function will ensure the [TestState] is
/// dropped before it panics.
pub fn cli_test(test: impl Fn(&mut TestState) -> Result<(), String>) {
    if let Err(msg) = test(&mut TestState::new().unwrap()) {
        panic!("{}", msg);
    }
}

pub struct TestState {
    validators: Vec<Validator>,
    wallets: Vec<Wallet>,
    variables: HashMap<String, String>,
    prev_output: Vec<String>,
    server_port: u64,
    _tmp_dir: TempDir,
}

impl TestState {
    fn new() -> Result<Self, String> {
        // Generate keys for the primary wallet.
        let tmp_dir = TempDir::new("test_wallet_cli").map_err(err)?;
        let mut key_path = PathBuf::from(tmp_dir.path());
        key_path.push("primary_key");
        Wallet::key_gen(&key_path)?;

        // Each validator gets two ports: one for its PhaseLock node and one for the web sever.
        let mut ports = [(0, 0); 6];
        for p in &mut ports {
            *p = (get_port(), get_port());
        }

        let mut state = Self {
            wallets: Default::default(),
            variables: Default::default(),
            prev_output: Default::default(),
            validators: Self::start_validators(tmp_dir.path(), &key_path, &ports),
            server_port: ports[0].1,
            _tmp_dir: tmp_dir,
        };
        state.load(Some(key_path))?;
        Ok(state)
    }

    pub fn open(&mut self, wallet: usize) -> Result<&mut Self, String> {
        while wallet >= self.wallets.len() {
            self.load(None)?;
        }
        self.prev_output = self.wallets[wallet].open()?;
        Ok(self)
    }

    pub fn close(&mut self, wallet: usize) -> Result<&mut Self, String> {
        if let Some(wallet) = self.wallets.get_mut(wallet) {
            wallet.close();
        }
        Ok(self)
    }

    /// Issue a command to the wallet identified by `wallet`.
    ///
    /// The command string will be preprocessed by replacing each occurrence of `$var` in the
    /// command with the value of the variable `var`. See [output] for how variables can be bound to
    /// values using named capture groups in regexes.
    ///
    /// If `wallet` refers to a wallet that has not yet been created, a new one will be created. The
    /// [TestState] always starts off with one wallet, index 0, which gets an initial grant of 2^32
    /// native tokens. So `command(0, "command")` will not load a new wallet. But the first time
    /// `command(1, "command")` is called, it will block until wallet 1 is created.
    pub fn command(&mut self, id: usize, command: impl AsRef<str>) -> Result<&mut Self, String> {
        let command = self.substitute(command)?;
        let wallet = self
            .wallets
            .get_mut(id)
            .ok_or_else(|| format!("wallet {} is not open", id))?;
        println!("{}> {}", id, command);
        self.prev_output = wallet.command(&command)?;
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

        return Err(format!(
            "regex \"{}\" did not match output:\n{}",
            regex,
            self.prev_output.join("\n")
        ));
    }

    pub fn start_consensus(&mut self) -> Result<&mut Self, String> {
        for validator in &mut self.validators {
            validator.start_consensus()?;
        }
        Ok(self)
    }

    pub fn var(&self, var: impl AsRef<str>) -> Result<String, String> {
        self.variables
            .get(var.as_ref())
            .cloned()
            .ok_or_else(|| format!("no such variable {}", var.as_ref()))
    }

    fn load(&mut self, key_path: Option<PathBuf>) -> Result<&mut Self, String> {
        self.wallets.push(Wallet::new(
            format!("http://localhost:{}", self.server_port),
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

    fn start_validators(tmp_dir: &Path, key_path: &Path, ports: &[(u64, u64)]) -> Vec<Validator> {
        let (phaselock_ports, server_ports): (Vec<_>, Vec<_>) = ports.iter().cloned().unzip();
        let seed = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8,
        ];
        let nodes = Value::from(
            phaselock_ports
                .into_iter()
                .enumerate()
                .map(|(i, port)| {
                    (
                        i.to_string(),
                        Value::from(
                            vec![
                                ("ip", Value::from("localhost")),
                                ("port", Value::Integer(port as i64)),
                            ]
                            .into_iter()
                            .collect::<HashMap<_, _>>(),
                        ),
                    )
                })
                .collect::<HashMap<_, _>>(),
        );
        let config = Value::from(
            vec![
                ("title", Value::from("Node Configuration")),
                ("seed", Value::from(seed)),
                ("nodes", nodes),
            ]
            .into_iter()
            .collect::<HashMap<_, _>>(),
        );
        let mut config_file = tmp_dir.to_path_buf();
        config_file.push("node-config.toml");
        File::create(&config_file)
            .unwrap()
            .write_all(config.to_string().as_bytes())
            .unwrap();

        block_on(futures::future::join_all(
            server_ports
                .into_iter()
                .enumerate()
                .map(|(i, port)| Validator::new(&config_file, key_path, i, port)),
        ))
    }
}

struct OpenWallet {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    process: Child,
}

struct Wallet {
    process: Option<OpenWallet>,
    key_path: PathBuf,
    storage: TempDir,
    server: String,
}

impl Wallet {
    fn key_gen(key_path: &Path) -> Result<(), String> {
        cargo_run("zerok_client")?
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

    fn new(server: String, key_path: Option<PathBuf>) -> Result<Self, String> {
        let storage = TempDir::new("test_wallet").map_err(err)?;
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
            server,
        })
    }

    fn open(&mut self) -> Result<Vec<String>, String> {
        if self.process.is_some() {
            return Err(String::from("wallet is already open"));
        }
        let mut child = cargo_run("zerok_client")?
            .args([
                "-k",
                self.key_path.as_os_str().to_str().ok_or_else(|| {
                    format!("failed to convert key_path {:?} to string", self.key_path)
                })?,
            ])
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
            .arg(&self.server)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(err)?;
        let stdin = child
            .stdin
            .take()
            .ok_or("failed to open stdin for wallet")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to open stdout for wallet")?;
        self.process = Some(OpenWallet {
            process: child,
            stdin,
            stdout: BufReader::new(stdout),
        });
        self.read_until_prompt()
    }

    fn close(&mut self) {
        if let Some(mut child) = self.process.take() {
            child.process.kill().ok();
            child.process.wait().ok();
        }
    }

    fn command(&mut self, command: &str) -> Result<Vec<String>, String> {
        if let Some(child) = &mut self.process {
            writeln!(child.stdin, "{}", command).map_err(err)?;
            self.read_until_prompt()
        } else {
            Err(String::from("wallet is not open"))
        }
    }

    fn read_until_prompt(&mut self) -> Result<Vec<String>, String> {
        if let Some(child) = &mut self.process {
            let mut lines = Vec::new();
            let mut line = String::new();
            loop {
                child.stdout.read_line(&mut line).map_err(err)?;
                let line = std::mem::take(&mut line);
                let line = line.trim();
                if line.starts_with("Error loading wallet") {
                    return Err(String::from(line));
                }
                if !line.is_empty() {
                    println!("< {}", line);
                    lines.push(String::from(line));
                }
                match line {
                    ">" | "Enter password:" | "Create password:" | "Retype password:" => {
                        break;
                    }
                    _ => {}
                }
            }
            Ok(lines)
        } else {
            Err(String::from("wallet is not open"))
        }
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.close();
    }
}

struct Validator {
    stdin: ChildStdin,
    process: Child,
}

impl Validator {
    async fn new(cfg_path: &Path, key_path: &Path, id: usize, port: u64) -> Self {
        let cfg_path = PathBuf::from(cfg_path);
        let mut key_path = PathBuf::from(key_path);
        key_path.set_extension("pub");
        spawn_blocking(move || {
            let mut child = cargo_run("multi_machine")
                .unwrap()
                .args([
                    "--config",
                    cfg_path.as_os_str().to_str().unwrap(),
                    "--full",
                    "--id",
                    &id.to_string(),
                    "--wallet",
                    key_path.as_os_str().to_str().unwrap(),
                ])
                .env("PORT", port.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
            while let Some(line) = lines.next() {
                let line = line.unwrap();
                if line.trim() == "Hit the return key when ready to start the consensus..." {
                    // Spawn a detached task to consume the validator's stdout. If we don't do this,
                    // the validator will eventually fill up its output pipe and block.
                    async_std::task::spawn(async move { while lines.next().is_some() {} });
                    return Validator {
                        stdin: child.stdin.take().unwrap(),
                        process: child,
                    };
                }
            }
            panic!("validator {} exited", id);
        })
        .await
    }

    fn start_consensus(&mut self) -> Result<(), String> {
        writeln!(self.stdin).map_err(err)
    }
}

impl Drop for Validator {
    fn drop(&mut self) {
        self.process.kill().ok();
        self.process.wait().ok();
    }
}

fn err(err: impl std::fmt::Display) -> String {
    err.to_string()
}

lazy_static! {
    static ref FREE_PORT: Arc<Mutex<u64>> = Arc::new(Mutex::new(
        std::env::var("PORT")
            .ok()
            .and_then(|port| port
                .parse()
                .map_err(|err| {
                    println!("PORT env var must be an integer. Falling back to 50000.");
                    err
                })
                .ok())
            .unwrap_or(50000)
    ));
}

fn get_port() -> u64 {
    let mut first_free_port = FREE_PORT.lock().unwrap();
    let port = *first_free_port;
    *first_free_port += 1;
    port
}

fn cargo_run(bin: impl AsRef<str>) -> Result<Command, String> {
    Ok(CargoBuild::new()
        .package(bin.as_ref())
        .bin(bin.as_ref())
        .current_release()
        .current_target()
        .run()
        .map_err(err)?
        .command())
}
