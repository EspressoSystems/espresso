extern crate zerok_client;
use async_std::task::block_on;
use zerok_client::CliClient;

fn main() {
    let mut cli = CliClient::new().unwrap();
    let mut reader = rustyline::Editor::<()>::new();

    let mut line_num = 0;
    while let Ok(line) = reader.readline("> ") {
        line_num += 1;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (command, line) = match line.split_once(" ") {
            Some(res) => res,
            None => (line, ""),
        };
        let line = line.trim();
        match command {
            "list" => {
                if !line.is_empty() {
                    println!("{}: list command takes no arguments", line_num);
                    continue;
                }

                println!("Validators:");
                for v in cli.validators() {
                    let pid = match v.pid() {
                        Some(id) => id.to_string(),
                        None => String::from("not running"),
                    };
                    println!("  {} {}:{}", pid, v.hostname(), v.port());
                }
                println!("Wallets:");
                for w in cli.wallets() {
                    let pid = match w.pid() {
                        Some(id) => id.to_string(),
                        None => String::from("not running"),
                    };
                    println!("  {} {:?} {}", pid, w.storage(), w.server());
                }
            }

            "wallet" => {
                let (wallet, command) = line.split_once(":").unwrap_or((line, ""));
                let command = command.trim();
                let wallet = match wallet.parse() {
                    Ok(w) => w,
                    Err(e) => {
                        println!("{}: wallet ID must be an integer ({})", line_num, e);
                        continue;
                    }
                };

                match wallet_command(&mut cli, wallet, command) {
                    Ok(output) => {
                        for line in output {
                            if line != ">" {
                                println!("{}", line);
                            }
                        }
                    }
                    Err(err) => {
                        println!(
                            "{}: error in command to wallet {}: {}",
                            line_num, wallet, err
                        );
                        continue;
                    }
                }
            }

            "validator" => {
                let (validator, command) = match line.split_once(":") {
                    Some(res) => res,
                    None => {
                        println!(
                            "{}: validator command requires a validator ID and a command, \
                                  separated by :",
                            line_num
                        );
                        continue;
                    }
                };
                let command = command.trim();
                let validator = match validator.parse() {
                    Ok(w) => w,
                    Err(e) => {
                        println!("{}: validator ID must be an integer ({})", line_num, e);
                        continue;
                    }
                };

                let (command, rest) = command.split_once(" ").unwrap_or((command, ""));
                match validator_command(&mut cli, validator, command, rest) {
                    Ok(output) => {
                        for line in output {
                            println!("{}", line);
                        }
                    }
                    Err(err) => {
                        println!(
                            "{}: error in command to validator {}: {}",
                            line_num, validator, err
                        );
                        continue;
                    }
                }
            }

            _ => {
                println!("unrecognized command `{}' on line {}", command, line_num);
                continue;
            }
        }
    }
}

fn wallet_command(
    cli: &mut CliClient,
    wallet: usize,
    command: &str,
) -> Result<Vec<String>, String> {
    match command {
        "open" => {
            cli.open(wallet)?;
            Ok(cli.last_output().cloned().collect())
        }
        "close" => {
            cli.close(wallet)?;
            Ok(Vec::new())
        }
        _ => {
            cli.command(wallet, command)?;
            Ok(cli.last_output().cloned().collect())
        }
    }
}

fn validator_command(
    cli: &mut CliClient,
    validator: usize,
    command: &str,
    args: &str,
) -> Result<Vec<String>, String> {
    match command {
        "open" => {
            cli.open_validator(validator)?;
            Ok(Vec::new())
        }
        "close" => {
            cli.close_validator(validator)?;
            Ok(Vec::new())
        }
        "query" => {
            let v = cli.validator(validator)?;
            let res: serde_json::Value = block_on(
                surf::get(format!("http://{}:{}/{}", v.hostname(), v.port(), args)).recv_json(),
            )
            .map_err(|err| err.to_string())?;
            let output = serde_json::to_string_pretty(&res).map_err(|err| err.to_string())?;
            Ok(vec![output])
        }
        _ => Err(format!("unknown command {}", command)),
    }
}
