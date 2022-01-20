use super::WalletError;
use reef::Ledger;
use rpassword::prompt_password_stdout;

pub enum Reader {
    Interactive(rustyline::Editor<()>),
    Automated,
}

impl Reader {
    pub fn new(interactive: bool) -> Self {
        if interactive {
            Self::Interactive(rustyline::Editor::<()>::new())
        } else {
            Self::Automated
        }
    }

    pub fn read_password<L: Ledger>(&self, prompt: &str) -> Result<String, WalletError<L>> {
        match self {
            Self::Interactive(_) => {
                prompt_password_stdout(prompt).map_err(|err| WalletError::Failed {
                    msg: err.to_string(),
                })
            }
            Self::Automated => {
                println!("{}", prompt);
                let mut password = String::new();
                match std::io::stdin().read_line(&mut password) {
                    Ok(_) => Ok(password),
                    Err(err) => Err(WalletError::Failed {
                        msg: err.to_string(),
                    }),
                }
            }
        }
    }

    pub fn read_line(&mut self) -> Option<String> {
        let prompt = "> ";
        match self {
            Self::Interactive(editor) => editor.readline(prompt).ok(),
            Self::Automated => {
                println!("{}", prompt);
                let mut line = String::new();
                match std::io::stdin().read_line(&mut line) {
                    Ok(0) => {
                        // EOF
                        None
                    }
                    Err(_) => None,
                    Ok(_) => Some(line),
                }
            }
        }
    }
}
