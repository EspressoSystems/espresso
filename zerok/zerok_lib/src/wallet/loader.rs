use super::{encryption, hd, reader, EncryptionError, KeyError, WalletError};
use encryption::{Cipher, CipherText, Salt};
use hd::KeyTree;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use reader::Reader;
use reef::Ledger;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::path::PathBuf;

pub trait WalletLoader<L: Ledger> {
    type Meta; // Metadata stored in plaintext and used by the loader to access the wallet.
    fn location(&self) -> PathBuf;
    fn create(&mut self) -> Result<(Self::Meta, KeyTree), WalletError<L>>;
    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError<L>>;
}

pub enum LoadMethod {
    Password,
    Mnemonic,
}

// Metadata about a wallet which is always stored unencrypted, so we can report some basic
// information about the wallet without decrypting. This also aids in the key derivation process.
//
// DO NOT put secrets in here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoaderMetadata {
    encrypted: bool,
    salt: Salt,
    // Encrypted random bytes. This will only decrypt successfully if we have the correct
    // password/mnemonic, so we can use it as a quick check that the user entered the right thing.
    check_data: CipherText,
}

enum LoaderInput {
    User(Reader),
    Literal(String),
}

impl LoaderInput {
    fn create_password<L: Ledger>(&self) -> Result<String, WalletError<L>> {
        match self {
            Self::User(reader) => loop {
                let password = reader.read_password("Create password: ")?;
                let confirm = reader.read_password("Retype password: ")?;
                if password == confirm {
                    return Ok(password);
                } else {
                    println!("Passwords do not match.");
                }
            },

            Self::Literal(s) => Ok(s.clone()),
        }
    }

    fn read_password<L: Ledger>(&self) -> Result<String, WalletError<L>> {
        match self {
            Self::User(reader) => reader.read_password("Enter password: "),
            Self::Literal(s) => Ok(s.clone()),
        }
    }

    fn create_mnemonic<L: Ledger>(
        &mut self,
        rng: &mut ChaChaRng,
    ) -> Result<KeyTree, WalletError<L>> {
        match self {
            Self::User(reader) => {
                println!(
                    "Your wallet will be identified by a secret mnemonic phrase. This phrase will \
                     allow you to recover your wallet if you lose access to it. Anyone who has access \
                     to this phrase will be able to view and spend your assets. Store this phrase in a \
                     safe, private place."
                );
                'outer: loop {
                    let (key, mnemonic) = KeyTree::random(rng).context(KeyError)?;
                    println!("Your mnemonic phrase will be:");
                    println!("{}", mnemonic);
                    'inner: loop {
                        println!("1) Accept phrase and create wallet");
                        println!("2) Generate a new phrase");
                        println!(
                            "3) Manually enter a mnemonic (use this to recover a lost wallet)"
                        );
                        match reader.read_line() {
                            Some(line) => match line.as_str().trim() {
                                "1" => return Ok(key),
                                "2" => continue 'outer,
                                "3" => {
                                    let mnemonic =
                                        reader.read_password("Enter mnemonic phrase: ")?;
                                    return KeyTree::from_mnemonic(mnemonic.as_bytes())
                                        .context(KeyError);
                                }
                                _ => continue 'inner,
                            },
                            None => {
                                return Err(WalletError::Failed {
                                    msg: String::from("eof"),
                                })
                            }
                        }
                    }
                }
            }

            Self::Literal(s) => KeyTree::from_mnemonic(s.as_bytes()).context(KeyError),
        }
    }

    fn read_mnemonic<L: Ledger>(&self) -> Result<String, WalletError<L>> {
        match self {
            Self::User(reader) => reader.read_password("Enter mnemonic phrase: "),
            Self::Literal(s) => Ok(s.clone()),
        }
    }

    fn interactive(&self) -> bool {
        match self {
            Self::User(..) => true,
            Self::Literal(..) => false,
        }
    }
}

pub struct Loader {
    method: LoadMethod,
    encrypted: bool,
    dir: PathBuf,
    rng: ChaChaRng,
    input: LoaderInput,
}

impl Loader {
    pub fn new(method: LoadMethod, encrypted: bool, dir: PathBuf, reader: Reader) -> Self {
        Self {
            method,
            encrypted,
            dir,
            input: LoaderInput::User(reader),
            rng: ChaChaRng::from_entropy(),
        }
    }

    pub fn from_mnemonic(mnemonic: String, encrypted: bool, dir: PathBuf) -> Self {
        Self {
            method: LoadMethod::Mnemonic,
            encrypted,
            dir,
            input: LoaderInput::Literal(mnemonic),
            rng: ChaChaRng::from_entropy(),
        }
    }

    fn create_from_password<L: Ledger>(&mut self) -> Result<(KeyTree, Salt), WalletError<L>> {
        let password = if self.encrypted {
            self.input.create_password()?
        } else {
            self.dummy_password()
        };
        KeyTree::from_password(&mut self.rng, password.as_bytes()).context(KeyError)
    }

    fn load_from_password<L: Ledger>(
        &self,
        meta: &LoaderMetadata,
    ) -> Result<KeyTree, WalletError<L>> {
        let password = if meta.encrypted {
            self.input.read_password()?
        } else {
            self.dummy_password()
        };
        KeyTree::from_password_and_salt(password.as_bytes(), &meta.salt).context(KeyError)
    }

    fn dummy_password(&self) -> String {
        String::new()
    }

    fn create_from_mnemonic<L: Ledger>(&mut self) -> Result<KeyTree, WalletError<L>> {
        if self.encrypted {
            self.input.create_mnemonic(&mut self.rng)
        } else {
            KeyTree::from_mnemonic(self.dummy_mnemonic().as_bytes()).context(KeyError)
        }
    }

    fn load_from_mnemonic<L: Ledger>(
        &self,
        meta: &LoaderMetadata,
    ) -> Result<KeyTree, WalletError<L>> {
        let mnemonic = if meta.encrypted {
            self.input.read_mnemonic()?
        } else {
            self.dummy_mnemonic()
        };
        KeyTree::from_mnemonic(mnemonic.as_bytes()).context(KeyError)
    }

    fn dummy_mnemonic(&self) -> String {
        mnemonic::to_string(&[0u8; 32])
    }
}

static KEY_CHECK_SUB_TREE: &str = "key_check";

impl<L: Ledger> WalletLoader<L> for Loader {
    type Meta = LoaderMetadata;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(LoaderMetadata, KeyTree), WalletError<L>> {
        let (key, salt) = match self.method {
            LoadMethod::Password => self.create_from_password()?,
            LoadMethod::Mnemonic => (self.create_from_mnemonic()?, Salt::default()),
        };

        // Encrypt some random data, which we can decrypt on load to check the derived key.
        let mut check_data = [0; 32];
        self.rng.fill_bytes(&mut check_data);
        let check_data = Cipher::new(
            key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
            ChaChaRng::from_rng(&mut self.rng).unwrap(),
        )
        .encrypt(&check_data)
        .context(EncryptionError)?;

        let meta = LoaderMetadata {
            encrypted: self.encrypted,
            salt,
            check_data,
        };
        Ok((meta, key))
    }

    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError<L>> {
        if !self.encrypted {
            return Err(WalletError::Failed {
                msg: String::from(
                    "option --unencrypted is not allowed when loading an existing wallet",
                ),
            });
        }

        let key = loop {
            // Generate the key and check that we can use it to decrypt `check_data`. If we can't,
            // the key is wrong.
            let key = match self.method {
                LoadMethod::Password => self.load_from_password(meta)?,
                LoadMethod::Mnemonic => self.load_from_mnemonic(meta)?,
            };
            if Cipher::new(
                key.derive_sub_tree(KEY_CHECK_SUB_TREE.as_bytes()),
                ChaChaRng::from_rng(&mut self.rng).unwrap(),
            )
            .decrypt(&meta.check_data)
            .is_ok()
            {
                break key;
            } else if !meta.encrypted {
                // If the default password doesn't work, then the password_check data must be
                // corrupted or encrypted with a non-default password. If the metadata claims it is
                // unencrypted, than the metadata is corrupt (either in the `encrypted` field, the
                // `password_check` field, or both).
                return Err(WalletError::Failed {
                    msg: String::from("wallet metadata is corrupt"),
                });
            } else if self.input.interactive() {
                println!("Sorry, that's incorrect.");
            } else {
                return Err(WalletError::Failed {
                    msg: String::from("incorrect authentication"),
                });
            }
        };

        Ok(key)
    }
}
