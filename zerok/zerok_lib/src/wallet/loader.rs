use super::{encryption, hd, reader, EncryptionError, KeyError, WalletError};
use encryption::{Cipher, CipherText, Salt};
use hd::KeyTree;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaChaRng,
};
use reader::Reader;
use serde::{Deserialize, Serialize};
use snafu::ResultExt;
use std::path::PathBuf;

pub trait WalletLoader {
    type Meta; // Metadata stored in plaintext and used by the loader to access the wallet.
    fn location(&self) -> PathBuf;
    fn create(&mut self) -> Result<(Self::Meta, KeyTree), WalletError>;
    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError>;
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

pub struct Loader {
    method: LoadMethod,
    encrypted: bool,
    dir: PathBuf,
    rng: ChaChaRng,
    reader: Reader,
}

impl Loader {
    pub fn new(method: LoadMethod, encrypted: bool, dir: PathBuf, reader: Reader) -> Self {
        Self {
            method,
            encrypted,
            dir,
            reader,
            rng: ChaChaRng::from_entropy(),
        }
    }

    fn create_from_password(&mut self) -> Result<(KeyTree, Salt), WalletError> {
        let password = if self.encrypted {
            loop {
                let password = self.reader.read_password("Create password: ")?;
                let confirm = self.reader.read_password("Retype password: ")?;
                if password == confirm {
                    break password;
                } else {
                    println!("Passwords do not match.");
                }
            }
        } else {
            self.dummy_password()
        };
        KeyTree::from_password(&mut self.rng, password.as_bytes()).context(KeyError)
    }

    fn load_from_password(&self, meta: &LoaderMetadata) -> Result<KeyTree, WalletError> {
        let password = if meta.encrypted {
            self.reader.read_password("Enter password: ")?
        } else {
            self.dummy_password()
        };
        KeyTree::from_password_and_salt(password.as_bytes(), &meta.salt).context(KeyError)
    }

    fn dummy_password(&self) -> String {
        String::new()
    }

    fn create_from_mnemonic(&mut self) -> Result<KeyTree, WalletError> {
        if self.encrypted {
            println!(
                "Your wallet will be identified by a secret mnemonic phrase. This phrase will \
                 allow you to recover your wallet if you lose access to it. Anyone who has access \
                 to this phrase will be able to view and spend your assets. Store this phrase in a \
                 safe, private place."
            );
            'outer: loop {
                let (key, mnemonic) = KeyTree::random(&mut self.rng).context(KeyError)?;
                println!("Your mnemonic phrase will be:");
                println!("{}", mnemonic);
                'inner: loop {
                    println!("1) Accept phrase and create wallet");
                    println!("2) Generate a new phrase");
                    println!("3) Manually enter a mnemonic (use this to recover a lost wallet)");
                    match self.reader.read_line() {
                        Some(line) => match line.as_str().trim() {
                            "1" => return Ok(key),
                            "2" => continue 'outer,
                            "3" => {
                                let mnemonic =
                                    self.reader.read_password("Enter mnemonic phrase: ")?;
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
        } else {
            KeyTree::from_mnemonic(self.dummy_mnemonic().as_bytes()).context(KeyError)
        }
    }

    fn load_from_mnemonic(&self, meta: &LoaderMetadata) -> Result<KeyTree, WalletError> {
        let mnemonic = if meta.encrypted {
            self.reader.read_password("Enter mnemonic phrase: ")?
        } else {
            self.dummy_mnemonic()
        };
        KeyTree::from_mnemonic(mnemonic.as_bytes()).context(KeyError)
    }

    fn dummy_mnemonic(&self) -> String {
        mnemonic::to_string(&[])
    }
}

static KEY_CHECK_SUB_TREE: &str = "key_check";

impl WalletLoader for Loader {
    type Meta = LoaderMetadata;

    fn location(&self) -> PathBuf {
        self.dir.clone()
    }

    fn create(&mut self) -> Result<(LoaderMetadata, KeyTree), WalletError> {
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

    fn load(&mut self, meta: &Self::Meta) -> Result<KeyTree, WalletError> {
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
            } else {
                println!("Sorry, that's incorrect.");
            }
        };

        Ok(key)
    }
}
