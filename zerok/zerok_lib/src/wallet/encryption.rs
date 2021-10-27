use super::hd;
use chacha20::{cipher, ChaCha20};
use cipher::{NewCipher, StreamCipher};
pub use hd::Salt;
use hmac::{crypto_mac::MacError, Hmac, Mac, NewMac};
use rand_chacha::rand_core::{CryptoRng, RngCore};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha3::Keccak256;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    DataTooLong {
        #[snafu(source(false))]
        source: cipher::errors::LoopError,
    },
    ArgonError {
        #[snafu(source(false))]
        source: argon2::Error,
    },
    InvalidHmac {
        #[snafu(source(false))]
        source: MacError,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

pub type Nonce = [u8; 32];

/// An authenticating stream cipher.
///
/// This implementation uses the encrypt-then-MAC strategy, with ChaCha20 as the stream cipher and
/// Keccak-256 as an HMAC.
///
/// It requires an entire sub-tree of the HD key structure, as it generates separate keys for
/// encryption and authentication for each message it encrypts.
#[derive(Clone)]
pub struct Cipher<Rng: CryptoRng = ChaChaRng> {
    keys: hd::KeyTree,
    rng: Rng,
}

impl<Rng: RngCore + CryptoRng> Cipher<Rng> {
    pub fn new(keys: hd::KeyTree, rng: Rng) -> Self {
        Self { keys, rng }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<CipherText> {
        // Generate a random nonce unique to this message and use it to derive encryption and
        // authentication keys, also unique to this message.
        let mut nonce = Nonce::default();
        self.rng.fill_bytes(&mut nonce);
        let (cipher_key, hmac_key) = self.gen_keys(&nonce);

        // Encrypt the plaintext by applying the keystream.
        let mut bytes = plaintext.to_vec();
        self.apply(&cipher_key, &mut bytes)?;

        // Add the authentication tag.
        let hmac = self
            .hmac(&hmac_key, &nonce, &bytes)
            .finalize()
            .into_bytes()
            .to_vec();
        Ok(CipherText { bytes, nonce, hmac })
    }

    pub fn decrypt(&self, ciphertext: &CipherText) -> Result<Vec<u8>> {
        // Re-generate the keys which were used to encrypt and authenticate this message, based on
        // the associated nonce.
        let (cipher_key, hmac_key) = self.gen_keys(&ciphertext.nonce);

        // Verify the HMAC _before_ decrypting.
        self.hmac(&hmac_key, &ciphertext.nonce, &ciphertext.bytes)
            .verify(&ciphertext.hmac)
            .map_err(|source| Error::InvalidHmac { source })?;

        // If authentication succeeded, decrypt the ciphertext.
        let mut bytes = ciphertext.bytes.clone();
        self.apply(&cipher_key, &mut bytes)?;
        Ok(bytes)
    }

    fn apply(&self, key: &hd::Key, data: &mut [u8]) -> Result<()> {
        // We don't need a random nonce for the stream cipher, since we are initializing it with a
        // new key for each message.
        let mut cipher = ChaCha20::new(key.as_bytes().into(), &chacha20::Nonce::default());
        cipher
            .try_apply_keystream(data)
            .map_err(|source| Error::DataTooLong { source })?;
        Ok(())
    }

    fn hmac(&self, key: &hd::Key, nonce: &[u8], ciphertext: &[u8]) -> Hmac<Keccak256> {
        let mut hmac = Hmac::<Keccak256>::new_from_slice(key.as_bytes()).unwrap();
        hmac.update(key.as_bytes());
        hmac.update(nonce);
        // Note: the ciphertext must be the last field, since it is variable sized and we do not
        // explicitly commit to its length. If we included another variably sized field after the
        // ciphertext, an attacker could alter the field boundaries to create a semantically
        // different message with the same MAC.
        hmac.update(ciphertext);
        hmac
    }

    fn gen_keys(&self, nonce: &[u8]) -> (hd::Key, hd::Key) {
        // Derive keys (from their own sub-tree) for the cipher and the HMAC.
        let keys = self.keys.derive_sub_tree(nonce);
        (
            keys.derive_key("cipher".as_bytes()),
            keys.derive_key("hmac".as_bytes()),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CipherText {
    bytes: Vec<u8>,
    nonce: Nonce,
    hmac: Vec<u8>,
}
