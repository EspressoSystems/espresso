use super::hd;
use crate::util::canonical::{deserialize_canonical_bytes, CanonicalBytes};
use ark_serialize::*;
use chacha20::{cipher, ChaCha20};
use cipher::{NewCipher, StreamCipher};
use generic_array::GenericArray;
pub use hd::Salt;
use hmac::{crypto_mac::MacError, Hmac, Mac, NewMac};
use rand_chacha::rand_core::{CryptoRng, RngCore};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
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
/// SHA3-256 as an HMAC.
///
/// It requires an entire sub-tree of the HD key structure, as it generates separate keys for
/// encryption and authentication for each message it encrypts.
#[derive(Clone)]
pub struct Cipher<Rng: CryptoRng = ChaChaRng> {
    hmac_key: hd::Key,
    cipher_keyspace: hd::KeyTree,
    rng: Rng,
}

impl<Rng: RngCore + CryptoRng> Cipher<Rng> {
    pub fn new(keys: hd::KeyTree, rng: Rng) -> Self {
        Self {
            hmac_key: keys.derive_key("hmac".as_bytes()),
            cipher_keyspace: keys.derive_sub_tree("cipher".as_bytes()),
            rng,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<CipherText> {
        // Generate a random nonce unique to this message and use it to derive the encryption key.
        let mut nonce = Nonce::default();
        self.rng.fill_bytes(&mut nonce);
        let cipher_key = self.cipher_key(&nonce);

        // Encrypt the plaintext by applying the keystream.
        let mut bytes = plaintext.to_vec();
        self.apply(&cipher_key, &mut bytes)?;

        // Add the authentication tag.
        let hmac = self
            .hmac(&self.hmac_key, &nonce, &bytes)
            .finalize()
            .into_bytes()
            .into();
        Ok(CipherText { bytes, nonce, hmac })
    }

    pub fn decrypt(&self, ciphertext: &CipherText) -> Result<Vec<u8>> {
        // Verify the HMAC before doing anything else.
        self.hmac(&self.hmac_key, &ciphertext.nonce, &ciphertext.bytes)
            .verify(&ciphertext.hmac)
            .map_err(|source| Error::InvalidHmac { source })?;

        // If authentication succeeded, re-generate the key which was used to encrypt and
        // authenticate this message, based on the associated nonce, and use it to decrypt the
        // ciphertext.
        let cipher_key = self.cipher_key(&ciphertext.nonce);
        let mut bytes = ciphertext.bytes.clone();
        self.apply(&cipher_key, &mut bytes)?;
        Ok(bytes)
    }

    fn apply(&self, key: &hd::Key, data: &mut [u8]) -> Result<()> {
        // We don't need a random nonce for the stream cipher, since we are initializing it with a
        // new key for each message.
        let key = <&GenericArray<u8, _>>::from(key.as_bytes().open_secret());
        let mut cipher = ChaCha20::new(key, &chacha20::Nonce::default());
        cipher
            .try_apply_keystream(data)
            .map_err(|source| Error::DataTooLong { source })?;
        Ok(())
    }

    fn hmac(&self, hmac_key: &hd::Key, nonce: &[u8], ciphertext: &[u8]) -> Hmac<Sha3_256> {
        let mut hmac = Hmac::<Sha3_256>::new_from_slice(hmac_key.as_bytes().open_secret()).unwrap();
        hmac.update(nonce);
        // Note: the ciphertext must be the last field, since it is variable sized and we do not
        // explicitly commit to its length. If we included another variably sized field after the
        // ciphertext, an attacker could alter the field boundaries to create a semantically
        // different message with the same MAC.
        hmac.update(ciphertext);
        hmac
    }

    fn cipher_key(&self, nonce: &[u8]) -> hd::Key {
        self.cipher_keyspace.derive_key(nonce)
    }
}

// We serialize the ciphertext-and-metadata structure using a custom ark_serialize implementation in
// order to derive an unstructured, byte-oriented serialization format that does not look like a
// struct. This provides a few nice properties:
//  * the serialized byte stream should truly be indistinguishable from random data, since it is
//    just a concatenation of pseudo-random fields
//  * the deserialization process is extremely simple, and allows us to access and verify the MAC
//    before doing anything more than read in the encrypted file
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "CanonicalBytes", into = "CanonicalBytes")]
pub struct CipherText {
    hmac: [u8; 32],
    nonce: Nonce,
    bytes: Vec<u8>,
}
deserialize_canonical_bytes!(CipherText);

impl CanonicalSerialize for CipherText {
    fn serialize<W: Write>(&self, mut w: W) -> std::result::Result<(), SerializationError> {
        w.write_all(&self.hmac).map_err(SerializationError::from)?;
        w.write_all(&self.nonce).map_err(SerializationError::from)?;
        // We serialize the only variably sized field, the ciphertext itself, last, so that we don't
        // have to serialize its length (which would break the apparent pseudo-randomness of the
        // serialized byte stream). We can deserialize it by simply reading until the end of the
        // byte stream once we've deserialized the fixed-width fields.
        w.write_all(&self.bytes).map_err(SerializationError::from)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        self.nonce.len() + self.hmac.len() + self.bytes.len()
    }
}

impl CanonicalDeserialize for CipherText {
    fn deserialize<R: Read>(mut r: R) -> std::result::Result<Self, SerializationError> {
        // Deserialize the known-size fields.
        let mut hmac = <[u8; 32]>::default();
        r.read_exact(&mut hmac).map_err(SerializationError::from)?;
        let mut nonce = Nonce::default();
        r.read_exact(&mut nonce).map_err(SerializationError::from)?;
        // The ciphertext is whatever happens to be left in the input stream.
        let bytes = r
            .bytes()
            .collect::<std::result::Result<_, _>>()
            .map_err(SerializationError::from)?;
        Ok(Self { nonce, hmac, bytes })
    }
}
