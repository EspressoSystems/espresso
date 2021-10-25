use aead::{Aead, NewAead};
use aes::{Aes256, NewBlockCipher};
use aes_gcm_siv::{aead, Nonce};
use rand_chacha::rand_core::{CryptoRng, RngCore};
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::marker::PhantomPinned;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use zeroize::Zeroize;

type Aes = Aes256;
type AesGcmSiv = aes_gcm_siv::AesGcmSiv<Aes>;

#[derive(Debug, Snafu)]
pub enum Error {
    AesError {
        #[snafu(source(false))]
        source: aead::Error,
    },
    ArgonError {
        #[snafu(source(false))]
        source: argon2::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

pub type Salt = [u8; 32];

type InnerKey = aes_gcm_siv::Key<<Aes as NewBlockCipher>::KeySize>;

// A !Unpin wrapper around a secret S. 
//
// This type, when wrapped in a Pin<>, can be used to prevent a secret from being moved. Ensuring
// that a secret only has one location in memory for the duration of its life can reduce the risk of
// the compiler leaving unreachable, implicit copies of the secret scattered around memory.
//
// This is especially useful when S is zeroizing on drop.
#[derive(Clone, Default)]
struct Pinned<S> {
    secret: S,
    _pin: PhantomPinned,
}

impl<S> Pinned<S> {
    fn new(secret: S) -> Self {
        Self {
            secret,
            _pin: PhantomPinned::default(),
        }
    }
}

impl<S> Deref for Pinned<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.secret
    }
}

impl<S> DerefMut for Pinned<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.secret
    }
}

// A secret key that zeroes its memory when dropped.
#[derive(Clone, Default, Zeroize)]
#[zeroize(drop)]
struct ZeroizingKey(InnerKey);

// A wrapper around a pinned, zeroizing secret key.
#[derive(Clone)]
pub struct Key(Pin<Box<Pinned<ZeroizingKey>>>);

impl Key {
    pub fn from_password(
        rng: &mut (impl RngCore + CryptoRng),
        password: &[u8],
    ) -> Result<(Self, Salt)> {
        let mut salt = Salt::default();
        rng.fill_bytes(&mut salt);
        let key = Self::from_password_and_salt(password, &salt)?;
        Ok((key, salt))
    }

    pub fn from_password_and_salt(password: &[u8], salt: &[u8]) -> Result<Self> {
        let config = argon2::Config {
            hash_length: Self::size() as u32,
            ..Default::default()
        };
        let mut hash = argon2::hash_raw(password, salt, &config)
            .map_err(|source| Error::ArgonError { source })?;

        // Construct the key in an unpinned Box first, so we can write to the underlying memory
        // safely. We will pin it once we have written the key, and we're not going to move out in
        // the meantime.
        let mut key = Box::new(Pinned::<ZeroizingKey>::default());
        for (src, dst) in hash.iter().zip(&mut key.0) {
            *dst = *src;
        }
        // We just copied the hash into the secret key, so the data in the hash is now a secret. We
        // need to zero it. If only argon2 had an in-place mode, this wouldn't be necessary.
        hash.zeroize();

        // Convert the Boxed key into a Pin<Box<_>>
        Ok(Self(key.into()))
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut key = Box::new(Pinned::<ZeroizingKey>::default());
        rng.fill_bytes(&mut key.0);
        Self(key.into())
    }

    fn size() -> usize {
        InnerKey::default().len()
    }

    fn inner(&self) -> &InnerKey {
        &self.0.0
    }
}

#[derive(Clone)]
pub struct Cipher<Rng: CryptoRng = ChaChaRng> {
    // AesGcmSiv implements Clone itself, but using Arc prevents the clone impl for Cipher from
    // making in-memory copies of the underlying cipher, which is important for security because the
    // cipher contains data derived from the secret key. We pin the target of the pointer for the
    // same reason: to try to prevent the compiler from making temporary copies in memory.
    //
    // Note that this effort at security is not complete. We should also:
    //  * zero out the one in-memory copy we do have when all clones of a cipher are dropped.
    //    However, AesGcmSiv does not yet implement Zeroize. See https://github.com/RustCrypto/AEADs/issues/65.
    //  * pin the page where the AesGcmSiv is stored in memory to prevent the OS from making copies
    //    in swap space
    aes: Pin<Arc<Pinned<AesGcmSiv>>>,
    rng: Rng,
}

impl<Rng: RngCore + CryptoRng> Cipher<Rng> {
    pub fn new(key: &Key, rng: Rng) -> Self {
        Self {
            aes: Arc::pin(Pinned::new(AesGcmSiv::new(key.inner()))),
            rng,
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<CipherText> {
        let mut nonce = Nonce::default();
        self.rng.fill_bytes(&mut nonce);

        Ok(CipherText {
            bytes: self
                .aes
                .encrypt(&nonce, plaintext)
                .map_err(|source| Error::AesError { source })?,
            nonce,
        })
    }

    pub fn decrypt(&self, ciphertext: &CipherText) -> Result<Vec<u8>> {
        self.aes
            .decrypt(&ciphertext.nonce, ciphertext.bytes.as_slice())
            .map_err(|source| Error::AesError { source })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CipherText {
    bytes: Vec<u8>,
    nonce: Nonce,
}
