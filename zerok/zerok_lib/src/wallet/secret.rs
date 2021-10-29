////////////////////////////////////////////////////////////////////////////////
// Data structures for holding secrets in memory.
//
// This module defines a data structure `Secret<S>` which can be used to
// discourage the Rust compiler from making implicit in-memory copies of a
// secret `S`.
//

use std::convert::{AsMut, AsRef};
use std::marker::PhantomPinned;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use zeroize::{Zeroize, Zeroizing};

// A !Unpin wrapper around a secret S.
//
// This type, when wrapped in a Pin<>, can be used to prevent a secret from being moved. Ensuring
// that a secret only has one location in memory for the duration of its life can reduce the risk of
// the compiler leaving unreachable, implicit copies of the secret scattered around memory.
//
// This is especially useful when S is zeroizing on drop.
#[derive(Clone, Debug, Default)]
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

/// Provide a default value for use when constructing secrets.
///
/// Constructing a secret requires a default value, because we initialize the memory location where
/// the secret will go before constructing the secret, to avoid constructing a secret value and then
/// moving it around memory.
///
/// Some types that we want to use as secrets do not have a Default implementation (e.g. [T; 64]) so
/// we use this trait instead in order to add our own implementations without running into the
/// orphan rule.
pub trait SecretDefault {
    fn secret_default() -> Self;
}

macro_rules! secret_default_from_default {
    ($($t:ty),*) => {
        $(
            impl SecretDefault for $t {
                fn secret_default() -> Self {
                    Self::default()
                }
            }
        )*
    };
}

secret_default_from_default!(u8, u16, u32, u64, i8, i16, i32, i64);

macro_rules! secret_default_arrays {
    ($($n:expr),*) => {
        $(
            impl<S: Copy + SecretDefault> SecretDefault for [S; $n] {
                fn secret_default() -> Self {
                    [S::secret_default(); $n]
                }
            }
        )*
    }
}

secret_default_arrays!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
);

#[derive(Clone, Debug)]
pub struct Secret<S: Zeroize>(Pin<Box<Pinned<Zeroizing<S>>>>);

impl<S: Zeroize + SecretDefault> Secret<S> {
    /// Construct a pinned, zeroizing secret from a secret value.
    ///
    /// The value `val` is zeroed after it is used to initialize the new secret.
    pub fn new(val: &mut S) -> Self {
        let mut builder = Self::build();
        std::mem::swap(builder.as_mut(), val);
        val.zeroize();
        builder.finalize()
    }

    /// Incrementally build a secret.
    ///
    /// The returned `SecretBuilder` is a pointer to the final location the secret will occupy in
    /// memory. It can be used to obtain a mutable reference to that memory and initialize the
    /// secret in-place. Calling `finalize()` on the builder will pin it in memory and freeze its
    /// value.
    ///
    /// The caller should take care not to copy or move out of the value after it has been
    /// initialized with secret data but before it has been pinned.
    pub fn build() -> SecretBuilder<S> {
        SecretBuilder(Box::new(Pinned::new(Zeroizing::new(S::secret_default()))))
    }

    /// Access the secret data directly.
    ///
    /// Be very careful when using this method. Copying out of the returned reference can cause
    /// copies of secret data to be left un-zeroed in memory. This should only be used when passing
    /// a secret to an API which knows that it references secret data and which which ostensibly has
    /// its own scheme for dealing with in-memory secrets. For example, this can be used when
    /// passing as secret key to a MAC function or a cipher.
    pub fn open_secret(&self) -> &S {
        &*self.0
    }
}

pub struct SecretBuilder<S: Zeroize>(Box<Pinned<Zeroizing<S>>>);

impl<S: Zeroize> SecretBuilder<S> {
    pub fn finalize(self) -> Secret<S> {
        Secret(Pin::from(self.0))
    }
}

impl<S: Zeroize> Deref for SecretBuilder<S> {
    type Target = S;
    fn deref(&self) -> &S {
        &*self.0
    }
}

impl<S: Zeroize> DerefMut for SecretBuilder<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut *self.0
    }
}

impl<S: Zeroize> AsRef<S> for SecretBuilder<S> {
    fn as_ref(&self) -> &S {
        &*self
    }
}

impl<S: Zeroize> AsMut<S> for SecretBuilder<S> {
    fn as_mut(&mut self) -> &mut S {
        &mut *self
    }
}
