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
        Self { secret, _pin: PhantomPinned::default() }
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

#[derive(Clone, Debug)]
pub struct Secret<S: Zeroize>(Pin<Box<Pinned<Zeroizing<S>>>>);

impl<S: Zeroize + Default> Secret<S> {
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
        SecretBuilder(Box::new(Pinned::new(Zeroizing::new(S::default()))))
    }
}

impl<S: Zeroize> Deref for Secret<S> {
    type Target = S;

    fn deref(&self) -> &S {
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
