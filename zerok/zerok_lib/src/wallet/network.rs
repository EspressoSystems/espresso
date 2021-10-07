use super::WalletBackend;
use super::persistence::AtomicWalletStorage;

pub struct NetworkBackend<'a> {
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> WalletBackend<'a> for NetworkBackend<'a> {
    type Storage = AtomicWalletStorage;
}