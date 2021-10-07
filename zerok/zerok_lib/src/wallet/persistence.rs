use crate::wallet::WalletStorage;
pub struct AtomicWalletStorage {}
impl<'a> WalletStorage<'a> for AtomicWalletStorage {}
