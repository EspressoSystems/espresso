////////////////////////////////////////////////////////////////////////////////
// The AAP Wallet Frontend
//
// For now, this "frontend" is simply a comand-line read-eval-print loop which
// allows the user to enter commands for a wallet interactively.
//

use std::pin::Pin;
use wallet::network::*;
use zerok_lib::{wallet};

// This works
fn _test1<'a>(mut wallet: wallet::Wallet<'a, impl 'a + wallet::WalletBackend<'a> + Send + Sync>) {
    let _: Pin<Box<dyn Send>> = Box::pin(async {
        let fut = wallet.transfer();
        let _: &dyn Send = &fut;
        fut.await.unwrap();
    });
}

// This doesn't
fn _test2<'a>(mut wallet: wallet::Wallet<'a, NetworkBackend<'a>>) {
    let _: Pin<Box<dyn Send>> = Box::pin(async {
        let fut = wallet.transfer();
        let _: &dyn Send = &fut;
        fut.await.unwrap();
    });
}

// But, NetworkBackend<'a> does satisfy all the type constraints:
fn _test3<'a>(wallet: wallet::Wallet<'a, NetworkBackend<'a>>) {
    _test1(wallet);
}

#[async_std::main]
async fn main() {
}
