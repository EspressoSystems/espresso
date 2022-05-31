use seahorse::events::LedgerEvent;
use zerok_lib::ledger::EspressoLedger;

pub trait CatchUpDataSource {
    type EventIterType: AsRef<[LedgerEvent<EspressoLedger>]>;

    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType;
}
