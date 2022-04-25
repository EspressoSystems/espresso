use seahorse::events::LedgerEvent;
use zerok_lib::ledger::EspressoLedger;

pub trait LedgerEventDataSource {
    type EventIterType: Iterator<Item = LedgerEvent<EspressoLedger>>;

    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType;
}
