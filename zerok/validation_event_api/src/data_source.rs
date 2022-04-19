use seahorse::events::LedgerEvent;
use zerok_lib::ledger::EspressoLedger;

pub trait LedgerEventDataSource {
    type EventIterType: Iterator;
    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType;
}
