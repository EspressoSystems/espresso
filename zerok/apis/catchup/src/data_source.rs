use seahorse::events::LedgerEvent;
use zerok_lib::ledger::EspressoLedger;

pub trait CatchUpDataSource {
    type EventIterType: AsRef<[LedgerEvent<EspressoLedger>]>;

    fn get_nth_event_iter(&self, n: usize) -> Self::EventIterType;
}

pub trait UpdateCatchUpData {
    type Error;

    fn append_events(
        &mut self,
        events: &mut Vec<LedgerEvent<EspressoLedger>>,
    ) -> Result<(), Self::Error>;
}
