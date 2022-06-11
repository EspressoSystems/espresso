use crate::query_data::ValidatorStatus;
use core::convert::From;

pub trait StatusDataSource<'a> {
    fn get_validator_status(self) -> &'a ValidatorStatus;
}

pub trait UpdateStatusData {
    type Error;
    fn set_status(&mut self, status: ValidatorStatus) -> Result<(), Self::Error>;
    fn edit_status<U, F>(&mut self, op: F) -> Result<(), Self::Error>
    where
        F: FnOnce(&mut ValidatorStatus) -> Result<(), U>,
        Self::Error: From<U>;
}
