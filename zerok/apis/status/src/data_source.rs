use crate::query_data::ValidatorStatus;

pub trait StatusDataSource<'a> {
    fn get_validator_status(self) -> &'a ValidatorStatus;
}
