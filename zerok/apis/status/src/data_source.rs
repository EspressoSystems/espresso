use crate::query_data::ValidatorStatus;

pub trait ValidatorStatusDataSource {
    fn get_validator_status(&self) -> &ValidatorStatus;
}
