// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.

use crate::query_data::ValidatorStatus;
use core::convert::From;
use std::error::Error;
use std::fmt::Debug;

pub trait StatusDataSource {
    fn get_validator_status(&self) -> &ValidatorStatus;
    fn get_location(&self) -> &Option<String>;
}

pub trait UpdateStatusData {
    type Error: Error + Debug;
    fn set_status(&mut self, status: ValidatorStatus) -> Result<(), Self::Error>;
    fn edit_status<U, F>(&mut self, op: F) -> Result<(), Self::Error>
    where
        F: FnOnce(&mut ValidatorStatus) -> Result<(), U>,
        Self::Error: From<U>;
}
