// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Espresso library.
//
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU
// General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not,
// see <https://www.gnu.org/licenses/>.

use crate::{
    ledger::EspressoLedger,
    set_merkle_tree::SetMerkleProof,
    state::{state_comm::LedgerStateCommitment, Block, ElaboratedBlock, ElaboratedTransaction},
};
use fmt::{Display, Formatter};
use jf_cap::{structs::ReceiverMemo, Signature, TransactionNote};
use phaselock::PhaseLockError;
use serde::{Deserialize, Serialize};
use snafu::{ErrorCompat, IntoError, Snafu};
use std::fmt;

pub use net::*;

#[derive(Debug, Serialize, Deserialize, Snafu)]
#[non_exhaustive]
pub enum EspressoError {
    QueryService {
        source: crate::node::QueryServiceError,
    },
    Validation {
        source: crate::state::ValidationError,
    },
    #[snafu(display("{:?}", source))]
    Consensus {
        // PhaseLockError cannot be serialized. Instead, if we have to serialize this variant, we
        // will serialize Ok(err) to Err(format(err)), and when we deserialize we will at least
        // preserve the variant ConsensusError and a String representation of the underlying error.
        // Unfortunately, this means we cannot use this variant as a SNAFU error source.
        #[serde(with = "crate::state::ser_debug")]
        #[snafu(source(false))]
        source: Result<Box<PhaseLockError>, String>,
    },
    #[snafu(display("error in parameter {}: {}", param, msg))]
    Param { param: String, msg: String },
    #[snafu(display("{}", msg))]
    Internal { msg: String },
}

impl Error for EspressoError {
    fn catch_all(msg: String) -> Self {
        Self::Internal { msg }
    }

    fn status(&self) -> tide::StatusCode {
        match self {
            Self::Param { .. } => tide::StatusCode::BadRequest,
            _ => tide::StatusCode::InternalServerError,
        }
    }
}

impl From<crate::node::QueryServiceError> for EspressoError {
    fn from(source: crate::node::QueryServiceError) -> Self {
        Self::QueryService { source }
    }
}

impl From<crate::state::ValidationError> for EspressoError {
    fn from(source: crate::state::ValidationError) -> Self {
        Self::Validation { source }
    }
}

impl From<PhaseLockError> for EspressoError {
    fn from(source: PhaseLockError) -> Self {
        Self::Consensus {
            source: Ok(Box::new(source)),
        }
    }
}

impl From<serde_json::Error> for EspressoError {
    fn from(source: serde_json::Error) -> Self {
        Self::Internal {
            msg: source.to_string(),
        }
    }
}

impl From<Box<bincode::ErrorKind>> for EspressoError {
    fn from(source: Box<bincode::ErrorKind>) -> Self {
        Self::Internal {
            msg: source.to_string(),
        }
    }
}

/// Conversion from [EspressoError] to module-specific error types.
///
/// Any error type which has a catch-all variant can implement this trait and get conversions from
/// other [EspressoError] variants for free. By default, the conversion function for each variant
/// simply converts the variant to a String using the Display instance and calls the [catch_all]
/// method. If the implementing type has a variant for a specific type of error encapsulated in
/// [EspressoError], it can override the conversion function for that variant.
///
/// Having default conversion functions for each variant ensures that new error types can be added
/// to [EspressoError] without breaking existing conversions, as long as a corresponding new default
/// method is added to this trait.
///
/// [catch_all]: #tymethod.catch_all
pub trait FromError: Sized {
    fn catch_all(msg: String) -> Self;

    fn from_query_service_error(source: crate::node::QueryServiceError) -> Self {
        Self::catch_all(source.to_string())
    }

    fn from_validation_error(source: crate::state::ValidationError) -> Self {
        Self::catch_all(source.to_string())
    }

    fn from_consensus_error(source: Result<PhaseLockError, String>) -> Self {
        match source {
            Ok(err) => Self::catch_all(format!("{:?}", err)),
            Err(msg) => Self::catch_all(msg),
        }
    }

    fn from_param_error(param: String, msg: String) -> Self {
        Self::catch_all(format!("invalid request parameter {}: {}", param, msg))
    }

    fn from_espresso_error<E: Into<EspressoError>>(source: E) -> Self {
        match source.into() {
            EspressoError::QueryService { source } => Self::from_query_service_error(source),
            EspressoError::Validation { source } => Self::from_validation_error(source),
            EspressoError::Consensus { source } => {
                Self::from_consensus_error(source.map(|err| *err))
            }
            EspressoError::Param { param, msg } => Self::from_param_error(param, msg),
            EspressoError::Internal { msg } => Self::catch_all(msg),
        }
    }

    /// Convert from a generic client-side error to a specific error type.
    ///
    /// If `source` can be downcast to an [Error], it is converted to the specific type using
    /// [from_espresso_error]. Otherwise, it is converted to a [String] using [Display] and then
    /// converted to the specific type using [catch_all].
    ///
    /// [from_espresso_error]: #method.from_espresso_error
    /// [catch_all]: #tymethod.catch_all
    fn from_client_error(source: surf::Error) -> Self {
        Self::from_espresso_error(<EspressoError as Error>::from_client_error(source))
    }
}

impl FromError for EspressoError {
    fn catch_all(msg: String) -> Self {
        Self::Internal { msg }
    }

    fn from_query_service_error(source: crate::node::QueryServiceError) -> Self {
        Self::QueryService { source }
    }

    fn from_validation_error(source: crate::state::ValidationError) -> Self {
        Self::Validation { source }
    }

    fn from_consensus_error(source: Result<PhaseLockError, String>) -> Self {
        Self::Consensus {
            source: source.map(Box::new),
        }
    }

    fn from_param_error(param: String, msg: String) -> Self {
        Self::Param { param, msg }
    }

    fn from_espresso_error<E: Into<EspressoError>>(source: E) -> Self {
        source.into()
    }
}

impl FromError for seahorse::KeystoreError<EspressoLedger> {
    fn catch_all(msg: String) -> Self {
        Self::Failed { msg }
    }

    fn from_query_service_error(source: crate::node::QueryServiceError) -> Self {
        source.into()
    }

    fn from_validation_error(source: crate::state::ValidationError) -> Self {
        Self::InvalidBlock { source }
    }

    fn from_consensus_error(source: Result<PhaseLockError, String>) -> Self {
        match source {
            Ok(err) => Self::catch_all(err.to_string()),
            Err(msg) => Self::catch_all(msg),
        }
    }
}

/// Context for embedding network client errors into specific error types.
///
/// This type implements the [IntoError] trait from SNAFU, so it can be used with
/// `ResultExt::context` just like automatically generated SNAFU contexts.
///
/// Calling `some_result.context(EspressoError)` will convert a potential error from a [surf::Error]
/// to a specific error type `E: FromError` using the method `E::from_client_error`, provided by the
/// [FromError] trait.
pub struct ClientError;

impl<E: FromError + ErrorCompat + std::error::Error> IntoError<E> for ClientError {
    type Source = surf::Error;

    fn into_error(self, source: Self::Source) -> E {
        E::from_client_error(source)
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// API response types for Espresso-specific data structures
//

impl From<LedgerStateCommitment> for Hash {
    fn from(c: LedgerStateCommitment) -> Self {
        Self::from(commit::Commitment::<_>::from(c))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommittedBlock {
    pub id: BlockId,
    pub index: usize,
    pub hash: Hash,
    pub state_commitment: LedgerStateCommitment,
    pub transactions: Vec<CommittedTransaction>,
}

impl Display for CommittedBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_as_json(self, f)
    }
}

impl From<CommittedBlock> for ElaboratedBlock {
    fn from(b: CommittedBlock) -> Self {
        let (txs, proofs) = b
            .transactions
            .into_iter()
            .map(|tx| (tx.data, tx.proofs))
            .unzip();
        Self {
            block: Block(txs),
            proofs,
        }
    }
}

impl From<&CommittedBlock> for ElaboratedBlock {
    fn from(b: &CommittedBlock) -> Self {
        let (txs, proofs) = b
            .transactions
            .iter()
            .map(|tx| (tx.data.clone(), tx.proofs.clone()))
            .unzip();
        Self {
            block: Block(txs),
            proofs,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommittedTransaction {
    pub id: TransactionId,
    pub data: TransactionNote,
    pub proofs: Vec<SetMerkleProof>,
    pub output_uids: Vec<u64>,
    pub output_memos: Option<Vec<ReceiverMemo>>,
    pub memos_signature: Option<Signature>,
}

impl From<CommittedTransaction> for ElaboratedTransaction {
    fn from(tx: CommittedTransaction) -> Self {
        Self {
            txn: tx.data,
            proofs: tx.proofs,
        }
    }
}

impl From<&CommittedTransaction> for ElaboratedTransaction {
    fn from(tx: &CommittedTransaction) -> Self {
        Self {
            txn: tx.data.clone(),
            proofs: tx.proofs.clone(),
        }
    }
}

impl Display for CommittedTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_as_json(self, f)
    }
}

/// Response body for the query service endpoint GET /getnullifier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NullifierProof {
    pub spent: bool,
    pub proof: SetMerkleProof,
}

impl Display for NullifierProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_as_json(self, f)
    }
}
