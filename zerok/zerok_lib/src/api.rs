///////////////////////////////////////////////////////////////////////////////
// Rust interface for the query API
//
// All data structures returned by query API endpoints correspond directly to
// Rust data structures via the serde serialization and deserialization
// interfaces. For query responses which do not directly correspond to data
// structures elsewhere in this crate or in Jellyfish, data structures are
// defined in this module which can be serialized to and from the API
// responses.
//
// Types which must be embeddable in URLs (e.g. hashes and identifiers) and
// binary blob types are serialized as tagged base 64 strings. Other
// structures use derived serde implementations, which allows them to
// serialize as human-readable JSON objects or as binary strings, depending
// on the serializer used. This makes it easy for the API to support multiple
// content types in its responses, as long as each endpoint handler returns an
// object with the appropriate Serialize implementation.
//

use crate::util::commit;
use crate::{
    state_comm::LedgerStateCommitment, Block, ElaboratedBlock, ElaboratedTransaction,
    SetMerkleProof,
};
use ark_serialize::*;
use fmt::{Display, Formatter};
use futures::future::BoxFuture;
use futures::prelude::*;
use generic_array::{ArrayLength, GenericArray};
use jf_txn::{
    structs::{ReceiverMemo, RecordCommitment},
    Signature, TransactionNote,
};
use jf_utils::{tagged_blob, Tagged};
use phaselock::BlockHash;
use serde::{Deserialize, Serialize};
use snafu::{ErrorCompat, IntoError, ResultExt, Snafu};
use std::fmt;
use tagged_base64::TaggedBase64;

#[tagged_blob("HASH")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct Hash(pub Vec<u8>);

impl<const N: usize> From<BlockHash<N>> for Hash {
    fn from(h: BlockHash<N>) -> Self {
        Self(h.as_ref().to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for Hash {
    fn from(h: [u8; N]) -> Self {
        Self(h.as_ref().to_vec())
    }
}

impl<U: ArrayLength<u8>> From<GenericArray<u8, U>> for Hash {
    fn from(a: GenericArray<u8, U>) -> Self {
        Self((&*a).to_vec())
    }
}

impl<T: commit::Committable> From<commit::Commitment<T>> for Hash {
    fn from(c: commit::Commitment<T>) -> Self {
        Self::from(<[u8; 32]>::from(c))
    }
}

impl From<LedgerStateCommitment> for Hash {
    fn from(c: LedgerStateCommitment) -> Self {
        Self::from(commit::Commitment::<_>::from(c))
    }
}

#[tagged_blob("BK")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct BlockId(pub usize);

#[tagged_blob("TX")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct TransactionId(pub BlockId, pub usize);

// UserAddress from jf_txn is just a type alias for VerKey, which serializes with the tag VERKEY,
// which is confusing. This newtype struct lets us a define a more user-friendly tag.
#[tagged_blob("ADDR")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct UserAddress(pub jf_txn::keys::UserAddress);

pub use jf_txn::keys::UserPubKey;

#[tagged_blob("RECPROOF")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct MerklePath(pub jf_txn::MerklePath);

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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnspentRecord {
    pub commitment: RecordCommitment,
    pub uid: u64,
    pub memo: Option<ReceiverMemo>,
}

impl Display for UnspentRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fmt_as_json(self, f)
    }
}

/// Request body for the bulletin board endpoint POST /memos.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostMemos {
    pub memos: Vec<ReceiverMemo>,
    pub signature: Signature,
}

impl Display for PostMemos {
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

/// Errors which can be serialized in a response body.
///
/// When a request fails for any reason, the body of the response will contain a serialization of
/// the error that caused the failure. The serialization will represent this data structure.
/// Variants can be added to handle any specific error type that the API wants to expose. Other
/// errors (such as errors generated from the [tide] framework) will be serialized as strings using
/// their [Display] instance and encoded in the [Error::InternalError] variant.
#[derive(Debug, Serialize, Deserialize, Snafu)]
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
pub enum Error {
    QueryServiceError {
        source: crate::node::QueryServiceError,
    },
    ValidationError {
        source: crate::ValidationError,
    },
    #[snafu(display("{:?}", source))]
    ConsensusError {
        // PhaseLockError cannot be serialized. Instead, if we have to serialize this variant, we
        // will serialize Ok(err) to Err(format(err)), and when we deserialize we will at least
        // preserve the variant ConsensusError and a String representation of the underlying error.
        // Unfortunately, this means we cannot use this variant as a SNAFU error source.
        #[serde(with = "crate::ser_debug")]
        #[snafu(source(false))]
        source: Result<phaselock::error::PhaseLockError, String>,
    },
    #[snafu(display("error in parameter {}: {}", param, msg))]
    ParamError {
        param: String,
        msg: String,
    },
    #[snafu(display("unsupported content type {}", content_type))]
    UnsupportedContentType {
        content_type: String,
    },
    UnspecifiedContentType {},
    #[snafu(display("{}", msg))]
    InternalError {
        msg: String,
    },
}

impl Error {
    fn status(&self) -> tide::StatusCode {
        match self {
            Self::ParamError { .. } => tide::StatusCode::BadRequest,
            Self::UnsupportedContentType { .. } => tide::StatusCode::BadRequest,
            _ => tide::StatusCode::InternalServerError,
        }
    }
}

impl From<crate::node::QueryServiceError> for Error {
    fn from(source: crate::node::QueryServiceError) -> Self {
        Self::QueryServiceError { source }
    }
}

impl From<crate::ValidationError> for Error {
    fn from(source: crate::ValidationError) -> Self {
        Self::ValidationError { source }
    }
}

impl From<phaselock::error::PhaseLockError> for Error {
    fn from(source: phaselock::error::PhaseLockError) -> Self {
        Self::ConsensusError { source: Ok(source) }
    }
}

impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Self::InternalError {
            msg: source.to_string(),
        }
    }
}

impl From<Box<bincode::ErrorKind>> for Error {
    fn from(source: Box<bincode::ErrorKind>) -> Self {
        Self::InternalError {
            msg: source.to_string(),
        }
    }
}

/// Convert a concrete error type into a server error.
///
/// The error is first converted into an [Error] using the [From] instance. That error is then
/// upcasted into an anyhow error to be embedded in the [tide::Error].
pub fn server_error(error: impl Into<Error>) -> tide::Error {
    let error = error.into();
    tide::Error::new(error.status(), error)
}

/// Conversion from [api::Error] to module-specific error types.
///
/// Any error type which has a catch-all variant can implement this trait and get conversions from
/// other [Error] variants for free. By default, the conversion function for each variant simply
/// converts the variant to a String using the Display instance and calls the [catch_all] method. If
/// the implementing type has a variant for a specific type of error encapsulated in [Error], it can
/// override the conversion function for that variant.
///
/// Having default conversion functions for each variant ensures that new error types can be added
/// to [Error] without breaking existing conversions, as long as a corresponding new default method
/// is added to this trait.
pub trait FromError: Sized {
    fn catch_all(msg: String) -> Self;

    fn from_query_service_error(source: crate::node::QueryServiceError) -> Self {
        Self::catch_all(source.to_string())
    }

    fn from_validation_error(source: crate::ValidationError) -> Self {
        Self::catch_all(source.to_string())
    }

    fn from_consensus_error(source: Result<phaselock::error::PhaseLockError, String>) -> Self {
        match source {
            Ok(err) => Self::catch_all(format!("{:?}", err)),
            Err(msg) => Self::catch_all(msg),
        }
    }

    fn from_param_error(param: String, msg: String) -> Self {
        Self::catch_all(format!("invalid request parameter {}: {}", param, msg))
    }

    fn from_unsupported_content_type(content_type: String) -> Self {
        Self::catch_all(format!("unsupported content type {}", content_type))
    }

    fn from_unspecified_content_type() -> Self {
        Self::catch_all(String::from("missing Content-Type header"))
    }

    fn from_api_error<E: Into<Error>>(source: E) -> Self {
        match source.into() {
            Error::QueryServiceError { source } => Self::from_query_service_error(source),
            Error::ValidationError { source } => Self::from_validation_error(source),
            Error::ConsensusError { source } => Self::from_consensus_error(source),
            Error::ParamError { param, msg } => Self::from_param_error(param, msg),
            Error::UnsupportedContentType { content_type } => {
                Self::from_unsupported_content_type(content_type)
            }
            Error::UnspecifiedContentType {} => Self::from_unspecified_content_type(),
            Error::InternalError { msg } => Self::catch_all(msg),
        }
    }

    /// Convert from a generic client-side error to a specific error type.
    ///
    /// If `source` can be downcast to an [Error], it is converted to the specific type using
    /// [from_api_error]. Otherwise, it is converted to a [String] using [Display] and then
    /// converted to the specific type using [catch_all].
    fn from_client_error(source: surf::Error) -> Self {
        match source.downcast::<Error>() {
            Ok(err) => Self::from_api_error(err),
            Err(err) => Self::catch_all(err.to_string()),
        }
    }
}

impl FromError for Error {
    fn catch_all(msg: String) -> Self {
        Self::InternalError { msg }
    }

    fn from_query_service_error(source: crate::node::QueryServiceError) -> Self {
        Self::QueryServiceError { source }
    }

    fn from_validation_error(source: crate::ValidationError) -> Self {
        Self::ValidationError { source }
    }

    fn from_consensus_error(source: Result<phaselock::error::PhaseLockError, String>) -> Self {
        Self::ConsensusError { source }
    }

    fn from_param_error(param: String, msg: String) -> Self {
        Self::ParamError { param, msg }
    }

    fn from_unsupported_content_type(content_type: String) -> Self {
        Self::UnsupportedContentType { content_type }
    }

    fn from_unspecified_content_type() -> Self {
        Self::UnspecifiedContentType {}
    }

    fn from_api_error<E: Into<Error>>(source: E) -> Self {
        source.into()
    }
}

/// Context for embedding network client errors into specific error types.
///
/// This type implements the [IntoError] trait from SNAFU, so it can be used with
/// [ResultExt::context] just like automatically generated SNAFU contexts.
///
/// Calling `some_result.context(ClientError)` will convert a potential error from a [surf::Error]
/// to a specific error type `E` using the method `E::from_client_error`, provided by the
/// [FromError] trait.
///
/// This is the inverse of [server_error], and can be used on the client side to recover errors
/// which were generated on the server using [server_error].
pub struct ClientError;

impl<E: FromError + ErrorCompat + std::error::Error> IntoError<E> for ClientError {
    type Source = surf::Error;

    fn into_error(self, source: Self::Source) -> E {
        E::from_client_error(source)
    }
}

/// Convert a concrete error type into a client error.
///
/// The error is first converted into an [Error] using the [From] instance. That error is then
/// upcasted into an anyhow error to be embedded in the [surf::Error].
///
/// This is the equivalent for [server_error] for errors generated on the client side; for instance,
/// in middleware.
pub fn client_error(error: impl Into<Error>) -> surf::Error {
    let error = error.into();
    surf::Error::new(error.status(), error)
}

pub mod server {
    use super::*;
    use mime::Mime;
    use tide::http::{content::Accept, mime};
    use tide::{Body, Next, Request, Response, StatusCode};
    use tracing::{event, Level};

    /// Deserialize the body of a request.
    ///
    /// The Content-Type header is used to determine the serialization format.
    pub async fn request_body<T: for<'de> Deserialize<'de>, S>(
        req: &mut Request<S>,
    ) -> Result<T, tide::Error> {
        if let Some(content_type) = req.header("Content-Type") {
            match content_type.as_str() {
                "application/json" => req.body_json().await,
                "application/octet-stream" => {
                    let bytes = req.body_bytes().await?;
                    bincode::deserialize(&bytes).map_err(server_error)
                }
                content_type => Err(server_error(Error::UnsupportedContentType {
                    content_type: String::from(content_type),
                })),
            }
        } else {
            Err(server_error(Error::UnspecifiedContentType {}))
        }
    }

    pub fn best_response_type(
        accept: &mut Option<Accept>,
        available: &[Mime],
    ) -> Result<Mime, tide::Error> {
        match accept {
            Some(accept) => {
                // The Accept type has a `negotiate` method, but it doesn't properly handle
                // wildcards. It handles * but not */* and basetype/*, because for content type
                // proposals like */* and basetype/*, it looks for a literal match in `available`,
                // it does not perform pattern matching. So, we implement negotiation ourselves.
                //
                // First sort by the weight parameter, which the Accept type does do correctly.
                accept.sort();
                // Go through each proposed content type, in the order specified by the client, and
                // match them against our available types, respecting wildcards.
                for proposed in accept.iter() {
                    if proposed.basetype() == "*" {
                        // The only acceptable Accept value with a basetype of * is */*, therefore
                        // this will match any available type.
                        return Ok(available[0].clone());
                    } else if proposed.subtype() == "*" {
                        // If the subtype is * but the basetype is not, look for a proposed type
                        // with a matching basetype and any subtype.
                        for mime in available {
                            if mime.basetype() == proposed.basetype() {
                                return Ok(mime.clone());
                            }
                        }
                    } else if available.contains(proposed) {
                        // If neither part of the proposal is a wildcard, look for a literal match.
                        return Ok((**proposed).clone());
                    }
                }

                if accept.wildcard() {
                    // If no proposals are available but a wildcard flag * was given, return any
                    // available content type.
                    Ok(available[0].clone())
                } else {
                    Err(tide::Error::from_str(
                        StatusCode::NotAcceptable,
                        "No suitable Content-Type found",
                    ))
                }
            }
            None => {
                // If no content type is explicitly requested, default to the first available type.
                Ok(available[0].clone())
            }
        }
    }

    fn respond_with<T: Serialize>(
        accept: &mut Option<Accept>,
        body: T,
    ) -> Result<Response, tide::Error> {
        let ty = best_response_type(accept, &[mime::JSON, mime::BYTE_STREAM])?;
        if ty == mime::BYTE_STREAM {
            let bytes = bincode::serialize(&body)?;
            Ok(Response::builder(tide::StatusCode::Ok)
                .body(bytes)
                .content_type(mime::BYTE_STREAM)
                .build())
        } else if ty == mime::JSON {
            Ok(Response::builder(tide::StatusCode::Ok)
                .body(Body::from_json(&body)?)
                .content_type(mime::JSON)
                .build())
        } else {
            unreachable!()
        }
    }

    /// Serialize the body of a response.
    ///
    /// The Accept header of the request is used to determine the serialization format.
    ///
    /// This function combined with the [add_error_body] middleware defines the server-side protocol
    /// for encoding zerok types in HTTP responses.
    pub fn response<T: Serialize, S>(req: &Request<S>, body: T) -> Result<Response, tide::Error> {
        respond_with(&mut Accept::from_headers(req)?, body)
    }

    /// Server middleware which automatically populates the body of error responses.
    ///
    /// If the response contains an error, the error is encoded into the [Error] type (either by
    /// downcasting if the server has generated an instance of [Error], or by converting to a
    /// [String] using [Display] if the error can not be downcasted to [Error]). The resulting
    /// [Error] is then serialized and used as the body of the response.
    ///
    /// If the response does not contain an error, it is passed through unchanged.
    ///
    /// This middleware is the inverse of the client-side middleware `parse_error_body`, which
    /// automatically converts error responses into [Err] variants, assuming the responses follow
    /// the convention implemented by this middleware.
    pub fn add_error_body<'a, T: Clone + Send + Sync + 'static>(
        req: Request<T>,
        next: Next<'a, T>,
    ) -> BoxFuture<'a, tide::Result> {
        Box::pin(async {
            let mut accept = Accept::from_headers(&req)?;
            let mut res = next.run(req).await;
            if let Some(error) = res.take_error() {
                let error = Error::from_client_error(error);
                event!(Level::WARN, "responding with error: {}", error);
                let mut res = respond_with(&mut accept, &error)?;
                res.set_status(error.status());
                Ok(res)
            } else {
                Ok(res)
            }
        })
    }

    /// Server middleware which logs requests and responses.
    pub fn trace<'a, T: Clone + Send + Sync + 'static>(
        req: tide::Request<T>,
        next: tide::Next<'a, T>,
    ) -> BoxFuture<'a, tide::Result> {
        Box::pin(async {
            event!(
                Level::INFO,
                "<-- received request {{url: {}, content-type: {:?}, accept: {:?}}}",
                req.url(),
                req.content_type(),
                Accept::from_headers(&req),
            );
            let res = next.run(req).await;
            event!(
                Level::INFO,
                "--> responding with {{content-type: {:?}, error: {:?}}}",
                res.content_type(),
                res.error(),
            );
            Ok(res)
        })
    }
}

pub mod client {
    use super::*;
    use surf::{middleware::Next, Client, Request, Response, StatusCode};

    /// Deserialize the body of a response.
    ///
    /// The Content-Type header is used to determine the serialization format.
    ///
    /// This function combined with the [parse_error_body] middleware defines the client-side
    /// protocol for decoding zerok types from HTTP responses.
    pub async fn response_body<T: for<'de> Deserialize<'de>>(
        res: &mut Response,
    ) -> Result<T, surf::Error> {
        if let Some(content_type) = res.header("Content-Type") {
            match content_type.as_str() {
                "application/json" => res.body_json().await,
                "application/octet-stream" => {
                    bincode::deserialize(&res.body_bytes().await?).map_err(client_error)
                }
                content_type => Err(client_error(Error::UnsupportedContentType {
                    content_type: String::from(content_type),
                })),
            }
        } else {
            Err(client_error(Error::UnspecifiedContentType {}))
        }
    }

    pub async fn response_to_result(mut res: Response) -> surf::Result<Response> {
        if res.status() == StatusCode::Ok {
            Ok(res)
        } else {
            let err: Error = response_body(&mut res).await?;
            Err(surf::Error::new(err.status(), err))
        }
    }

    /// Client middleware which turns responses with non-success statuses into errors.
    ///
    /// If the status code of the response is Ok (200), the response is passed through unchanged.
    /// Otherwise, the body of the response is treated as an [Error] which is lifted into a
    /// [surf::Error]. This can then be converted into a module-specific error type using
    /// [FromApiError::from_client_error].
    ///
    /// If the request fails without producing a response at all, the [surf::Error] from the failed
    /// request is passed through.
    ///
    /// This middleware is the inverse of the server-side middleware `add_error_body`, which
    /// automatically prepares the body of error responses for interpretation by this client side
    /// middleware.
    pub fn parse_error_body(
        req: Request,
        client: Client,
        next: Next<'_>,
    ) -> BoxFuture<surf::Result<Response>> {
        Box::pin(
            next.run(req, client)
                .and_then(|res| async { response_to_result(res).await }),
        )
    }
}

// Helper trait with a blanket implementation allowing us to convert TaggedBase64 to any type which
// implements Tagged and CanonicalDeserialize.
pub trait TaggedBlob: Sized + Tagged + CanonicalDeserialize {
    fn from_tagged_blob(b64: &TaggedBase64) -> Result<Self, TaggedBlobError>;
}

#[derive(Debug, Snafu)]
pub enum TaggedBlobError {
    SerError { source: SerializationError },
    TagMismatch { actual: String, expected: String },
}

impl<T: Tagged + CanonicalDeserialize> TaggedBlob for T {
    fn from_tagged_blob(b64: &TaggedBase64) -> Result<Self, TaggedBlobError> {
        if b64.tag() == Self::tag() {
            Self::deserialize(&*b64.value()).context(SerError)
        } else {
            Err(TaggedBlobError::TagMismatch {
                actual: b64.tag(),
                expected: Self::tag(),
            })
        }
    }
}

// Display implementation for types which serialize to JSON. Displays as a valid JSON object.
fn fmt_as_json<T: Serialize>(v: &T, f: &mut Formatter<'_>) -> fmt::Result {
    let string = serde_json::to_string(v).map_err(|_| fmt::Error)?;
    write!(f, "{}", string)
}
