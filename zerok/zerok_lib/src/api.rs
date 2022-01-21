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

use ark_serialize::*;
use fmt::{Debug, Display, Formatter};
use futures::future::BoxFuture;
use futures::prelude::*;
use generic_array::{ArrayLength, GenericArray};
use jf_aap::{
    structs::{ReceiverMemo, RecordCommitment},
    Signature,
};
use jf_utils::{tagged_blob, Tagged};
use phaselock::BlockHash;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

#[tagged_blob("BK")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct BlockId(pub usize);

#[tagged_blob("TX")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct TransactionId(pub BlockId, pub usize);

// UserAddress from jf_aap is just a type alias for VerKey, which serializes with the tag VERKEY,
// which is confusing. This newtype struct lets us a define a more user-friendly tag.
#[tagged_blob("ADDR")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, Hash)]
pub struct UserAddress(pub jf_aap::keys::UserAddress);

impl From<jf_aap::keys::UserAddress> for UserAddress {
    fn from(addr: jf_aap::keys::UserAddress) -> Self {
        Self(addr)
    }
}

impl From<UserAddress> for jf_aap::keys::UserAddress {
    fn from(addr: UserAddress) -> Self {
        addr.0
    }
}

pub use jf_aap::keys::UserPubKey;

#[tagged_blob("RECPROOF")]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct MerklePath(pub jf_aap::MerklePath);

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

/// Errors which can be serialized in a response body.
///
/// This trait can be used to define a standard error type returned by all API endpoints. When a
/// request fails for any reason, the body of the response will contain a serialization of
/// the error that caused the failure, upcasted into an anyhow::Error. If the error is an instance
/// of the standard error type for that particular API, it can be deserialized and downcasted to
/// this type on the client. The `client` module provides a middleware handler that does this
/// automatically.
///
/// Other errors (those which don't downcast to the API's errortype, such as errors
/// generated from the [tide] framework) will be serialized as strings using their [Display]
/// instance and encoded as an API error using the `catch_all` function.
pub trait Error: std::error::Error + Serialize + DeserializeOwned + Send + Sync + 'static {
    fn catch_all(msg: String) -> Self;
    fn status(&self) -> tide::StatusCode;

    /// Convert from a generic client-side error to a specific error type.
    ///
    /// If `source` can be downcast to `Self`, it is simply downcasted. Otherwise, it is converted
    /// to a [String] using [Display] and then converted to `Self` using [catch_all].
    fn from_client_error(source: surf::Error) -> Self {
        match source.downcast::<Self>() {
            Ok(err) => err,
            Err(err) => Self::catch_all(err.to_string()),
        }
    }
}

/// Convert a concrete error type into a server error.
///
/// The error is first converted into an `E` using the [From] instance. That error is then
/// upcasted into an anyhow error to be embedded in the [tide::Error], using the status code
/// indicated by [Error::status_code].
///
/// TODO the best way I can think of using this is something like
/// ```ignore
/// enum MyError { ... }
///
/// impl Error for MyError { ... }
///
/// fn my_error(error: impl Into<MyError>) -> tide::Error {
///     server_error(error)
/// }
///
/// fn some_endpoint(...) {
///     ...
///     some_result.map_err(my_error)?;
///     ...
/// }
/// ```
/// to ensure that the correct type parameter `MyError` is always used with `server_error`. A better
/// way would be to define a `Server` type which wraps a `tide` server, and takes endpoints of the
/// form `(...) -> Result<impl Serialize, impl Error>` and then calls `server_error` internal. This
/// would also be a good place to put other common server-related code, such as parsing api.toml and
/// route dispatching.
pub fn server_error<E: Error>(error: impl Into<E>) -> tide::Error {
    let error = error.into();
    tide::Error::new(error.status(), error)
}

/// Context for embedding network client errors into specific error types.
///
/// This type implements the [IntoError] trait from SNAFU, so it can be used with
/// [ResultExt::context] just like automatically generated SNAFU contexts.
///
/// Calling `some_result.context(ClientError)` will convert a potential error from a [surf::Error]
/// to a specific error type `E` using the method `E::from_client_error`, provided by the
/// [Error] trait.
///
/// This is the inverse of [server_error], and can be used on the client side to recover errors
/// which were generated on the server using [server_error].
pub struct ClientError;

impl<E: Error + ErrorCompat + std::error::Error> IntoError<E> for ClientError {
    type Source = surf::Error;

    fn into_error(self, source: Self::Source) -> E {
        E::from_client_error(source)
    }
}

/// Convert a concrete error type into a client error.
///
/// The error is first converted into an [Error] using the [Into] instance. That error is then
/// upcasted into an anyhow error to be embedded in the [surf::Error].
///
/// This is the equivalent for [server_error] for errors generated on the client side; for instance,
/// in middleware.
pub fn client_error<E: Error>(error: impl Into<E>) -> surf::Error {
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
                    bincode::deserialize(&bytes).map_err(|err| {
                        tide::Error::from_str(
                            StatusCode::BadRequest,
                            format!("unable to deserialie request body: {}", err),
                        )
                    })
                }
                content_type => Err(tide::Error::from_str(
                    StatusCode::BadRequest,
                    format!("unsupported content type {}", content_type),
                )),
            }
        } else {
            Err(tide::Error::from_str(
                StatusCode::BadRequest,
                "unspecified content type",
            ))
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
    pub fn add_error_body<'a, T: Clone + Send + Sync + 'static, E: Error>(
        req: Request<T>,
        next: Next<'a, T>,
    ) -> BoxFuture<'a, tide::Result> {
        Box::pin(async {
            let mut accept = Accept::from_headers(&req)?;
            let mut res = next.run(req).await;
            if let Some(error) = res.take_error() {
                let error = E::from_client_error(error);
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
                "application/octet-stream" => bincode::deserialize(&res.body_bytes().await?)
                    .map_err(|err| {
                        surf::Error::from_str(
                            StatusCode::InternalServerError,
                            format!("response body fails to deserialize: {}", err),
                        )
                    }),
                content_type => Err(surf::Error::from_str(
                    StatusCode::UnsupportedMediaType,
                    format!("unsupported content type {}", content_type),
                )),
            }
        } else {
            Err(surf::Error::from_str(
                StatusCode::UnsupportedMediaType,
                "unspecified content type in response",
            ))
        }
    }

    pub async fn response_to_result<E: Error>(mut res: Response) -> surf::Result<Response> {
        if res.status() == StatusCode::Ok {
            Ok(res)
        } else {
            let err: E = response_body(&mut res).await?;
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
    pub fn parse_error_body<E: Error>(
        req: Request,
        client: Client,
        next: Next<'_>,
    ) -> BoxFuture<surf::Result<Response>> {
        Box::pin(
            next.run(req, client)
                .and_then(|res| async { response_to_result::<E>(res).await }),
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
pub fn fmt_as_json<T: Serialize>(v: &T, f: &mut Formatter<'_>) -> fmt::Result {
    let string = serde_json::to_string(v).map_err(|_| fmt::Error)?;
    write!(f, "{}", string)
}
