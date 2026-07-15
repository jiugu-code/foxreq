#![forbid(unsafe_code)]

mod chunked;
mod client;
mod error;
mod request;
mod response;

pub use client::{
    ClientError, ClientErrorKind, ClientRequest, ClientResponse, Http1Client, OwnedHeader,
};
pub use error::{Error, ErrorKind, ResponseError, ResponseErrorKind};
pub use request::{serialize_request, Header, Request, RequestBody, RequestLimits};
pub use response::{
    FeedResult, FeedStatus, RequestSemantics, Response, ResponseHead, ResponseHeader,
    ResponseLimits, ResponseParser, Version,
};
