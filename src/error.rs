//! The TAMP Error message (RFC 5934 §4.11).
//!
//! This is the protocol's error *message* — what a store sends back when it will not process
//! something. It is not this crate's Rust error type: decoding and encoding fail with
//! [`der::Error`], as everywhere else in the RustCrypto formats stack.

use const_oid::ObjectIdentifier;
use der::Sequence;

use crate::common::{StatusCode, TampMsgRef, TampVersion};

/// ```text
/// TAMPError ::= SEQUENCE {
///   version [0] TAMPVersion DEFAULT v2,
///   msgType     OBJECT IDENTIFIER,
///   status      StatusCode,
///   msgRef      TAMPMsgRef OPTIONAL }
/// ```
///
/// May be signed or unsigned — a store that can sign must, but one that cannot still has to be able
/// to say no. It is never used to report success.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampError {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// Content type of the message that caused the error — one of the identifiers in
    /// [`crate::oid`], or whatever unrecognized identifier was presented.
    pub msg_type: ObjectIdentifier,

    /// Why it was refused.
    pub status: StatusCode,

    /// The target and sequence number of the offending message, when they could be read. Optional
    /// because a message that failed to decode may have neither, but the RFC asks for it whenever
    /// it is available: without it a sender cannot tell which of its messages this answers.
    #[asn1(optional = "true")]
    pub msg_ref: Option<TampMsgRef>,
}
