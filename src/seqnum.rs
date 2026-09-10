//! Sequence Number Adjust and Sequence Number Adjust Confirm messages (RFC 5934 §4.9 and §4.10).
//!
//! A store records the last sequence number it saw from each authorized signer and refuses anything
//! not greater. That is what makes a captured TAMP message useless to replay, and it is also what
//! strands a store that has fallen behind. The adjust message is the repair: it carries nothing but
//! a signed sequence number, which the store accepts if it is at least as large as the one it
//! holds.

use der::Sequence;

use crate::common::{StatusCode, TampMsgRef, TampVersion};

/// ```text
/// SequenceNumberAdjust ::= SEQUENCE {
///   version [0] TAMPVersion DEFAULT v2,
///   msgRef      TAMPMsgRef }
/// ```
///
/// The whole payload is the reference, whose `seqNum` is the number being set. It must be signed.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SequenceNumberAdjust {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// Which targets this is for, and the sequence number they should record for the signer.
    pub msg_ref: TampMsgRef,
}

/// ```text
/// SequenceNumberAdjustConfirm ::= SEQUENCE {
///   version [0] TAMPVersion DEFAULT v2,
///   adjust      TAMPMsgRef,
///   status      StatusCode }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SequenceNumberAdjustConfirm {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// The reference from the adjust being confirmed.
    pub adjust: TampMsgRef,

    /// Whether the number was recorded.
    pub status: StatusCode,
}
