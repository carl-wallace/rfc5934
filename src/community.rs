//! Community Update and Community Update Confirm messages (RFC 5934 §4.7 and §4.8).
//!
//! A community is an object identifier a group of targets share, so that one message can be
//! addressed to all of them at once ([`TargetIdentifier::Communities`]). These two messages are how
//! a target's memberships change.
//!
//! [`TargetIdentifier::Communities`]: crate::common::TargetIdentifier::Communities

use der::{Choice, Sequence};

use crate::common::{CommunityIdentifierList, StatusCode, TampMsgRef, TampVersion, TerseOrVerbose};

/// ```text
/// TAMPCommunityUpdate ::= SEQUENCE {
///   version [0] TAMPVersion DEFAULT v2,
///   terse   [1] TerseOrVerbose DEFAULT verbose,
///   msgRef      TAMPMsgRef,
///   updates     CommunityUpdates }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampCommunityUpdate {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// How much detail the confirm should carry. Absent means verbose.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub terse: Option<TerseOrVerbose>,

    /// Which target this message is for, and where it sits in that target's sequence.
    pub msg_ref: TampMsgRef,

    /// The memberships to drop and to take on.
    pub updates: CommunityUpdates,
}

/// ```text
/// CommunityUpdates ::= SEQUENCE {
///   remove [1] CommunityIdentifierList OPTIONAL,
///   add    [2] CommunityIdentifierList OPTIONAL }
///   -- At least one must be present
/// ```
///
/// The "at least one" is a comment in the RFC's module rather than a constraint the syntax can
/// express, so a message with neither field decodes here and is rejected by the target with
/// [`CommunityUpdateFailed`](crate::common::StatusCode::CommunityUpdateFailed). [`Self::is_empty`]
/// asks the question directly.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CommunityUpdates {
    /// Memberships to drop. Removals are processed before additions.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub remove: Option<CommunityIdentifierList>,

    /// Memberships to take on.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub add: Option<CommunityIdentifierList>,
}

impl CommunityUpdates {
    /// Whether the message asks for nothing — neither field present, or both present and empty.
    pub fn is_empty(&self) -> bool {
        let empty = |list: &Option<CommunityIdentifierList>| {
            list.as_ref().is_none_or(|list| list.is_empty())
        };
        empty(&self.remove) && empty(&self.add)
    }
}

/// ```text
/// TAMPCommunityUpdateConfirm ::= SEQUENCE {
///   version     [0] TAMPVersion DEFAULT v2,
///   update          TAMPMsgRef,
///   commConfirm     CommunityConfirm }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampCommunityUpdateConfirm {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// The reference from the community update being confirmed.
    pub update: TampMsgRef,

    /// What happened.
    pub comm_confirm: CommunityConfirm,
}

/// ```text
/// CommunityConfirm ::= CHOICE {
///   terseCommConfirm   [0] TerseCommunityConfirm,
///   verboseCommConfirm [1] VerboseCommunityConfirm }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CommunityConfirm {
    /// `TerseCommunityConfirm ::= StatusCode` — one code, and nothing else. Primitive rather than
    /// constructed, because an ENUMERATED under an implicit tag stays primitive.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "false")]
    TerseCommConfirm(StatusCode),

    /// The same code plus the memberships the target now holds.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    VerboseCommConfirm(VerboseCommunityConfirm),
}

/// ```text
/// VerboseCommunityConfirm ::= SEQUENCE {
///   status      StatusCode,
///   communities CommunityIdentifierList OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct VerboseCommunityConfirm {
    /// Whether the update was applied.
    pub status: StatusCode,

    /// Every community the target belongs to afterwards. Absent means it belongs to none.
    #[asn1(optional = "true")]
    pub communities: Option<CommunityIdentifierList>,
}
