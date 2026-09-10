//! Any TAMP message, chosen by its content type.
//!
//! A TAMP message is only decodable once you know which of the eleven it is, and that is carried
//! outside the message — in `eContentType` for a signed message, in `contentType` for an unsigned
//! one, and in the `Content-Type` header when the transport is HTTP. [`MessageType`] is that
//! identifier in a form you can match on; [`TampMessage`] is what comes out the other side.

use alloc::vec::Vec;

use cms::signed_data::EncapsulatedContentInfo;
use const_oid::ObjectIdentifier;
use der::asn1::OctetString;
use der::{Decode, Encode, Error, ErrorKind};

use crate::apex::{TampApexUpdate, TampApexUpdateConfirm};
use crate::community::{TampCommunityUpdate, TampCommunityUpdateConfirm};
use crate::error::TampError;
use crate::oid;
use crate::seqnum::{SequenceNumberAdjust, SequenceNumberAdjustConfirm};
use crate::status::{TampStatusQuery, TampStatusResponse};
use crate::update::{TampUpdate, TampUpdateConfirm};

/// Which of the eleven TAMP messages a content type names.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MessageType {
    /// Ask a store what it holds.
    StatusQuery,
    /// The answer.
    StatusResponse,
    /// Add, remove or change trust anchors.
    Update,
    /// The answer.
    UpdateConfirm,
    /// Replace the apex trust anchor.
    ApexUpdate,
    /// The answer.
    ApexUpdateConfirm,
    /// Change a store's community memberships.
    CommunityUpdate,
    /// The answer.
    CommunityUpdateConfirm,
    /// Set the sequence number a store records for the signer.
    SequenceNumberAdjust,
    /// The answer.
    SequenceNumberAdjustConfirm,
    /// A refusal, in reply to any of the above.
    Error,
}

impl MessageType {
    /// Every message type, in the order RFC 5934 introduces them.
    pub const ALL: [MessageType; 11] = [
        MessageType::StatusQuery,
        MessageType::StatusResponse,
        MessageType::Update,
        MessageType::UpdateConfirm,
        MessageType::ApexUpdate,
        MessageType::ApexUpdateConfirm,
        MessageType::CommunityUpdate,
        MessageType::CommunityUpdateConfirm,
        MessageType::SequenceNumberAdjust,
        MessageType::SequenceNumberAdjustConfirm,
        MessageType::Error,
    ];

    /// The content type identifying this message.
    pub const fn oid(self) -> ObjectIdentifier {
        match self {
            MessageType::StatusQuery => oid::ID_CT_TAMP_STATUS_QUERY,
            MessageType::StatusResponse => oid::ID_CT_TAMP_STATUS_RESPONSE,
            MessageType::Update => oid::ID_CT_TAMP_UPDATE,
            MessageType::UpdateConfirm => oid::ID_CT_TAMP_UPDATE_CONFIRM,
            MessageType::ApexUpdate => oid::ID_CT_TAMP_APEX_UPDATE,
            MessageType::ApexUpdateConfirm => oid::ID_CT_TAMP_APEX_UPDATE_CONFIRM,
            MessageType::CommunityUpdate => oid::ID_CT_TAMP_COMMUNITY_UPDATE,
            MessageType::CommunityUpdateConfirm => oid::ID_CT_TAMP_COMMUNITY_UPDATE_CONFIRM,
            MessageType::SequenceNumberAdjust => oid::ID_CT_TAMP_SEQ_NUM_ADJUST,
            MessageType::SequenceNumberAdjustConfirm => oid::ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM,
            MessageType::Error => oid::ID_CT_TAMP_ERROR,
        }
    }

    /// The message type a content type names, or `None` for one RFC 5934 does not define.
    pub fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        MessageType::ALL.into_iter().find(|ty| ty.oid() == oid)
    }

    /// The media type registered for this message in RFC 5934 Appendix B, which is what TAMP over
    /// HTTP puts in `Content-Type`.
    ///
    /// Note the two sequence number messages: their media types say `sequence-adjust` where their
    /// ASN.1 says `seqNumAdjust`.
    pub const fn media_type(self) -> &'static str {
        match self {
            MessageType::StatusQuery => "application/tamp-status-query",
            MessageType::StatusResponse => "application/tamp-status-response",
            MessageType::Update => "application/tamp-update",
            MessageType::UpdateConfirm => "application/tamp-update-confirm",
            MessageType::ApexUpdate => "application/tamp-apex-update",
            MessageType::ApexUpdateConfirm => "application/tamp-apex-update-confirm",
            MessageType::CommunityUpdate => "application/tamp-community-update",
            MessageType::CommunityUpdateConfirm => "application/tamp-community-update-confirm",
            MessageType::SequenceNumberAdjust => "application/tamp-sequence-adjust",
            MessageType::SequenceNumberAdjustConfirm => "application/tamp-sequence-adjust-confirm",
            MessageType::Error => "application/tamp-error",
        }
    }

    /// The file extension registered alongside the media type, without its dot.
    pub const fn file_extension(self) -> &'static str {
        match self {
            MessageType::StatusQuery => "tsq",
            MessageType::StatusResponse => "tsr",
            MessageType::Update => "tur",
            MessageType::UpdateConfirm => "tuc",
            MessageType::ApexUpdate => "tau",
            MessageType::ApexUpdateConfirm => "auc",
            MessageType::CommunityUpdate => "tcu",
            MessageType::CommunityUpdateConfirm => "cuc",
            MessageType::SequenceNumberAdjust => "tsa",
            MessageType::SequenceNumberAdjustConfirm => "sac",
            MessageType::Error => "ter",
        }
    }

    /// Whether RFC 5934 requires this message to be signed.
    ///
    /// Only the error message may travel unsigned, and only from a store that cannot sign at all.
    pub const fn must_be_signed(self) -> bool {
        !matches!(self, MessageType::Error)
    }
}

/// A decoded TAMP message of any of the eleven types.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum TampMessage {
    /// `id-ct-TAMP-statusQuery`
    StatusQuery(TampStatusQuery),
    /// `id-ct-TAMP-statusResponse`
    StatusResponse(TampStatusResponse),
    /// `id-ct-TAMP-update`
    Update(TampUpdate),
    /// `id-ct-TAMP-updateConfirm`
    UpdateConfirm(TampUpdateConfirm),
    /// `id-ct-TAMP-apexUpdate`
    ApexUpdate(TampApexUpdate),
    /// `id-ct-TAMP-apexUpdateConfirm`
    ApexUpdateConfirm(TampApexUpdateConfirm),
    /// `id-ct-TAMP-communityUpdate`
    CommunityUpdate(TampCommunityUpdate),
    /// `id-ct-TAMP-communityUpdateConfirm`
    CommunityUpdateConfirm(TampCommunityUpdateConfirm),
    /// `id-ct-TAMP-seqNumAdjust`
    SequenceNumberAdjust(SequenceNumberAdjust),
    /// `id-ct-TAMP-seqNumAdjustConfirm`
    SequenceNumberAdjustConfirm(SequenceNumberAdjustConfirm),
    /// `id-ct-TAMP-error`
    Error(TampError),
}

impl TampMessage {
    /// Decodes a message of a type you already know.
    pub fn from_der(message_type: MessageType, bytes: &[u8]) -> der::Result<Self> {
        Ok(match message_type {
            MessageType::StatusQuery => TampMessage::StatusQuery(TampStatusQuery::from_der(bytes)?),
            MessageType::StatusResponse => {
                TampMessage::StatusResponse(TampStatusResponse::from_der(bytes)?)
            }
            MessageType::Update => TampMessage::Update(TampUpdate::from_der(bytes)?),
            MessageType::UpdateConfirm => {
                TampMessage::UpdateConfirm(TampUpdateConfirm::from_der(bytes)?)
            }
            MessageType::ApexUpdate => TampMessage::ApexUpdate(TampApexUpdate::from_der(bytes)?),
            MessageType::ApexUpdateConfirm => {
                TampMessage::ApexUpdateConfirm(TampApexUpdateConfirm::from_der(bytes)?)
            }
            MessageType::CommunityUpdate => {
                TampMessage::CommunityUpdate(TampCommunityUpdate::from_der(bytes)?)
            }
            MessageType::CommunityUpdateConfirm => {
                TampMessage::CommunityUpdateConfirm(TampCommunityUpdateConfirm::from_der(bytes)?)
            }
            MessageType::SequenceNumberAdjust => {
                TampMessage::SequenceNumberAdjust(SequenceNumberAdjust::from_der(bytes)?)
            }
            MessageType::SequenceNumberAdjustConfirm => TampMessage::SequenceNumberAdjustConfirm(
                SequenceNumberAdjustConfirm::from_der(bytes)?,
            ),
            MessageType::Error => TampMessage::Error(TampError::from_der(bytes)?),
        })
    }

    /// Decodes the message a CMS `EncapsulatedContentInfo` carries, using its `eContentType` to
    /// decide which one it is.
    ///
    /// Fails with [`ErrorKind::OidUnknown`] on a content type RFC 5934 does not define — which the
    /// protocol answers with [`UnsupportedTampMsgType`](crate::common::StatusCode::UnsupportedTampMsgType)
    /// — and with [`ErrorKind::Failed`] when `eContent` is absent, which CMS allows and TAMP does
    /// not ([`MissingContent`](crate::common::StatusCode::MissingContent)).
    pub fn from_encapsulated(content: &EncapsulatedContentInfo) -> der::Result<Self> {
        let message_type = MessageType::from_oid(content.econtent_type).ok_or_else(|| {
            Error::from(ErrorKind::OidUnknown {
                oid: content.econtent_type,
            })
        })?;
        let econtent = content
            .econtent
            .as_ref()
            .ok_or_else(|| Error::from(ErrorKind::Failed))?;
        // eContent is an OCTET STRING wrapping the message, so it is unwrapped once here rather
        // than by every caller.
        let payload = econtent.decode_as::<OctetString>()?;
        TampMessage::from_der(message_type, payload.as_bytes())
    }

    /// Which of the eleven this is.
    pub const fn message_type(&self) -> MessageType {
        match self {
            TampMessage::StatusQuery(_) => MessageType::StatusQuery,
            TampMessage::StatusResponse(_) => MessageType::StatusResponse,
            TampMessage::Update(_) => MessageType::Update,
            TampMessage::UpdateConfirm(_) => MessageType::UpdateConfirm,
            TampMessage::ApexUpdate(_) => MessageType::ApexUpdate,
            TampMessage::ApexUpdateConfirm(_) => MessageType::ApexUpdateConfirm,
            TampMessage::CommunityUpdate(_) => MessageType::CommunityUpdate,
            TampMessage::CommunityUpdateConfirm(_) => MessageType::CommunityUpdateConfirm,
            TampMessage::SequenceNumberAdjust(_) => MessageType::SequenceNumberAdjust,
            TampMessage::SequenceNumberAdjustConfirm(_) => MessageType::SequenceNumberAdjustConfirm,
            TampMessage::Error(_) => MessageType::Error,
        }
    }

    /// Encodes the message itself — not the CMS envelope around it.
    pub fn to_der(&self) -> der::Result<Vec<u8>> {
        match self {
            TampMessage::StatusQuery(m) => m.to_der(),
            TampMessage::StatusResponse(m) => m.to_der(),
            TampMessage::Update(m) => m.to_der(),
            TampMessage::UpdateConfirm(m) => m.to_der(),
            TampMessage::ApexUpdate(m) => m.to_der(),
            TampMessage::ApexUpdateConfirm(m) => m.to_der(),
            TampMessage::CommunityUpdate(m) => m.to_der(),
            TampMessage::CommunityUpdateConfirm(m) => m.to_der(),
            TampMessage::SequenceNumberAdjust(m) => m.to_der(),
            TampMessage::SequenceNumberAdjustConfirm(m) => m.to_der(),
            TampMessage::Error(m) => m.to_der(),
        }
    }
}
