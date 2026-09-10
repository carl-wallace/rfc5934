//! Apex Trust Anchor Update and Apex Trust Anchor Update Confirm messages (RFC 5934 §4.5 and
//! §4.6), and the two structures that support the apex contingency key.
//!
//! The apex trust anchor is the one that manages the store itself, so replacing it is a different
//! operation from an ordinary update: it can clear everything else on the way through, and it can
//! be signed with a contingency key held in reserve for the case where the operational key is lost.
//! That contingency key travels wrapped, in a certificate extension
//! ([`ApexContingencyKey`]), and the symmetric key that unwraps it arrives as an unsigned attribute
//! ([`PlaintextSymmetricKey`]) on the very message it authenticates.

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
use der::{Choice, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::anchor::TrustAnchorChoice;

use crate::common::{
    CommunityIdentifierList, SeqNumber, StatusCode, TampMsgRef, TampSequenceNumbers, TampVersion,
    TerseOrVerbose, TrustAnchorChoiceList,
};
use crate::oid::ID_PE_WRAPPED_APEX_CONTIN_KEY;

/// ```text
/// TAMPApexUpdate ::= SEQUENCE {
///   version           [0] TAMPVersion DEFAULT v2,
///   terse             [1] TerseOrVerbose DEFAULT verbose,
///   msgRef                TAMPMsgRef,
///   clearTrustAnchors     BOOLEAN,
///   clearCommunities      BOOLEAN,
///   seqNumber             SeqNumber OPTIONAL,
///   apexTA                TrustAnchorChoice }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampApexUpdate {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// How much detail the confirm should carry. Absent means verbose.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub terse: Option<TerseOrVerbose>,

    /// Which target this message is for, and where it sits in that target's sequence.
    pub msg_ref: TampMsgRef,

    /// Whether to discard every other trust anchor as the apex is replaced.
    pub clear_trust_anchors: bool,

    /// Whether to discard the target's community memberships as the apex is replaced.
    pub clear_communities: bool,

    /// The sequence number the target should record for the new apex.
    ///
    /// Present because the new apex has no history with this target: without it the target has no
    /// counter to compare the apex's next message against.
    #[asn1(optional = "true")]
    pub seq_number: Option<SeqNumber>,

    /// The apex trust anchor to install.
    pub apex_ta: TrustAnchorChoice,
}

/// ```text
/// TAMPApexUpdateConfirm ::= SEQUENCE {
///   version     [0] TAMPVersion DEFAULT v2,
///   apexReplace     TAMPMsgRef,
///   apexConfirm     ApexUpdateConfirm }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampApexUpdateConfirm {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// The reference from the apex update being confirmed.
    pub apex_replace: TampMsgRef,

    /// What happened.
    pub apex_confirm: ApexUpdateConfirm,
}

/// ```text
/// ApexUpdateConfirm ::= CHOICE {
///   terseApexConfirm   [0] TerseApexUpdateConfirm,
///   verboseApexConfirm [1] VerboseApexUpdateConfirm }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(clippy::large_enum_variant)]
pub enum ApexUpdateConfirm {
    /// `TerseApexUpdateConfirm ::= StatusCode` — one code, and nothing else. Primitive rather than
    /// constructed, because an ENUMERATED under an implicit tag stays primitive.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "false")]
    TerseApexConfirm(StatusCode),

    /// The same code plus the resulting configuration.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    VerboseApexConfirm(VerboseApexUpdateConfirm),
}

/// ```text
/// VerboseApexUpdateConfirm ::= SEQUENCE {
///   status             StatusCode,
///   taInfo             TrustAnchorChoiceList,
///   communities    [0] CommunityIdentifierList OPTIONAL,
///   tampSeqNumbers [1] TAMPSequenceNumbers OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct VerboseApexUpdateConfirm {
    /// Whether the apex was replaced.
    pub status: StatusCode,

    /// Every anchor the target holds afterwards — which is the apex alone if the update asked for
    /// everything else to be cleared.
    pub ta_info: TrustAnchorChoiceList,

    /// The communities the target belongs to afterwards.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub communities: Option<CommunityIdentifierList>,

    /// The sequence numbers the target records afterwards.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<TampSequenceNumbers>,
}

/// `PlaintextSymmetricKey ::= OCTET STRING`
///
/// The key that decrypts an apex trust anchor's stored contingency public key, carried as the
/// unsigned attribute [`ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY`] on the apex update it
/// authenticates. Unsigned, necessarily: it is the input to checking that message's signature.
///
/// [`ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY`]:
///     crate::oid::ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY
pub type PlaintextSymmetricKey = OctetString;

/// ```text
/// ApexContingencyKey ::= SEQUENCE {
///   wrapAlgorithm       AlgorithmIdentifier OPTIONAL,
///   wrappedContinPubKey OCTET STRING OPTIONAL }
/// ```
///
/// The `id-pe-wrappedApexContinKey` certificate extension: an apex trust anchor's contingency
/// public key, encrypted under a symmetric key that is not published until the day it is needed.
///
/// **Both fields are modelled as optional, following RFC 5934 §9 rather than the module in its
/// Appendix A**, which makes them mandatory. The two disagree, and §9 is the one that explains
/// itself: it says both fields must be present or both absent, and that an empty extension is how a
/// certificate says "some relying parties treat this key as an apex trust anchor" without publishing
/// any contingency material. A mandatory model cannot decode that certificate at all.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ApexContingencyKey {
    /// The symmetric algorithm the contingency public key is encrypted under.
    #[asn1(optional = "true")]
    pub wrap_algorithm: Option<AlgorithmIdentifierOwned>,

    /// The encrypted contingency public key, which decrypts to a `SubjectPublicKeyInfo`.
    #[asn1(optional = "true")]
    pub wrapped_contin_pub_key: Option<OctetString>,
}

impl ApexContingencyKey {
    /// Whether the extension carries contingency material, as opposed to marking the key as an apex
    /// anchor and nothing more.
    ///
    /// RFC 5934 §9 requires the two fields to appear together, so a `false` here from an extension
    /// with one field present is a non-conformant certificate rather than a half-usable key.
    pub fn is_present(&self) -> bool {
        self.wrap_algorithm.is_some() && self.wrapped_contin_pub_key.is_some()
    }
}

impl AssociatedOid for ApexContingencyKey {
    const OID: ObjectIdentifier = ID_PE_WRAPPED_APEX_CONTIN_KEY;
}
