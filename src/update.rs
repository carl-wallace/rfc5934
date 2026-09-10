//! Trust Anchor Update and Trust Anchor Update Confirm messages (RFC 5934 §4.3 and §4.4).
//!
//! The update is the message that adds, removes or changes the trust anchors a target holds, and
//! the confirm is what the target sends back. Of the eleven TAMP messages these two are the ones
//! with published samples to test against — DoD InstallRoot streams are updates — so the rest of
//! the protocol is modelled from the ASN.1 alone. See [`crate::dod`].

use alloc::string::String;
use alloc::vec::Vec;

use der::{Choice, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::anchor::{CertPathControls, TrustAnchorChoice};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::common::{
    KeyIdentifier, StatusCodeList, TampMsgRef, TampSequenceNumbers, TampVersion, TerseOrVerbose,
    TrustAnchorChoiceList,
};

/// ```text
/// TAMPUpdate ::= SEQUENCE {
///   version         [0] TAMPVersion DEFAULT v2,
///   terse           [1] TerseOrVerbose DEFAULT verbose,
///   msgRef              TAMPMsgRef,
///   updates             SEQUENCE SIZE (1..MAX) OF TrustAnchorUpdate,
///   tampSeqNumbers  [2] TAMPSequenceNumbers OPTIONAL }
/// ```
///
/// The two `DEFAULT` fields are modelled as `Option` rather than as a value that defaults: DER
/// requires a field holding its default value to be absent, so `None` is the only encodable way to
/// say "the default", and an `Option` says that in the type instead of leaving a value that cannot
/// round-trip.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampUpdate {
    /// Protocol version. Absent means [`V2`](crate::common::V2), which is what published streams
    /// rely on.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// How much detail the confirm should carry. Absent means verbose.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub terse: Option<TerseOrVerbose>,

    /// Which target this message is for, and where it sits in that target's sequence.
    pub msg_ref: TampMsgRef,

    /// The changes to apply, in order.
    pub updates: Vec<TrustAnchorUpdate>,

    /// Sequence numbers to install alongside the update, one per TAMP signer. Present when the
    /// update itself is what teaches a store the counters to expect — after an apex change, say.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<TampSequenceNumbers>,
}

/// ```text
/// TrustAnchorUpdate ::= CHOICE {
///   add    [1] TrustAnchorChoice,
///   remove [2] SubjectPublicKeyInfo,
///   change [3] EXPLICIT TrustAnchorChangeInfoChoice }
/// ```
///
/// `add` is tagged EXPLICIT because `TrustAnchorChoice` is itself a CHOICE, which cannot take an
/// implicit tag — the encoding shows it as one context tag wrapping another, and a decoder that
/// assumes implicit tagging here fails on every published stream. `change` is EXPLICIT for the same
/// reason, spelled out in the RFC's module rather than implied by it.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorUpdate {
    /// A trust anchor to install, usually as a `TrustAnchorInfo` carrying the certificate.
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    Add(TrustAnchorChoice),

    /// The public key of an anchor to remove. Identified by key rather than by certificate,
    /// because the point is to stop trusting the key however it was expressed.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", constructed = "true")]
    Remove(SubjectPublicKeyInfoOwned),

    /// A change to an installed anchor, which keeps the key and edits what surrounds it.
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", constructed = "true")]
    Change(TrustAnchorChangeInfoChoice),
}

/// ```text
/// TrustAnchorChangeInfoChoice ::= CHOICE {
///   tbsCertChange [0] TBSCertificateChangeInfo,
///   taChange      [1] TrustAnchorChangeInfo }
/// ```
///
/// Which arm is legal depends on how the target stores the anchor being changed: an anchor held as
/// a certificate takes `tbsCertChange`, one held as a `TrustAnchorInfo` takes `taChange`, and
/// crossing the two earns [`ImproperTaChange`](crate::common::StatusCode::ImproperTaChange).
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(clippy::large_enum_variant)]
pub enum TrustAnchorChangeInfoChoice {
    /// Change an anchor held as a certificate.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    TbsCertChange(TbsCertificateChangeInfo),

    /// Change an anchor held as a `TrustAnchorInfo`.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    TaChange(TrustAnchorChangeInfo),
}

/// ```text
/// TBSCertificateChangeInfo ::= SEQUENCE {
///   serialNumber             CertificateSerialNumber OPTIONAL,
///   signature            [0] AlgorithmIdentifier OPTIONAL,
///   issuer               [1] Name OPTIONAL,
///   validity             [2] Validity OPTIONAL,
///   subject              [3] Name OPTIONAL,
///   subjectPublicKeyInfo [4] SubjectPublicKeyInfo,
///   exts                 [5] EXPLICIT Extensions OPTIONAL }
/// ```
///
/// The public key is the one mandatory field because it is the identifier: it says which installed
/// anchor to change. Every other field present replaces its counterpart, and every field absent
/// leaves that counterpart alone.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsCertificateChangeInfo {
    /// Replacement serial number.
    #[asn1(optional = "true")]
    pub serial_number: Option<SerialNumber>,

    /// Replacement signature algorithm.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub signature: Option<AlgorithmIdentifierOwned>,

    /// Replacement issuer name.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer: Option<Name>,

    /// Replacement validity period.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub validity: Option<Validity>,

    /// Replacement subject name.
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", optional = "true")]
    pub subject: Option<Name>,

    /// The public key of the anchor to change — which anchor this message is about, not a new key.
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT")]
    pub subject_public_key_info: SubjectPublicKeyInfoOwned,

    /// Replacement extensions.
    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", optional = "true")]
    pub exts: Option<Extensions>,
}

/// ```text
/// TrustAnchorChangeInfo ::= SEQUENCE {
///   pubKey       SubjectPublicKeyInfo,
///   keyId        KeyIdentifier OPTIONAL,
///   taTitle      TrustAnchorTitle OPTIONAL,
///   certPath     CertPathControls OPTIONAL,
///   exts     [1] Extensions OPTIONAL }
/// ```
///
/// As with [`TbsCertificateChangeInfo`], the key names the anchor and the rest is what changes.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TrustAnchorChangeInfo {
    /// The public key of the anchor to change.
    pub pub_key: SubjectPublicKeyInfoOwned,

    /// Replacement key identifier.
    #[asn1(optional = "true")]
    pub key_id: Option<KeyIdentifier>,

    /// Replacement human-readable title. `TrustAnchorTitle ::= UTF8String (SIZE (1..64))`.
    #[asn1(optional = "true")]
    pub ta_title: Option<String>,

    /// Replacement certification path controls.
    #[asn1(optional = "true")]
    pub cert_path: Option<CertPathControls>,

    /// Replacement extensions.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub exts: Option<Extensions>,
}

/// ```text
/// TAMPUpdateConfirm ::= SEQUENCE {
///   version [0] TAMPVersion DEFAULT v2,
///   update      TAMPMsgRef,
///   confirm     UpdateConfirm }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampUpdateConfirm {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// The reference from the update being confirmed, copied so the sender can match them up.
    pub update: TampMsgRef,

    /// What happened.
    pub confirm: UpdateConfirm,
}

/// ```text
/// UpdateConfirm ::= CHOICE {
///   terseConfirm   [0] TerseUpdateConfirm,
///   verboseConfirm [1] VerboseUpdateConfirm }
/// ```
///
/// Which arm appears is the update's choice, not the target's: it follows the `terse` field of the
/// [`TampUpdate`] being answered.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(clippy::large_enum_variant)]
pub enum UpdateConfirm {
    /// `TerseUpdateConfirm ::= StatusCodeList` — one status code per update, in the order the
    /// update listed them, and nothing else.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    TerseConfirm(StatusCodeList),

    /// The same codes plus the resulting anchor configuration.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    VerboseConfirm(VerboseUpdateConfirm),
}

/// ```text
/// VerboseUpdateConfirm ::= SEQUENCE {
///   status         StatusCodeList,
///   taInfo         TrustAnchorChoiceList,
///   tampSeqNumbers TAMPSequenceNumbers OPTIONAL,
///   usesApex       BOOLEAN DEFAULT TRUE }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct VerboseUpdateConfirm {
    /// One status code per update, in the order the update listed them.
    pub status: StatusCodeList,

    /// Every anchor the target holds once the update has been applied — not just the ones touched.
    pub ta_info: TrustAnchorChoiceList,

    /// The sequence numbers the target now records, one per TAMP signer.
    #[asn1(optional = "true")]
    pub tamp_seq_numbers: Option<TampSequenceNumbers>,

    /// Whether the target uses an apex trust anchor. Absent means true.
    #[asn1(optional = "true")]
    pub uses_apex: Option<bool>,
}
