//! TAMP Status Query and TAMP Status Response messages (RFC 5934 §4.1 and §4.2).
//!
//! The response is the part of TAMP worth reading even if you never send a TAMP message: it is a
//! signed, self-describing statement of *what trust anchors a store actually holds* — terse as a
//! list of key identifiers, verbose as the anchors themselves, either way with the communities the
//! store belongs to and the sequence numbers it has recorded. Two stores that have never heard of
//! each other can be compared by putting each one's contents in this shape.
//!
//! [`VerboseStatusResponse::terse`] does the one reduction the format implies, and is the piece a
//! comparison usually wants: identity by key identifier, independent of how each store chose to
//! wrap its anchors.

use alloc::vec::Vec;

use const_oid::AssociatedOid;
use der::{Choice, Decode, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

use crate::common::{
    CommunityIdentifierList, KeyIdentifier, KeyIdentifiers, TampMsgRef, TampSequenceNumbers,
    TampVersion, TerseOrVerbose, TrustAnchorChoiceList,
};

/// ```text
/// TAMPStatusQuery ::= SEQUENCE {
///   version [0] TAMPVersion DEFAULT v2,
///   terse   [1] TerseOrVerbose DEFAULT verbose,
///   query       TAMPMsgRef }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampStatusQuery {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// How much detail to answer with. Absent means verbose.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub terse: Option<TerseOrVerbose>,

    /// Which target is being asked, and where the question sits in that target's sequence.
    pub query: TampMsgRef,
}

/// ```text
/// TAMPStatusResponse ::= SEQUENCE {
///   version  [0] TAMPVersion DEFAULT v2,
///   query        TAMPMsgRef,
///   response     StatusResponse,
///   usesApex     BOOLEAN DEFAULT TRUE }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampStatusResponse {
    /// Protocol version. Absent means [`V2`](crate::common::V2).
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub version: Option<TampVersion>,

    /// The reference from the query being answered, copied so the asker can match them up.
    pub query: TampMsgRef,

    /// The answer.
    pub response: StatusResponse,

    /// Whether the target uses an apex trust anchor. Absent means true.
    #[asn1(optional = "true")]
    pub uses_apex: Option<bool>,
}

/// ```text
/// StatusResponse ::= CHOICE {
///   terseResponse   [0] TerseStatusResponse,
///   verboseResponse [1] VerboseStatusResponse }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(clippy::large_enum_variant)]
pub enum StatusResponse {
    /// Key identifiers only.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", constructed = "true")]
    TerseResponse(TerseStatusResponse),

    /// The anchors themselves.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    VerboseResponse(VerboseStatusResponse),
}

/// ```text
/// TerseStatusResponse ::= SEQUENCE {
///   taKeyIds    KeyIdentifiers,
///   communities CommunityIdentifierList OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TerseStatusResponse {
    /// One key identifier per installed trust anchor, apex included.
    pub ta_key_ids: KeyIdentifiers,

    /// The communities the target belongs to.
    #[asn1(optional = "true")]
    pub communities: Option<CommunityIdentifierList>,
}

/// ```text
/// VerboseStatusResponse ::= SEQUENCE {
///   taInfo                     TrustAnchorChoiceList,
///   continPubKeyDecryptAlg [0] AlgorithmIdentifier OPTIONAL,
///   communities            [1] CommunityIdentifierList OPTIONAL,
///   tampSeqNumbers         [2] TAMPSequenceNumbers OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct VerboseStatusResponse {
    /// Every trust anchor the target holds, apex first.
    pub ta_info: TrustAnchorChoiceList,

    /// The algorithm that would unwrap the apex contingency public key, when the target has one.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub contin_pub_key_decrypt_alg: Option<AlgorithmIdentifierOwned>,

    /// The communities the target belongs to.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub communities: Option<CommunityIdentifierList>,

    /// The sequence numbers the target has recorded, one per TAMP signer.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub tamp_seq_numbers: Option<TampSequenceNumbers>,
}

impl VerboseStatusResponse {
    /// The terse response describing the same store.
    ///
    /// `None` when an anchor has no key identifier to reduce to — a bare certificate carrying no
    /// subject key identifier extension. RFC 5934 requires the two forms to describe the same set,
    /// so a store holding such an anchor cannot answer tersely at all, and reporting that is more
    /// use than quietly returning a shorter list than the store holds.
    pub fn terse(&self) -> Option<TerseStatusResponse> {
        let mut ta_key_ids = Vec::with_capacity(self.ta_info.len());
        for anchor in &self.ta_info {
            ta_key_ids.push(key_identifier(anchor)?);
        }
        Some(TerseStatusResponse {
            ta_key_ids,
            communities: self.communities.clone(),
        })
    }
}

/// The key identifier a trust anchor is known by, whichever form it takes.
///
/// A `TrustAnchorInfo` states it; a certificate or a `TBSCertificate` carries it in the subject key
/// identifier extension. `None` means the anchor has none to state — this does not compute one from
/// the public key, because a store that did so would answer with identifiers no other store would
/// recognize.
pub fn key_identifier(anchor: &TrustAnchorChoice) -> Option<KeyIdentifier> {
    let extensions = match anchor {
        TrustAnchorChoice::TaInfo(info) => return Some(info.key_id.clone()),
        TrustAnchorChoice::Certificate(cert) => cert.tbs_certificate().extensions(),
        TrustAnchorChoice::TbsCertificate(tbs) => tbs.extensions(),
    };
    let skid = extensions?
        .iter()
        .find(|ext| ext.extn_id == SubjectKeyIdentifier::OID)?;
    SubjectKeyIdentifier::from_der(skid.extn_value.as_bytes())
        .ok()
        .map(|skid| skid.0)
}
