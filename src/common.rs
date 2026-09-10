//! Types shared by more than one TAMP message.
//!
//! Every message carries a version and a [`TampMsgRef`]; most carry a status code, a community
//! list, or a set of sequence numbers. They are gathered here rather than duplicated per message,
//! and named as RFC 5934 names them.

use alloc::vec::Vec;

use const_oid::ObjectIdentifier;
use der::asn1::{Ia5String, Null, OctetString};
use der::{Choice, Enumerated, Sequence};
use x509_cert::anchor::TrustAnchorChoice;
use x509_cert::ext::pkix::name::OtherName;

/// `TAMPVersion ::= INTEGER { v1(1), v2(2) }`
///
/// A named-number INTEGER rather than an enumeration, so a value outside the two named ones is
/// still well formed: the RFC has a target answer an unrecognized version with
/// [`StatusCode::VersionNumberMismatch`], which it can only do if the message decoded first.
pub type TampVersion = u8;

/// TAMP as RFC 5011 era implementations spoke it.
pub const V1: TampVersion = 1;

/// TAMP as RFC 5934 defines it, and what every `version` field defaults to when absent.
pub const V2: TampVersion = 2;

/// `TerseOrVerbose ::= ENUMERATED { terse(1), verbose(2) }`
///
/// How much detail the sender wants back. Absent means [`Verbose`](TerseOrVerbose::Verbose).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Enumerated)]
#[repr(u8)]
pub enum TerseOrVerbose {
    /// Answer with status codes and key identifiers only.
    Terse = 1,
    /// Answer with the trust anchors themselves.
    Verbose = 2,
}

/// `SeqNumber ::= INTEGER (0..9223372036854775807)`
///
/// Typed as an integer rather than an arbitrary-precision value: a message outside that range is
/// malformed, and saying so at decode time is better than carrying it and failing later.
pub type SeqNumber = u64;

/// ```text
/// TAMPMsgRef ::= SEQUENCE {
///   target  TargetIdentifier,
///   seqNum  SeqNumber }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampMsgRef {
    /// Who the message is addressed to.
    pub target: TargetIdentifier,

    /// Monotonic sequence number, which a target uses to reject replays and reordering.
    pub seq_num: SeqNumber,
}

/// ```text
/// TargetIdentifier ::= CHOICE {
///   hwModules   [1] HardwareModuleIdentifierList,
///   communities [2] CommunityIdentifierList,
///   allModules  [3] NULL,
///   uri         [4] IA5String,
///   otherName   [5] INSTANCE OF OTHER-NAME }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum TargetIdentifier {
    /// Particular hardware modules, named by type and serial number.
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    HwModules(HardwareModuleIdentifierList),

    /// Every module belonging to any of the listed communities.
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", constructed = "true")]
    Communities(CommunityIdentifierList),

    /// Every module the sender can reach.
    #[asn1(context_specific = "3", tag_mode = "IMPLICIT", constructed = "false")]
    AllModules(Null),

    /// A URI naming the stream, which is what InstallRoot uses.
    #[asn1(context_specific = "4", tag_mode = "IMPLICIT", constructed = "false")]
    Uri(Ia5String),

    /// Another name form.
    #[asn1(context_specific = "5", tag_mode = "IMPLICIT", constructed = "true")]
    OtherName(OtherName),
}

/// `HardwareModuleIdentifierList ::= SEQUENCE SIZE (1..MAX) OF HardwareModules`
pub type HardwareModuleIdentifierList = Vec<HardwareModules>;

/// ```text
/// HardwareModules ::= SEQUENCE {
///   hwType          OBJECT IDENTIFIER,
///   hwSerialEntries SEQUENCE SIZE (1..MAX) OF HardwareSerialEntry }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct HardwareModules {
    /// The kind of module, which is what gives the serial numbers below their meaning.
    pub hw_type: ObjectIdentifier,

    /// Which of that kind, as individual serials, ranges, or all of them.
    pub hw_serial_entries: Vec<HardwareSerialEntry>,
}

/// ```text
/// HardwareSerialEntry ::= CHOICE {
///   all    NULL,
///   single OCTET STRING,
///   block  SEQUENCE { low OCTET STRING, high OCTET STRING } }
/// ```
///
/// Untagged, and unambiguous without tags because the three arms are a NULL, an OCTET STRING and a
/// SEQUENCE.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum HardwareSerialEntry {
    /// Every module of this hardware type.
    All(Null),

    /// One module, by serial number.
    Single(OctetString),

    /// Every module whose serial number falls in a range.
    Block(HardwareSerialBlock),
}

/// The `block` arm of [`HardwareSerialEntry`], which RFC 5934 leaves anonymous.
///
/// Serial numbers compare as unsigned integers of the same length, so `low` and `high` are expected
/// to be the same length as each other and as the serials they bound.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct HardwareSerialBlock {
    /// First serial number in the range, included.
    pub low: OctetString,

    /// Last serial number in the range, included.
    pub high: OctetString,
}

/// `Community ::= OBJECT IDENTIFIER`
pub type Community = ObjectIdentifier;

/// `CommunityIdentifierList ::= SEQUENCE SIZE (0..MAX) OF Community`
///
/// Zero is a legal size: an empty list says the target belongs to no community, which is a
/// different statement from the field being absent.
pub type CommunityIdentifierList = Vec<Community>;

/// `KeyIdentifier`, as RFC 5280 defines it — the value of a subject key identifier extension.
pub type KeyIdentifier = OctetString;

/// `KeyIdentifiers ::= SEQUENCE SIZE (1..MAX) OF KeyIdentifier`
pub type KeyIdentifiers = Vec<KeyIdentifier>;

/// ```text
/// TAMPSequenceNumber ::= SEQUENCE {
///   keyId     KeyIdentifier,
///   seqNumber SeqNumber }
/// ```
///
/// The sequence number a target has recorded for one TAMP signer, which is per signer rather than
/// per target: a store tracks a separate counter for each key that has sent it a message.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TampSequenceNumber {
    /// The signer's key identifier.
    pub key_id: KeyIdentifier,

    /// The highest sequence number seen from that signer.
    pub seq_number: SeqNumber,
}

/// `TAMPSequenceNumbers ::= SEQUENCE SIZE (1..MAX) OF TAMPSequenceNumber`
pub type TampSequenceNumbers = Vec<TampSequenceNumber>;

/// `TrustAnchorChoiceList ::= SEQUENCE SIZE (1..MAX) OF TrustAnchorChoice`
pub type TrustAnchorChoiceList = Vec<TrustAnchorChoice>;

/// `StatusCodeList ::= SEQUENCE SIZE (1..MAX) OF StatusCode`
///
/// One code per update in the message it answers, in the same order.
pub type StatusCodeList = Vec<StatusCode>;

/// `StatusCode ::= ENUMERATED { ... }` — why a TAMP message was or was not processed.
///
/// A closed enumeration: RFC 5934 defines no extension marker and asks for no IANA registry, so an
/// unrecognized value is a malformed message rather than one from a later revision.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Enumerated)]
#[repr(u8)]
pub enum StatusCode {
    /// The message was processed.
    Success = 0,

    /// The message could not be decoded.
    DecodeFailure = 1,

    /// The `ContentInfo` syntax is invalid.
    BadContentInfo = 2,

    /// The `SignedData` syntax is invalid, its version is unsupported, or it names more than one
    /// digest algorithm.
    BadSignedData = 3,

    /// The `EncapsulatedContentInfo` syntax is invalid.
    BadEncapContent = 4,

    /// A certificate in the certificate set is not valid syntax.
    BadCertificate = 5,

    /// The `SignerInfo` syntax is invalid, or its version is unsupported.
    BadSignerInfo = 6,

    /// The signed attributes are not valid syntax.
    BadSignedAttrs = 7,

    /// The unsigned attributes are not valid syntax.
    BadUnsignedAttrs = 8,

    /// `eContent` is absent, which TAMP requires even though CMS makes it optional.
    MissingContent = 9,

    /// The signer identifier leads to no installed trust anchor — or it is an issuer and serial
    /// number, which TAMP does not permit for identifying a signer.
    NoTrustAnchor = 10,

    /// The signer is an installed anchor but not one authorized for this content type, or
    /// subordination processing denied it the anchor it tried to manage.
    NotAuthorized = 11,

    /// The digest algorithm is unknown or unsupported.
    BadDigestAlgorithm = 12,

    /// The signature algorithm is unknown or unsupported.
    BadSignatureAlgorithm = 13,

    /// The signature algorithm is supported but the signer's key size is not.
    UnsupportedKeySize = 14,

    /// The signature algorithm is known but the parameters the signer used are not supported.
    UnsupportedParameters = 15,

    /// The signature did not verify.
    SignatureFailure = 16,

    /// The store has no room for the resulting configuration.
    InsufficientMemory = 17,

    /// The store does not implement this message type — which includes any content type the
    /// specification does not define.
    UnsupportedTampMsgType = 18,

    /// An update tried to remove the apex trust anchor.
    ApexTampAnchor = 19,

    /// An add would have modified an existing anchor's attributes improperly; a change operation
    /// may be the operation that was meant.
    ImproperTaAddition = 20,

    /// Sequence number processing rejected the message.
    SeqNumFailure = 21,

    /// The contingency public key could not be decrypted.
    ContingencyPublicKeyDecrypt = 22,

    /// The store is not the target the message names.
    IncorrectTarget = 23,

    /// A community could not be added or removed as asked.
    CommunityUpdateFailed = 24,

    /// A change named an anchor the store does not hold.
    TrustAnchorNotFound = 25,

    /// The anchor's signature algorithm — or its parameters — is not implemented.
    UnsupportedTaAlgorithm = 26,

    /// The anchor's public key is of an unsupported size.
    UnsupportedTaKeySize = 27,

    /// The apex contingency key's decryption algorithm is not supported.
    UnsupportedContinPubKeyDecryptAlg = 28,

    /// The message arrived unsigned and this type must be signed.
    MissingSignature = 29,

    /// The resources to process the message are busy; later may succeed.
    ResourcesBusy = 30,

    /// The version in the message is not acceptable.
    VersionNumberMismatch = 31,

    /// The anchor's policy flags require a policy set and none was given.
    MissingPolicySet = 32,

    /// A certificate needed to process the message is revoked.
    RevokedCertificate = 33,

    /// The trust anchor format, or its version, is not supported.
    UnsupportedTrustAnchorFormat = 34,

    /// A change tried to move an anchor to a different format than the one it is stored in.
    ImproperTaChange = 35,

    /// The CMS structure around the message is malformed.
    Malformed = 36,

    /// The CMS structure failed to process — a content type or message digest attribute, say.
    CmsError = 37,

    /// The `TargetIdentifier` option used is not supported.
    UnsupportedTargetIdentifier = 38,

    /// None of the above. RFC 5934 asks that this be avoided.
    Other = 127,
}

impl StatusCode {
    /// Whether the code reports success. Every other code is a refusal of some kind.
    pub fn is_success(self) -> bool {
        self == StatusCode::Success
    }
}
