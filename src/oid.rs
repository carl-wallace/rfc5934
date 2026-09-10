//! Object identifiers RFC 5934 defines, and the two from RFC 4073 that carry its messages.

use const_oid::ObjectIdentifier;

/// `id-tamp`, the arc every TAMP content type hangs off:
/// `{ joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) dod(2) infosec(1)
/// formats(2) 77 }`.
///
/// It reads as a DoD-private identifier because of where it sits, and it is not: RFC 5934 §11
/// records this arc as one IANA delegated to the PKIX working group, and the identifiers below are
/// the registered ones. A file carrying `2.16.840.1.101.2.1.2.77.3` is using the standard trust
/// anchor update content type, not a local substitute for it.
pub const ID_TAMP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77");

/// `id-ct-TAMP-statusQuery` — content type of a [`TampStatusQuery`](crate::status::TampStatusQuery).
pub const ID_CT_TAMP_STATUS_QUERY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.1");

/// `id-ct-TAMP-statusResponse` — content type of a
/// [`TampStatusResponse`](crate::status::TampStatusResponse).
pub const ID_CT_TAMP_STATUS_RESPONSE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.2");

/// `id-ct-TAMP-update` — content type of a [`TampUpdate`](crate::update::TampUpdate), and the one
/// DoD InstallRoot streams carry.
pub const ID_CT_TAMP_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.3");

/// `id-ct-TAMP-updateConfirm` — content type of a
/// [`TampUpdateConfirm`](crate::update::TampUpdateConfirm).
pub const ID_CT_TAMP_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.4");

/// `id-ct-TAMP-apexUpdate` — content type of a [`TampApexUpdate`](crate::apex::TampApexUpdate).
pub const ID_CT_TAMP_APEX_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.5");

/// `id-ct-TAMP-apexUpdateConfirm` — content type of a
/// [`TampApexUpdateConfirm`](crate::apex::TampApexUpdateConfirm).
pub const ID_CT_TAMP_APEX_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.6");

/// `id-ct-TAMP-communityUpdate` — content type of a
/// [`TampCommunityUpdate`](crate::community::TampCommunityUpdate).
pub const ID_CT_TAMP_COMMUNITY_UPDATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.7");

/// `id-ct-TAMP-communityUpdateConfirm` — content type of a
/// [`TampCommunityUpdateConfirm`](crate::community::TampCommunityUpdateConfirm).
pub const ID_CT_TAMP_COMMUNITY_UPDATE_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.8");

/// `id-ct-TAMP-error` — content type of a [`TampError`](crate::error::TampError).
///
/// Out of numeric order relative to the messages either side of it, which is how RFC 5934 assigns
/// it: the two sequence number adjust types took 10 and 11 after the error message had taken 9.
pub const ID_CT_TAMP_ERROR: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.9");

/// `id-ct-TAMP-seqNumAdjust` — content type of a
/// [`SequenceNumberAdjust`](crate::seqnum::SequenceNumberAdjust).
pub const ID_CT_TAMP_SEQ_NUM_ADJUST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.10");

/// `id-ct-TAMP-seqNumAdjustConfirm` — content type of a
/// [`SequenceNumberAdjustConfirm`](crate::seqnum::SequenceNumberAdjustConfirm).
pub const ID_CT_TAMP_SEQ_NUM_ADJUST_CONFIRM: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.2.77.11");

/// `id-aa-TAMP-contingencyPublicKeyDecryptKey` — the unsigned attribute carrying the symmetric key
/// that decrypts a stored contingency public key. See [`crate::apex`].
pub const ID_AA_TAMP_CONTINGENCY_PUBLIC_KEY_DECRYPT_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.2.1.5.63");

/// `id-pe-wrappedApexContinKey` — the certificate extension carrying a wrapped apex contingency
/// public key. See [`ApexContingencyKey`](crate::apex::ApexContingencyKey).
pub const ID_PE_WRAPPED_APEX_CONTIN_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.20");

/// `id-ct-contentCollection` (RFC 4073): the content type of a
/// [`ContentCollection`](crate::collection::ContentCollection) when one is itself wrapped in a
/// `ContentInfo`. A collection may also appear bare, as the outermost structure of a file, which is
/// how InstallRoot streams are published.
pub const ID_CT_CONTENT_COLLECTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.19");

/// `id-ct-contentWithAttrs` (RFC 4073): content carried alongside attributes describing it.
pub const ID_CT_CONTENT_WITH_ATTRS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.20");
