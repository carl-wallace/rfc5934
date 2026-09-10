//! `SignedData` that survives what publishers actually emit.
//!
//! The `cms` crate models RFC 5652 exactly, and is right to. DoD InstallRoot streams are not
//! exactly RFC 5652: their `crls` field carries **OCSP responses as bare `SEQUENCE`s**, where the
//! ASN.1 permits only a `CertificateList` unless the entry is wrapped as
//! `other [1] OtherRevocationInfoFormat` with `id-ri-ocsp-response` (RFC 5940). A conformant
//! decoder therefore rejects the whole message — including the trust anchor update inside it, which
//! is perfectly well formed.
//!
//! Rather than fork CMS or rewrite the bytes, this type **defers** that one field: `crls` is kept
//! as the raw encoding and every other field uses `cms`'s own types. Interpreting it is a separate
//! step ([`SignedData::revocation_info`]), so the accommodation for a publisher's deviation sits
//! beside the structure rather than inside it, and a file that *is* conformant decodes the same way.
//!
//! Deferring also preserves the original bytes, which is what signature verification needs: the
//! signature is over `eContent`, and re-encoding anything to check it invites a mismatch that has
//! nothing to do with the signature.

use alloc::vec::Vec;
use cms::signed_data::{CertificateSet, EncapsulatedContentInfo, SignerInfos};
use der::asn1::{Any, ContextSpecific, SetOfVec};
use der::{Decode, DecodeValue, Encode, FixedTag, Header, Reader, SliceReader, Tag, TagNumber};
use spki::AlgorithmIdentifierOwned;

/// RFC 5652 `SignedData` with the `crls` field left undecoded. See the module documentation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedData {
    /// `version CMSVersion`
    pub version: u8,
    /// `digestAlgorithms DigestAlgorithmIdentifiers`
    pub digest_algorithms: SetOfVec<AlgorithmIdentifierOwned>,
    /// `encapContentInfo EncapsulatedContentInfo` — the signed content itself.
    pub encap_content_info: EncapsulatedContentInfo,
    /// `certificates [0] IMPLICIT CertificateSet OPTIONAL` — for a TAMP stream, the signer's chain.
    pub certificates: Option<CertificateSet>,
    /// `crls [1] IMPLICIT RevocationInfoChoices OPTIONAL`, kept as the raw encoding of the whole
    /// field, tag included. Interpret it with [`SignedData::revocation_info`].
    pub crls: Option<Vec<u8>>,
    /// `signerInfos SignerInfos`
    pub signer_infos: SignerInfos,
}

impl FixedTag for SignedData {
    const TAG: Tag = Tag::Sequence;
}

impl<'a> DecodeValue<'a> for SignedData {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> der::Result<Self> {
        reader.read_nested(header.length(), |reader| {
            let version = reader.decode()?;
            let digest_algorithms = reader.decode()?;
            let encap_content_info = reader.decode()?;
            let certificates =
                ContextSpecific::<CertificateSet>::decode_implicit(reader, TagNumber(0))?
                    .map(|cs| cs.value);
            // Captured rather than decoded: this is the field publishers get wrong.
            let crls = match Tag::peek(reader) {
                Ok(Tag::ContextSpecific {
                    constructed: true,
                    number: TagNumber(1),
                }) => Some(reader.tlv_bytes()?.to_vec()),
                _ => None,
            };
            let signer_infos = reader.decode()?;
            Ok(Self {
                version,
                digest_algorithms,
                encap_content_info,
                certificates,
                crls,
                signer_infos,
            })
        })
    }
}

/// What the `crls` field turned out to hold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RevocationInfo {
    /// What RFC 5652 allows: certificate revocation lists, and entries wrapped in
    /// `other [1] OtherRevocationInfoFormat`.
    Conformant(Vec<Any>),
    /// What DoD InstallRoot emits: OCSP responses placed directly in the field, without the
    /// RFC 5940 wrapper that would make them legal there.
    ///
    BareOcspResponses(Vec<x509_ocsp::OcspResponse>),
}

impl SignedData {
    /// Interprets the deferred `crls` field, conformant reading first.
    ///
    /// `Ok(None)` when the field is absent. An `Err` means the field is neither shape, which is
    /// worth surfacing rather than swallowing — this method exists to accommodate one known
    /// deviation, not to accept anything at all.
    pub fn revocation_info(&self) -> der::Result<Option<RevocationInfo>> {
        let Some(raw) = &self.crls else {
            return Ok(None);
        };
        // The field is [1] IMPLICIT over a SET OF, so there is no inner SET tag to decode through:
        // the members follow the context tag directly. Read them as encoded values and let the
        // caller's question — conformant or not — decide what they are.
        let mut reader = SliceReader::new(raw)?;
        let header = Header::decode(&mut reader)?;
        let body = reader.read_slice(header.length())?;
        let mut reader = SliceReader::new(body)?;
        let mut members = Vec::new();
        while !reader.is_finished() {
            members.push(Any::decode(&mut reader)?);
        }

        if members.iter().all(is_revocation_info_choice) {
            return Ok(Some(RevocationInfo::Conformant(members)));
        }
        let mut responses = Vec::with_capacity(members.len());
        for member in &members {
            responses.push(x509_ocsp::OcspResponse::from_der(&member.to_der()?)?);
        }
        Ok(Some(RevocationInfo::BareOcspResponses(responses)))
    }
}

/// Whether a member decodes as something RFC 5652 permits in `crls`.
fn is_revocation_info_choice(member: &Any) -> bool {
    match member.to_der() {
        Ok(der) => {
            x509_cert::crl::CertificateList::<x509_cert::certificate::Raw>::from_der(&der).is_ok()
        }
        Err(_) => false,
    }
}
