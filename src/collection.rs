//! RFC 4073 — protecting multiple contents with the Cryptographic Message Syntax.
//!
//! One type of the three matters here: a [`ContentCollection`] is a sequence of `ContentInfo`,
//! which is how a publisher signs several independent messages and ships them as one artifact.
//! DoD InstallRoot streams are exactly that — a collection whose members are separately signed
//! TAMP updates, so each can be verified and applied on its own.
//!
//! This lives here rather than in the `cms` crate only because `cms` does not implement RFC 4073
//! today; it is a CMS companion specification and would sit naturally there if it is ever
//! contributed upstream.

use alloc::vec::Vec;
use cms::content_info::ContentInfo;
use der::Sequence;

/// ```text
/// ContentCollection ::= SEQUENCE SIZE (1..MAX) OF ContentInfo
/// ```
///
/// Decoding does not verify anything: each member carries its own signature, and checking one is
/// the caller's business because only the caller knows which trust anchors should have signed it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentCollection(pub Vec<ContentInfo>);

impl<'a> der::DecodeValue<'a> for ContentCollection {
    type Error = der::Error;

    fn decode_value<R: der::Reader<'a>>(reader: &mut R, header: der::Header) -> der::Result<Self> {
        Ok(ContentCollection(Vec::<ContentInfo>::decode_value(
            reader, header,
        )?))
    }
}

impl der::EncodeValue for ContentCollection {
    fn value_len(&self) -> der::Result<der::Length> {
        self.0.value_len()
    }

    fn encode_value(&self, writer: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode_value(writer)
    }
}

impl der::FixedTag for ContentCollection {
    const TAG: der::Tag = der::Tag::Sequence;
}

/// ```text
/// ContentWithAttributes ::= SEQUENCE {
///   content     ContentInfo,
///   attrs       SEQUENCE SIZE (1..MAX) OF Attribute }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ContentWithAttributes {
    /// The protected content.
    pub content: ContentInfo,
    /// Attributes describing it.
    pub attrs: Vec<x509_cert::attr::Attribute>,
}
