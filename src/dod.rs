//! The DoD InstallRoot profile of TAMP.
//!
//! The streams at `crl.gds.disa.mil/pke/config` (`DoD`, `ECA`, `JITC`, `WCF`) are the only TAMP
//! messages published in the open, and they are ordinary RFC 5934 updates: standard content type
//! ([`ID_CT_TAMP_UPDATE`](crate::oid::ID_CT_TAMP_UPDATE) — the arc under `2.16.840.1.101` is where
//! IANA delegated TAMP's identifiers, not a DoD-private substitute), standard `TAMPUpdate` syntax,
//! standard RFC 5914 anchors inside.
//!
//! Two things about them are local, and both live here rather than in the protocol modules:
//!
//! 1. **A stream is a bare RFC 4073 [`ContentCollection`](crate::collection::ContentCollection)**
//!    of four separately signed updates — three for WCF, which publishes no `Untrusted` — rather
//!    than a single message. RFC 4073 allows this; TAMP says nothing about it either way.
//! 2. **The meaning of each message is in its label**, not its structure: `TAMPMsgRef.target`
//!    carries a URI of the form `<url>;<stream>;<kind>`, and the `RemoveCertificateHintList`
//!    message's entries are the same `add` entries as everywhere else. Reading a stream without
//!    reading its labels gets the `Untrusted` message backwards.
//!
//! What a consumer should *do* with the four messages — in particular what order to apply them in —
//! is a profile question this crate deliberately does not answer.
//!
//! The third local thing is a deviation rather than a profile choice: these streams put bare OCSP
//! responses in the CMS `crls` field. See [`crate::signed`].

use crate::common::TargetIdentifier;

/// What one message in a stream is for, read from the last field of its target URI.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StreamKind<'a> {
    /// Certificates the consumer should stop treating as hints when building paths.
    RemoveCertificateHintList,

    /// Trust anchors — the roots.
    Root,

    /// Intermediate CAs, offered as path-building material rather than as anchors.
    Ca,

    /// Certificates not to trust.
    Untrusted,

    /// A label this crate does not recognize, carried as published.
    Other(&'a str),
}

impl<'a> StreamKind<'a> {
    /// Reads a kind from its label.
    pub fn from_label(label: &'a str) -> Self {
        match label {
            "RemoveCertificateHintList" => StreamKind::RemoveCertificateHintList,
            "Root" => StreamKind::Root,
            "CA" => StreamKind::Ca,
            "Untrusted" => StreamKind::Untrusted,
            other => StreamKind::Other(other),
        }
    }

    /// The label as it appears in the target URI.
    pub const fn label(&self) -> &'a str {
        match self {
            StreamKind::RemoveCertificateHintList => "RemoveCertificateHintList",
            StreamKind::Root => "Root",
            StreamKind::Ca => "CA",
            StreamKind::Untrusted => "Untrusted",
            StreamKind::Other(label) => label,
        }
    }
}

/// The three fields of an InstallRoot target URI: `<url>;<stream>;<kind>`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StreamTarget<'a> {
    /// Where the stream is published.
    pub url: &'a str,

    /// Which stream it is — `DoD`, `ECA`, `JITC`, `WCF`.
    pub stream: &'a str,

    /// What this message within the stream is for.
    pub kind: StreamKind<'a>,
}

impl<'a> StreamTarget<'a> {
    /// Parses a target identifier as an InstallRoot label.
    ///
    /// `None` for any target that is not a URI, and for a URI that does not have the three
    /// semicolon-separated fields — a conformant TAMP target identifier this profile does not
    /// describe, rather than a malformed one.
    pub fn parse(target: &'a TargetIdentifier) -> Option<Self> {
        let TargetIdentifier::Uri(uri) = target else {
            return None;
        };
        let mut fields = uri.as_str().split(';');
        let (url, stream, kind) = (fields.next()?, fields.next()?, fields.next()?);
        if fields.next().is_some() {
            return None;
        }
        Some(StreamTarget {
            url,
            stream,
            kind: StreamKind::from_label(kind),
        })
    }
}
