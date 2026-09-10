//! Decodes real DoD InstallRoot streams.
//!
//! The fixtures are not committed — run `tests/fetch-fixtures.sh` first. Every test skips when
//! they are absent, so a checkout without them passes rather than failing for want of someone
//! else's trust material.

use der::{Decode, Encode};
use rfc5934::dod::StreamTarget;
use rfc5934::message::{MessageType, TampMessage};
use rfc5934::signed::{RevocationInfo, SignedData};
use rfc5934::{ContentCollection, TampUpdate, TrustAnchorUpdate};
use x509_cert::anchor::TrustAnchorChoice;

fn stream(name: &str) -> Option<Vec<u8>> {
    let path = format!("{}/tests/fixtures/{name}.ir4", env!("CARGO_MANIFEST_DIR"));
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!("skipping {name}: no fixture at {path} (run tests/fetch-fixtures.sh)");
            None
        }
    }
}

/// Returns each member's TAMP update alongside the label its target URI carries.
fn updates(raw: &[u8]) -> Vec<(String, TampUpdate)> {
    let collection = ContentCollection::from_der(raw).expect("stream is a content collection");
    collection
        .0
        .iter()
        .map(|ci| {
            assert_eq!(ci.content_type, const_oid::db::rfc5911::ID_SIGNED_DATA);
            let sd = ci.content.decode_as::<SignedData>().expect("signed data");
            assert_eq!(
                sd.encap_content_info.econtent_type,
                rfc5934::ID_CT_TAMP_UPDATE,
                "the streams carry the content type RFC 5934 registers, not one of their own"
            );
            let message = TampMessage::from_encapsulated(&sd.encap_content_info)
                .expect("the encapsulated message decodes");
            assert_eq!(message.message_type(), MessageType::Update);
            let TampMessage::Update(update) = message else {
                unreachable!("just asserted the type")
            };
            let target = StreamTarget::parse(&update.msg_ref.target)
                .expect("an InstallRoot target is a three-field URI");
            (target.kind.label().to_string(), update)
        })
        .collect()
}

#[test]
fn every_published_stream_decodes() {
    for (name, expected) in [
        (
            "DoD",
            vec!["RemoveCertificateHintList", "Root", "CA", "Untrusted"],
        ),
        (
            "ECA",
            vec!["RemoveCertificateHintList", "Root", "CA", "Untrusted"],
        ),
        (
            "JITC",
            vec!["RemoveCertificateHintList", "Root", "CA", "Untrusted"],
        ),
        // WCF publishes no Untrusted message, which is why the count is not asserted globally.
        ("WCF", vec!["RemoveCertificateHintList", "Root", "CA"]),
    ] {
        let Some(raw) = stream(name) else { continue };
        let labels: Vec<String> = updates(&raw).into_iter().map(|(l, _)| l).collect();
        assert_eq!(labels, expected, "{name}.ir4 messages");
    }
}

/// The model is right only if what it decodes re-encodes to the same bytes. Anything the crate
/// carries unparsed rides along in that check too, which is the point of carrying it as `Any`.
#[test]
fn updates_round_trip_byte_for_byte() {
    for name in ["DoD", "ECA", "JITC", "WCF"] {
        let Some(raw) = stream(name) else { continue };
        let collection = ContentCollection::from_der(&raw).unwrap();
        for (i, ci) in collection.0.iter().enumerate() {
            let sd = ci.content.decode_as::<SignedData>().unwrap();
            let econtent = sd.encap_content_info.econtent.clone().unwrap();
            let payload = econtent.decode_as::<der::asn1::OctetString>().unwrap();
            let original = payload.as_bytes();
            let update = TampUpdate::from_der(original).unwrap();
            assert_eq!(
                update.to_der().unwrap(),
                original,
                "{name}.ir4 message {i} did not re-encode identically"
            );
        }
        // and the collection itself
        assert_eq!(collection.to_der().unwrap(), raw, "{name}.ir4 collection");
    }
}

#[test]
fn the_dod_root_message_carries_the_four_dod_roots() {
    let Some(raw) = stream("DoD") else { return };
    let (_, root) = updates(&raw)
        .into_iter()
        .find(|(label, _)| label == "Root")
        .expect("DoD publishes a Root message");

    let mut subjects = vec![];
    for entry in &root.updates {
        match entry {
            TrustAnchorUpdate::Add(TrustAnchorChoice::TaInfo(info)) => {
                let cert = info
                    .cert_path
                    .as_ref()
                    .and_then(|p| p.certificate.as_ref())
                    .expect("an InstallRoot anchor carries its certificate");
                subjects.push(cert.tbs_certificate().subject().to_string());
            }
            TrustAnchorUpdate::Add(other) => panic!("unexpected anchor form: {other:?}"),
            TrustAnchorUpdate::Remove(_) | TrustAnchorUpdate::Change(_) => {}
        }
    }
    subjects.sort();
    assert_eq!(
        subjects,
        vec![
            "CN=DoD Root CA 3,OU=PKI,OU=DoD,O=U.S. Government,C=US",
            "CN=DoD Root CA 4,OU=PKI,OU=DoD,O=U.S. Government,C=US",
            "CN=DoD Root CA 5,OU=PKI,OU=DoD,O=U.S. Government,C=US",
            "CN=DoD Root CA 6,OU=PKI,OU=DoD,O=U.S. Government,C=US",
        ],
        "the published root set"
    );
}

/// The published streams put OCSP responses in the CMS `crls` field without the RFC 5940 wrapper
/// that would make them legal there, which is why this crate defers that field instead of using
/// `cms::signed_data::SignedData`. Pinning it here means a stream that is *fixed* one day shows up
/// as a failing test rather than passing silently under the accommodation.
#[test]
fn the_crls_field_carries_bare_ocsp_responses() {
    for name in ["DoD", "ECA", "JITC", "WCF"] {
        let Some(raw) = stream(name) else { continue };
        for (i, ci) in ContentCollection::from_der(&raw)
            .unwrap()
            .0
            .iter()
            .enumerate()
        {
            let signed = ci.content.decode_as::<SignedData>().unwrap();
            match signed.revocation_info().unwrap() {
                Some(RevocationInfo::BareOcspResponses(responses)) => {
                    assert!(!responses.is_empty(), "{name} message {i}");
                }
                Some(RevocationInfo::Conformant(_)) => {
                    panic!("{name} message {i} is now conformant — the accommodation can go")
                }
                None => panic!("{name} message {i} has no crls field"),
            }
        }
    }
}
