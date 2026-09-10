//! The ten TAMP messages that are not the trust anchor update.
//!
//! No sample of any of them appears to be published — TAMP shipped into closed systems, and the
//! only streams in the open are DoD InstallRoot updates. So these tests do two different jobs:
//!
//! - **Round-tripping** every message type proves the model is self-consistent, and nothing more.
//!   A field in the wrong order or under the wrong tag round-trips perfectly.
//! - **Byte vectors**, hand-derived from the ASN.1 in RFC 5934 Appendix A, are what actually pin
//!   the encoding. They are deliberately small — a NULL target, a one-arc OID, an empty key — so
//!   that every byte can be read against the module by eye. The ones chosen cover the decisions a
//!   reader of the module has to make: the order of `TAMPUpdate`'s fields, EXPLICIT versus IMPLICIT
//!   on a tagged CHOICE, and whether a tagged ENUMERATED stays primitive.

use der::asn1::{BitString, Ia5String, Null, OctetString};
use der::{Decode, Encode};
use hex_literal::hex;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::anchor::{TrustAnchorChoice, TrustAnchorInfo};

use rfc5934::apex::{ApexUpdateConfirm, TampApexUpdate, TampApexUpdateConfirm};
use rfc5934::common::{
    CommunityIdentifierList, HardwareModules, HardwareSerialEntry, StatusCode, TampMsgRef,
    TampSequenceNumber, TargetIdentifier, TerseOrVerbose, V2,
};
use rfc5934::community::{
    CommunityConfirm, CommunityUpdates, TampCommunityUpdate, TampCommunityUpdateConfirm,
    VerboseCommunityConfirm,
};
use rfc5934::error::TampError;
use rfc5934::message::{MessageType, TampMessage};
use rfc5934::seqnum::{SequenceNumberAdjust, SequenceNumberAdjustConfirm};
use rfc5934::status::{
    StatusResponse, TampStatusQuery, TampStatusResponse, TerseStatusResponse, VerboseStatusResponse,
};
use rfc5934::update::{TampUpdate, TampUpdateConfirm, TrustAnchorUpdate, UpdateConfirm};

/// `1.2.3`, which encodes as two bytes and belongs to nobody.
const OID: const_oid::ObjectIdentifier = const_oid::ObjectIdentifier::new_unwrap("1.2.3");

/// `SEQUENCE { SEQUENCE { 1.2.3 }, BIT STRING (0 unused, empty) }` — eleven bytes of valid
/// `SubjectPublicKeyInfo` carrying no key at all.
fn spki() -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: OID,
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(&[]).unwrap(),
    }
}

fn key_id() -> OctetString {
    OctetString::new(vec![0xAA]).unwrap()
}

fn anchor() -> TrustAnchorChoice {
    TrustAnchorChoice::TaInfo(TrustAnchorInfo {
        version: Default::default(),
        pub_key: spki(),
        key_id: key_id(),
        ta_title: None,
        cert_path: None,
        extensions: None,
        ta_title_lang_tag: None,
    })
}

/// `{ allModules, 1 }` — the smallest legal message reference.
fn msg_ref() -> TampMsgRef {
    TampMsgRef {
        target: TargetIdentifier::AllModules(Null),
        seq_num: 1,
    }
}

fn communities() -> CommunityIdentifierList {
    vec![OID]
}

// ---------------------------------------------------------------------------------------------
// Byte vectors
// ---------------------------------------------------------------------------------------------

/// ```text
/// SEQUENCE {                    30 07
///   SEQUENCE {                    30 05     -- TAMPMsgRef
///     [3] NULL                      83 00   -- allModules
///     INTEGER 1 } }                 02 01 01
/// ```
///
/// `version` is absent because it holds its default, which DER requires.
#[test]
fn sequence_number_adjust_encodes_as_the_module_says() {
    let adjust = SequenceNumberAdjust {
        version: None,
        msg_ref: msg_ref(),
    };
    assert_eq!(adjust.to_der().unwrap(), hex!("3007 3005 8300 020101"));
}

/// ```text
/// SEQUENCE {                    30 0f
///   OBJECT IDENTIFIER             06 0a 60 86 48 01 65 02 01 02 4d 03  -- id-ct-TAMP-update
///   ENUMERATED 1 }                0a 01 01                             -- decodeFailure
/// ```
///
/// The identifier in `msgType` is worth reading closely: `2.16.840.1.101.2.1.2.77.3` is the content
/// type RFC 5934 registers for a trust anchor update, and the same one DoD InstallRoot streams
/// carry. The arc under `2.16.840.1.101` is where IANA delegated TAMP's identifiers.
#[test]
fn tamp_error_encodes_as_the_module_says() {
    let error = TampError {
        version: None,
        msg_type: MessageType::Update.oid(),
        status: StatusCode::DecodeFailure,
        msg_ref: None,
    };
    assert_eq!(
        error.to_der().unwrap(),
        hex!("300f 060a 60 86 48 01 65 02 01 02 4d 03 0a0101"),
    );
}

/// ```text
/// SEQUENCE {                    30 13
///   [1] ENUMERATED 1              81 01 01           -- terse, primitive under an implicit tag
///   SEQUENCE {                    30 06              -- TAMPMsgRef
///     [4] IA5String "x"             84 01 78         -- uri
///     INTEGER 0 }                   02 01 00
///   SEQUENCE {                    30 06              -- CommunityUpdates
///     [2] {                         a2 04            -- add
///       OBJECT IDENTIFIER             06 02 2a 03 } } }
/// ```
#[test]
fn community_update_encodes_as_the_module_says() {
    let update = TampCommunityUpdate {
        version: None,
        terse: Some(TerseOrVerbose::Terse),
        msg_ref: TampMsgRef {
            target: TargetIdentifier::Uri(Ia5String::new("x").unwrap()),
            seq_num: 0,
        },
        updates: CommunityUpdates {
            remove: None,
            add: Some(communities()),
        },
    };
    assert_eq!(
        update.to_der().unwrap(),
        hex!("3013 810101 3006 840178 020100 3006 a204 06022a03"),
    );
}

/// ```text
/// SEQUENCE {                    30 0a
///   SEQUENCE {                    30 05      -- TAMPMsgRef
///     [3] NULL                      83 00
///     INTEGER 1 }                   02 01 01
///   [0] 00 }                      80 01 00   -- terseApexConfirm: success
/// ```
///
/// `TerseApexUpdateConfirm ::= StatusCode`, an ENUMERATED, so the `[0]` tag replaces the ENUMERATED
/// tag and stays **primitive**: `80`, not `a0`. Reading `[0]` as constructed — the reflex, since
/// most tagged things in this module are SEQUENCEs — produces a confirm no target will parse.
#[test]
fn terse_apex_update_confirm_keeps_a_primitive_tag() {
    let confirm = TampApexUpdateConfirm {
        version: None,
        apex_replace: msg_ref(),
        apex_confirm: ApexUpdateConfirm::TerseApexConfirm(StatusCode::Success),
    };
    assert_eq!(
        confirm.to_der().unwrap(),
        hex!("300a 3005 8300 020101 800100"),
    );
}

/// ```text
/// SEQUENCE {                    30 1a
///   [0] INTEGER 2                 80 01 02        -- version, spelled out
///   [1] ENUMERATED 2              81 01 02        -- terse: verbose, spelled out
///   SEQUENCE {                    30 05           -- msgRef
///     [3] NULL                      83 00
///     INTEGER 1 }                   02 01 01
///   SEQUENCE {                    30 0b           -- updates
///     [2] {                         a2 09         -- remove: SubjectPublicKeyInfo, IMPLICIT
///       SEQUENCE { 1.2.3 }            30 04 06 02 2a 03
///       BIT STRING } } }              03 01 00
/// ```
///
/// This is the vector that pins field order. `version` and `terse` are both encoded here even
/// though they hold their defaults — which a conformant encoder would not do — precisely so that
/// their positions are visible: RFC 5934 puts `terse` **before** `msgRef`, not after `updates`.
/// Published streams omit both, so no InstallRoot file can catch the ordering being wrong.
#[test]
fn update_puts_terse_before_the_message_reference() {
    let update = TampUpdate {
        version: Some(V2),
        terse: Some(TerseOrVerbose::Verbose),
        msg_ref: msg_ref(),
        updates: vec![TrustAnchorUpdate::Remove(spki())],
        tamp_seq_numbers: None,
    };
    assert_eq!(
        update.to_der().unwrap(),
        hex!("301a 800102 810102 3005 8300 020101 300b a209 300406022a03 030100"),
    );
}

/// ```text
/// SEQUENCE {                    30 1d
///   SEQUENCE {                    30 05             -- msgRef
///     [3] NULL  INTEGER 1 }         83 00 02 01 01
///   SEQUENCE {                    30 14             -- updates
///     [1] {                         a1 12           -- add, EXPLICIT
///       [2] {                         a2 10         -- TrustAnchorChoice: taInfo, EXPLICIT
///         SEQUENCE {                    30 0e       -- TrustAnchorInfo
///           SEQUENCE {                    30 09     -- pubKey
///             SEQUENCE { 1.2.3 }            30 04 06 02 2a 03
///             BIT STRING }                  03 01 00
///           OCTET STRING aa } } } } }       04 01 aa  -- keyId
/// ```
///
/// Two context tags in a row, `a1 a2`, is the whole point of this vector: `add [1]
/// TrustAnchorChoice` tags a CHOICE, which cannot take an implicit tag, and `TrustAnchorChoice`'s
/// own `taInfo [2]` is explicit for the same reason. An encoder that collapses either pair
/// produces bytes that decode as something else entirely.
#[test]
fn adding_an_anchor_nests_two_explicit_tags() {
    let update = TampUpdate {
        version: None,
        terse: None,
        msg_ref: msg_ref(),
        updates: vec![TrustAnchorUpdate::Add(anchor())],
        tamp_seq_numbers: None,
    };
    assert_eq!(
        update.to_der().unwrap(),
        hex!("301d 3005 8300 020101 3014 a112 a210 300e 3009 300406022a03 030100 0401aa"),
    );
}

// ---------------------------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------------------------

/// One of every message, built to exercise the optional fields rather than to be minimal.
fn one_of_each() -> Vec<TampMessage> {
    vec![
        TampMessage::StatusQuery(TampStatusQuery {
            version: Some(V2),
            terse: Some(TerseOrVerbose::Terse),
            query: msg_ref(),
        }),
        TampMessage::StatusResponse(TampStatusResponse {
            version: None,
            query: msg_ref(),
            response: StatusResponse::VerboseResponse(VerboseStatusResponse {
                ta_info: vec![anchor()],
                contin_pub_key_decrypt_alg: Some(AlgorithmIdentifierOwned {
                    oid: OID,
                    parameters: None,
                }),
                communities: Some(communities()),
                tamp_seq_numbers: Some(vec![TampSequenceNumber {
                    key_id: key_id(),
                    seq_number: 7,
                }]),
            }),
            uses_apex: Some(false),
        }),
        TampMessage::Update(TampUpdate {
            version: None,
            terse: None,
            msg_ref: TampMsgRef {
                target: TargetIdentifier::HwModules(vec![HardwareModules {
                    hw_type: OID,
                    hw_serial_entries: vec![
                        HardwareSerialEntry::All(Null),
                        HardwareSerialEntry::Single(key_id()),
                    ],
                }]),
                seq_num: 2,
            },
            updates: vec![
                TrustAnchorUpdate::Add(anchor()),
                TrustAnchorUpdate::Remove(spki()),
            ],
            tamp_seq_numbers: Some(vec![TampSequenceNumber {
                key_id: key_id(),
                seq_number: 9,
            }]),
        }),
        TampMessage::UpdateConfirm(TampUpdateConfirm {
            version: None,
            update: msg_ref(),
            confirm: UpdateConfirm::TerseConfirm(vec![StatusCode::Success, StatusCode::Other]),
        }),
        TampMessage::ApexUpdate(TampApexUpdate {
            version: None,
            terse: None,
            msg_ref: msg_ref(),
            clear_trust_anchors: true,
            clear_communities: false,
            seq_number: Some(3),
            apex_ta: anchor(),
        }),
        TampMessage::ApexUpdateConfirm(TampApexUpdateConfirm {
            version: None,
            apex_replace: msg_ref(),
            apex_confirm: ApexUpdateConfirm::TerseApexConfirm(StatusCode::SeqNumFailure),
        }),
        TampMessage::CommunityUpdate(TampCommunityUpdate {
            version: None,
            terse: None,
            msg_ref: TampMsgRef {
                target: TargetIdentifier::Communities(communities()),
                seq_num: 4,
            },
            updates: CommunityUpdates {
                remove: Some(communities()),
                add: Some(vec![]),
            },
        }),
        TampMessage::CommunityUpdateConfirm(TampCommunityUpdateConfirm {
            version: None,
            update: msg_ref(),
            comm_confirm: CommunityConfirm::VerboseCommConfirm(VerboseCommunityConfirm {
                status: StatusCode::CommunityUpdateFailed,
                communities: Some(communities()),
            }),
        }),
        TampMessage::SequenceNumberAdjust(SequenceNumberAdjust {
            version: None,
            msg_ref: msg_ref(),
        }),
        TampMessage::SequenceNumberAdjustConfirm(SequenceNumberAdjustConfirm {
            version: None,
            adjust: msg_ref(),
            status: StatusCode::Success,
        }),
        TampMessage::Error(TampError {
            version: Some(V2),
            msg_type: MessageType::StatusQuery.oid(),
            status: StatusCode::UnsupportedTargetIdentifier,
            msg_ref: Some(msg_ref()),
        }),
    ]
}

#[test]
fn every_message_type_round_trips() {
    let messages = one_of_each();
    assert_eq!(
        messages.len(),
        MessageType::ALL.len(),
        "one message per type, in the same order"
    );

    for (message, message_type) in messages.iter().zip(MessageType::ALL) {
        assert_eq!(message.message_type(), message_type);
        let der = message.to_der().unwrap();
        let decoded = TampMessage::from_der(message_type, &der).expect("decodes");
        assert_eq!(
            &decoded, message,
            "{message_type:?} did not survive a round trip"
        );
        assert_eq!(
            decoded.to_der().unwrap(),
            der,
            "{message_type:?} re-encoded differently"
        );
    }
}

#[test]
fn every_content_type_is_distinct_and_under_the_tamp_arc() {
    let mut seen = std::collections::HashSet::new();
    for message_type in MessageType::ALL {
        let oid = message_type.oid();
        assert!(
            oid.as_bytes().starts_with(rfc5934::oid::ID_TAMP.as_bytes()),
            "{message_type:?} is not under id-tamp"
        );
        assert_eq!(MessageType::from_oid(oid), Some(message_type));
        assert!(seen.insert(oid), "{message_type:?} shares an OID");
    }
    assert_eq!(
        MessageType::from_oid(OID),
        None,
        "1.2.3 is not a TAMP message"
    );
}

/// Media types and file extensions are registrations, not derivations — the two sequence number
/// messages say `sequence-adjust` where their ASN.1 says `seqNumAdjust` — so they are worth
/// pinning against RFC 5934 Appendix B rather than assumed to follow from the name.
#[test]
fn media_types_match_the_registrations() {
    assert_eq!(
        MessageType::SequenceNumberAdjust.media_type(),
        "application/tamp-sequence-adjust"
    );
    assert_eq!(MessageType::SequenceNumberAdjust.file_extension(), "tsa");
    assert_eq!(
        MessageType::ApexUpdateConfirm.media_type(),
        "application/tamp-apex-update-confirm"
    );
    assert_eq!(MessageType::ApexUpdateConfirm.file_extension(), "auc");

    let mut media_types = std::collections::HashSet::new();
    let mut extensions = std::collections::HashSet::new();
    for message_type in MessageType::ALL {
        assert!(
            media_types.insert(message_type.media_type()),
            "duplicate media type"
        );
        assert!(
            extensions.insert(message_type.file_extension()),
            "duplicate extension"
        );
    }
}

/// The reduction a comparison of two trust anchor stores actually runs on: identity by key
/// identifier, whatever form each store keeps its anchors in.
#[test]
fn a_verbose_status_response_reduces_to_a_terse_one() {
    let verbose = VerboseStatusResponse {
        ta_info: vec![anchor()],
        contin_pub_key_decrypt_alg: None,
        communities: Some(communities()),
        tamp_seq_numbers: None,
    };
    assert_eq!(
        verbose.terse(),
        Some(TerseStatusResponse {
            ta_key_ids: vec![key_id()],
            communities: Some(communities()),
        })
    );
}

/// An anchor kept as a bare certificate is identified by its subject key identifier extension,
/// which is the other half of the reduction: a store that holds certificates and one that holds
/// `TrustAnchorInfo`s must produce comparable identifiers, or comparing them is meaningless.
///
/// Uses a real certificate — hand-built anchors carry no extensions, so they cannot reach this
/// path — and skips when the fixtures are absent, as the rest of the suite does.
#[test]
fn a_certificate_anchor_is_identified_by_its_subject_key_identifier() {
    let path = format!("{}/tests/fixtures/DoD.ir4", env!("CARGO_MANIFEST_DIR"));
    let Ok(raw) = std::fs::read(&path) else {
        eprintln!("skipping: no fixture at {path} (run tests/fetch-fixtures.sh)");
        return;
    };
    let cert = first_certificate(&raw).expect("the stream's signer chain has a certificate");
    let expected = cert
        .tbs_certificate()
        .extensions()
        .and_then(|exts| {
            exts.iter()
                .find(|ext| ext.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER)
        })
        .expect("a CA certificate carries a subject key identifier");

    let verbose = VerboseStatusResponse {
        ta_info: vec![TrustAnchorChoice::Certificate(cert.clone())],
        contin_pub_key_decrypt_alg: None,
        communities: None,
        tamp_seq_numbers: None,
    };
    let terse = verbose.terse().expect("the certificate has an identifier");
    assert_eq!(
        terse.ta_key_ids[0].to_der().unwrap(),
        expected.extn_value.as_bytes(),
        "the identifier is the extension's value, not a hash computed here"
    );
}

/// The first certificate in a stream's signer chain.
fn first_certificate(raw: &[u8]) -> Option<x509_cert::Certificate> {
    use cms::cert::CertificateChoices;
    let collection = rfc5934::ContentCollection::from_der(raw).ok()?;
    let signed = collection
        .0
        .first()?
        .content
        .decode_as::<rfc5934::signed::SignedData>()
        .ok()?;
    match signed.certificates?.0.iter().next()? {
        CertificateChoices::Certificate(cert) => Some(cert.clone()),
        _ => None,
    }
}
