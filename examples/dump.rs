//! Prints what a TAMP file contains.
//!
//! ```text
//! cargo run --example dump -- tests/fixtures/DoD.ir4
//! ```
//!
//! Takes either an RFC 4073 content collection — which is what a DoD InstallRoot stream is — or a
//! single CMS message.

use std::env;

use der::{Decode, Encode};
use rfc5934::apex::ApexUpdateConfirm;
use rfc5934::common::{StatusCode, TargetIdentifier};
use rfc5934::community::CommunityConfirm;
use rfc5934::dod::StreamTarget;
use rfc5934::message::TampMessage;
use rfc5934::signed::{RevocationInfo, SignedData};
use rfc5934::status::StatusResponse;
use rfc5934::update::{TampUpdate, TrustAnchorUpdate, UpdateConfirm};
use rfc5934::ContentCollection;
use x509_cert::anchor::TrustAnchorChoice;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: dump <file>")?;
    let raw = std::fs::read(&path)?;

    // A stream is a bare collection; a single message is one ContentInfo. Try the collection first,
    // because a ContentInfo is not a collection but a one-member collection would be ambiguous.
    let members = match ContentCollection::from_der(&raw) {
        Ok(collection) => collection.0,
        Err(_) => vec![cms::content_info::ContentInfo::from_der(&raw)?],
    };
    println!("{path}: {} message(s)\n", members.len());

    for ci in &members {
        let signed = ci.content.decode_as::<SignedData>()?;
        let signers = signed.signer_infos.0.len();
        let chain = signed.certificates.as_ref().map_or(0, |c| c.0.len());
        let revocation = match signed.revocation_info()? {
            None => "none".to_string(),
            Some(RevocationInfo::Conformant(v)) => format!("{} CRL entr(ies)", v.len()),
            Some(RevocationInfo::BareOcspResponses(v)) => {
                format!("{} bare OCSP response(s) — not RFC 5940 wrapped", v.len())
            }
        };

        let message = TampMessage::from_encapsulated(&signed.encap_content_info)?;
        println!(
            "{:?}  ({})",
            message.message_type(),
            signed.encap_content_info.econtent_type
        );
        println!("  {signers} signer(s), {chain} cert(s) in the bag, revocation: {revocation}");
        summarize(&message);
        println!();
    }
    Ok(())
}

fn summarize(message: &TampMessage) {
    match message {
        TampMessage::Update(update) => summarize_update(update),
        TampMessage::UpdateConfirm(confirm) => match &confirm.confirm {
            UpdateConfirm::TerseConfirm(codes) => println!("  {}", codes_line(codes)),
            UpdateConfirm::VerboseConfirm(verbose) => {
                println!("  {}", codes_line(&verbose.status));
                println!("  {} anchor(s) installed afterwards", verbose.ta_info.len());
            }
        },
        TampMessage::StatusResponse(response) => match &response.response {
            StatusResponse::TerseResponse(terse) => {
                println!("  {} anchor(s), by key identifier", terse.ta_key_ids.len())
            }
            StatusResponse::VerboseResponse(verbose) => {
                println!("  {} anchor(s)", verbose.ta_info.len());
                for anchor in &verbose.ta_info {
                    println!("    {}", describe(anchor));
                }
            }
        },
        TampMessage::StatusQuery(query) => println!("  {}", target_line(&query.query.target)),
        TampMessage::ApexUpdate(update) => {
            println!("  {}", describe(&update.apex_ta));
            println!(
                "  clears anchors: {}, clears communities: {}",
                update.clear_trust_anchors, update.clear_communities
            );
        }
        TampMessage::ApexUpdateConfirm(confirm) => match &confirm.apex_confirm {
            ApexUpdateConfirm::TerseApexConfirm(code) => println!("  {code:?}"),
            ApexUpdateConfirm::VerboseApexConfirm(verbose) => println!(
                "  {:?}, {} anchor(s) afterwards",
                verbose.status,
                verbose.ta_info.len()
            ),
        },
        TampMessage::CommunityUpdate(update) => println!(
            "  remove {}, add {}",
            update.updates.remove.as_ref().map_or(0, |c| c.len()),
            update.updates.add.as_ref().map_or(0, |c| c.len())
        ),
        TampMessage::CommunityUpdateConfirm(confirm) => match &confirm.comm_confirm {
            CommunityConfirm::TerseCommConfirm(code) => println!("  {code:?}"),
            CommunityConfirm::VerboseCommConfirm(verbose) => println!(
                "  {:?}, {} community/ies afterwards",
                verbose.status,
                verbose.communities.as_ref().map_or(0, |c| c.len())
            ),
        },
        TampMessage::SequenceNumberAdjust(adjust) => println!(
            "  {} → seq {}",
            target_line(&adjust.msg_ref.target),
            adjust.msg_ref.seq_num
        ),
        TampMessage::SequenceNumberAdjustConfirm(confirm) => println!("  {:?}", confirm.status),
        TampMessage::Error(error) => println!("  {:?} processing {}", error.status, error.msg_type),
    }
}

fn summarize_update(update: &TampUpdate) {
    println!(
        "  {}, seq {}",
        target_line(&update.msg_ref.target),
        update.msg_ref.seq_num
    );

    let (mut added, mut removed, mut changed) = (0, 0, 0);
    for entry in &update.updates {
        match entry {
            TrustAnchorUpdate::Add(choice) => {
                added += 1;
                println!("    + {}", describe(choice));
            }
            TrustAnchorUpdate::Remove(spki) => {
                removed += 1;
                let key = spki.to_der().map(|d| d.len()).unwrap_or(0);
                println!("    - key of {} bytes ({})", key, spki.algorithm.oid);
            }
            TrustAnchorUpdate::Change(_) => changed += 1,
        }
    }
    println!("  {added} added, {removed} removed, {changed} changed");
}

/// The target, with the InstallRoot label spelled out when it carries one.
fn target_line(target: &TargetIdentifier) -> String {
    match StreamTarget::parse(target) {
        Some(stream) => format!(
            "{} / {} / {}",
            stream.url,
            stream.stream,
            stream.kind.label()
        ),
        None => match target {
            TargetIdentifier::Uri(uri) => uri.as_str().to_string(),
            TargetIdentifier::AllModules(_) => "all modules".to_string(),
            other => format!("{other:?}"),
        },
    }
}

fn codes_line(codes: &[StatusCode]) -> String {
    let failures = codes.iter().filter(|c| !c.is_success()).count();
    format!("{} status code(s), {failures} not success", codes.len())
}

/// The subject of the certificate an anchor carries, when it carries one.
fn describe(choice: &TrustAnchorChoice) -> String {
    let subject = match choice {
        TrustAnchorChoice::Certificate(cert) => Some(cert.tbs_certificate().subject().to_string()),
        TrustAnchorChoice::TbsCertificate(tbs) => Some(tbs.subject().to_string()),
        TrustAnchorChoice::TaInfo(info) => info
            .cert_path
            .as_ref()
            .and_then(|p| p.certificate.as_ref())
            .map(|c| c.tbs_certificate().subject().to_string()),
    };
    subject.unwrap_or_else(|| "(anchor carrying no certificate)".to_string())
}
