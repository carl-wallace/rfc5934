# rfc5934

Trust Anchor Management Protocol ([RFC 5934]) message types in Rust, with the [RFC 4073] content
collection that carries them. Built on [RustCrypto formats]: `der` for the encoding, `x509-cert` for
RFC 5914 trust anchors, `cms` for the signature envelope.

Decoding and encoding both, from the same derived types — a message that decodes re-encodes to the
same bytes, which the tests assert against real published streams.

## What it covers

- **RFC 5934**, all eleven messages: status query and response, trust anchor update and confirm,
  apex update and confirm, community update and confirm, sequence number adjust and confirm, and the
  error message. Plus the `ApexContingencyKey` certificate extension and the contingency key
  attribute. [`message::MessageType`] maps each to its content type, media type and file extension;
  [`message::TampMessage`] decodes whichever one a CMS `EncapsulatedContentInfo` turns out to hold.
- **RFC 4073** `ContentCollection` and `ContentWithAttributes`. Neither is in the `cms` crate today;
  they are CMS companions and would sit naturally there if contributed upstream.
- A **`SignedData` that tolerates what publishers emit** — see below.
- The **DoD InstallRoot profile**, in [`dod`] and nowhere else: everything local to those streams is
  in one module, so the rest of the crate is the protocol as specified.

Only the trust anchor update has published samples to test against. The other ten are modelled from
the ASN.1 module alone, and are pinned by hand-derived byte vectors rather than by round-tripping
alone — round-tripping proves a model self-consistent, not correct.

## Status response

The one part of TAMP worth reading even if you never send a TAMP message. A
[`status::TampStatusResponse`] is a signed, self-describing statement of what trust anchors a store
actually holds — terse as a list of key identifiers, verbose as the anchors themselves, either way
with the store's communities and the sequence numbers it has recorded. Two stores that have never
heard of each other can be compared by putting each one's contents in that shape, and
[`status::VerboseStatusResponse::terse`] does the reduction a comparison usually runs on.

## DoD InstallRoot

The streams at `crl.gds.disa.mil/pke/config` (`DoD`, `ECA`, `JITC`, `WCF`) are RFC 4073 collections
of separately signed RFC 5934 updates — four messages each, three for WCF. Three things about them
are worth knowing before you write a decoder.

**The content type is the registered one.** `2.16.840.1.101.2.1.2.77.3` looks DoD-private because of
where the arc sits, and is not: RFC 5934 §11 records that arc as one IANA delegated to the PKIX
working group, and `{ id-tamp 3 }` is exactly `id-ct-TAMP-update`. See [`oid::ID_CT_TAMP_UPDATE`].

**A message's meaning comes from its label**, carried in `TAMPMsgRef.target` as
`<url>;<stream>;<kind>` — `Root`, `CA`, `Untrusted`, `RemoveCertificateHintList`. The entries inside
a `RemoveCertificateHintList` are the same `add` entries as anywhere else, so the kind rather than
the entry tag says what to do with them. That mapping is DoD profile, not RFC 5934, and it lives in
[`dod::StreamTarget`].

**OCSP responses appear directly in the CMS `crls` field**, as bare `SEQUENCE`s. RFC 5652 permits
only a `CertificateList` there unless the entry is wrapped as `other [1] OtherRevocationInfoFormat`
with `id-ri-ocsp-response` ([RFC 5940]), so a conformant decoder — `cms` included — rejects the whole
message, trust anchor update and all. This crate defers that one field rather than forking CMS or
rewriting the input: [`signed::SignedData`] keeps `crls` as raw ASN.1 and
[`signed::SignedData::revocation_info`] interprets it, conformant reading first. Deferring also
leaves the original bytes intact, which is what signature verification needs.

## Two places the RFC disagrees with itself

Recorded here because both cost a reader time, and this crate had to choose.

- **`ApexContingencyKey`**: §9 makes both fields OPTIONAL and explains why — an empty extension marks
  a key as an apex anchor without publishing contingency material — while the module in Appendix A
  makes both mandatory. Modelled as optional, following §9.
- **`TAMPVersion`** is `INTEGER { v1(1), v2(2) }`, a named-number INTEGER rather than an ENUMERATED,
  so an unrecognized version is well formed and gets answered with `versionNumberMismatch`. Modelled
  as an integer, not an enum, so that answer is possible.

## Trying it

```sh
tests/fetch-fixtures.sh                              # downloads the four streams
cargo run --example dump -- tests/fixtures/DoD.ir4   # prints what one contains
cargo test
```

The fixtures are deliberately not committed: they are someone else's published trust material and
they change without notice. Every test that needs them skips when they are absent, so a checkout
without them passes.

[RFC 4073]: https://www.rfc-editor.org/rfc/rfc4073
[RFC 5934]: https://www.rfc-editor.org/rfc/rfc5934
[RFC 5940]: https://www.rfc-editor.org/rfc/rfc5940
[RustCrypto formats]: https://github.com/RustCrypto/formats
