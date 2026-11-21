//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! X.509 certificates and CRLs, with ECDSA signature verification.

use std::ops::Range;
use std::time::SystemTime;

use base64::Engine as _;
use der::asn1::BitString;
use der::oid::ObjectIdentifier;
use der::oid::db::rfc5912;
use der::{Decode, Header, Reader, SliceReader, Tag};
use graviola::hashing::{Hash, Sha256, Sha384};
use graviola::signing::ecdsa::{Curve, P256, P384, VerifyingKey};
use x509_cert::crl::CertificateList;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::Time;

use crate::error::ContextError;

pub(crate) struct X509ErrorDomain;
pub(crate) type Error = ContextError<X509ErrorDomain>;

type Result<T, E = Error> = std::result::Result<T, E>;

/// A parsed X.509 certificate that keeps its DER encoding.
#[derive(Clone, Debug)]
pub(crate) struct Certificate {
    der: Vec<u8>,
    tbs: Range<usize>,
    inner: x509_cert::Certificate,
}

impl Certificate {
    pub fn from_der(der: Vec<u8>) -> Result<Self> {
        let inner = x509_cert::Certificate::from_der(&der)?;
        let tbs = tbs_range(&der)?;
        Ok(Self { der, tbs, inner })
    }

    /// Parses every `CERTIFICATE` PEM block in `data`, ignoring text around the blocks.
    ///
    /// The base64 text may be wrapped at any width.
    pub fn from_pem_chain(data: &[u8]) -> Result<Vec<Self>> {
        const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
        const END: &[u8] = b"-----END CERTIFICATE-----";

        let mut certs = Vec::new();
        let mut rest = data;
        while let Some(start) = find(rest, BEGIN) {
            let block = &rest[start + BEGIN.len()..];
            let end = find(block, END).ok_or_else(|| Error::new("unterminated PEM certificate"))?;
            let base64_text: Vec<u8> = block[..end]
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(base64_text)
                .map_err(|e| Error::new(format!("invalid PEM certificate: {e}")))?;
            certs.push(Self::from_der(der)?);
            rest = &block[end + END.len()..];
        }

        Ok(certs)
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn subject(&self) -> &Name {
        self.inner.tbs_certificate().subject()
    }

    pub fn issuer(&self) -> &Name {
        self.inner.tbs_certificate().issuer()
    }

    pub fn serial_number(&self) -> &SerialNumber {
        self.inner.tbs_certificate().serial_number()
    }

    pub fn not_before(&self) -> Time {
        self.inner.tbs_certificate().validity().not_before
    }

    pub fn not_after(&self) -> Time {
        self.inner.tbs_certificate().validity().not_after
    }

    /// The first common name in the subject, if it is a string.
    pub fn common_name(&self) -> Option<String> {
        let common_name = self.subject().common_name().ok()??;
        Some(common_name.value().into_owned())
    }

    pub fn extensions(&self) -> &[Extension] {
        self.inner
            .tbs_certificate()
            .extensions()
            .map_or(&[], Vec::as_slice)
    }

    /// Returns the extension identified by `oid`, failing if it appears more than once.
    pub fn extension(&self, oid: ObjectIdentifier) -> Result<Option<&Extension>> {
        unique_extension(self.extensions(), oid)
    }

    pub fn basic_constraints(&self) -> Result<Option<BasicConstraints>> {
        decode_extension(self.extensions(), rfc5912::ID_CE_BASIC_CONSTRAINTS)
    }

    pub fn key_usage(&self) -> Result<Option<KeyUsage>> {
        decode_extension(self.extensions(), rfc5912::ID_CE_KEY_USAGE)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki(self.inner.tbs_certificate().subject_public_key_info())
    }

    pub fn is_valid_at(&self, timestamp: SystemTime) -> bool {
        self.not_before().to_system_time() <= timestamp
            && timestamp <= self.not_after().to_system_time()
    }

    pub fn is_self_issued(&self) -> bool {
        self.is_issued_by(self)
    }

    /// Whether `issuer` names this certificate's issuer and may sign certificates.
    ///
    /// This does not check the signature.
    pub fn is_issued_by(&self, issuer: &Certificate) -> bool {
        if self.issuer() != issuer.subject() {
            return false;
        }

        if !self.authority_key_id_matches(issuer).unwrap_or(false) {
            return false;
        }

        match issuer.key_usage() {
            Ok(Some(key_usage)) => key_usage.key_cert_sign(),
            Ok(None) => true,
            Err(_) => false,
        }
    }

    /// Fails if any extension is duplicated, is critical and not understood, or is a standard
    /// extension that does not decode.
    pub fn check_extensions(&self) -> Result<()> {
        const HANDLED_CRITICAL: [ObjectIdentifier; 2] =
            [rfc5912::ID_CE_BASIC_CONSTRAINTS, rfc5912::ID_CE_KEY_USAGE];

        check_extensions(self.extensions(), &HANDLED_CRITICAL)?;

        let basic_constraints = self.basic_constraints()?;
        if basic_constraints
            .is_some_and(|constraints| !constraints.ca && constraints.path_len_constraint.is_some())
        {
            return Err(Error::new("path length constraint on a non-CA certificate"));
        }
        self.key_usage()?;
        decode_extension::<AuthorityKeyIdentifier>(
            self.extensions(),
            rfc5912::ID_CE_AUTHORITY_KEY_IDENTIFIER,
        )?;
        decode_extension::<SubjectKeyIdentifier>(
            self.extensions(),
            rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER,
        )?;

        Ok(())
    }

    /// Verifies that this certificate is signed by `issuer_key`.
    pub fn verify_signature(&self, issuer_key: &PublicKey) -> Result<()> {
        let tbs_algorithm = self.inner.tbs_certificate().signature();
        if tbs_algorithm != self.inner.signature_algorithm() {
            return Err(Error::new("certificate signature algorithms differ"));
        }
        verify_signed(
            issuer_key,
            self.inner.signature_algorithm(),
            &self.der[self.tbs.clone()],
            self.inner.signature(),
        )
    }

    fn authority_key_id_matches(&self, issuer: &Certificate) -> Result<bool> {
        let Some(authority_key_id) = decode_extension::<AuthorityKeyIdentifier>(
            self.extensions(),
            rfc5912::ID_CE_AUTHORITY_KEY_IDENTIFIER,
        )?
        else {
            return Ok(true);
        };

        if let Some(key_id) = &authority_key_id.key_identifier {
            let subject_key_id = decode_extension::<SubjectKeyIdentifier>(
                issuer.extensions(),
                rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER,
            )?;
            if subject_key_id.is_some_and(|subject_key_id| &subject_key_id.0 != key_id) {
                return Ok(false);
            }
        }

        if let Some(serial_number) = &authority_key_id.authority_cert_serial_number
            && serial_number != issuer.serial_number()
        {
            return Ok(false);
        }

        if let Some(names) = &authority_key_id.authority_cert_issuer
            && !names.iter().any(
                |name| matches!(name, GeneralName::DirectoryName(name) if name == issuer.issuer()),
            )
        {
            return Ok(false);
        }

        Ok(true)
    }
}

/// A parsed X.509 certificate revocation list.
#[derive(Clone, Debug)]
pub(crate) struct Crl {
    der: Vec<u8>,
    tbs: Range<usize>,
    inner: CertificateList,
}

impl Crl {
    pub fn from_der(der: Vec<u8>) -> Result<Self> {
        let inner = CertificateList::from_der(&der)?;
        let tbs = tbs_range(&der)?;
        Ok(Self { der, tbs, inner })
    }

    pub fn issuer(&self) -> &Name {
        &self.inner.tbs_cert_list.issuer
    }

    pub fn this_update(&self) -> Time {
        self.inner.tbs_cert_list.this_update
    }

    pub fn next_update(&self) -> Option<Time> {
        self.inner.tbs_cert_list.next_update
    }

    pub fn extensions(&self) -> &[Extension] {
        self.inner
            .tbs_cert_list
            .crl_extensions
            .as_deref()
            .unwrap_or(&[])
    }

    /// Whether the CRL has been issued and has not passed its next update time.
    ///
    /// A CRL without a next update time stays current.
    pub fn is_current_at(&self, timestamp: SystemTime) -> bool {
        self.this_update().to_system_time() <= timestamp
            && self
                .next_update()
                .is_none_or(|next_update| timestamp < next_update.to_system_time())
    }

    /// Fails for delta and partitioned CRLs, and for critical extensions this code does not
    /// understand, since such CRLs do not list every revoked certificate.
    pub fn check_extensions(&self) -> Result<()> {
        const SCOPED: [ObjectIdentifier; 2] = [
            rfc5912::ID_CE_ISSUING_DISTRIBUTION_POINT,
            rfc5912::ID_CE_DELTA_CRL_INDICATOR,
        ];

        if self
            .extensions()
            .iter()
            .any(|extension| SCOPED.contains(&extension.extn_id))
        {
            return Err(Error::new("delta or partitioned CRLs are not supported"));
        }
        check_extensions(self.extensions(), &[])?;

        for revoked in self.revoked() {
            check_extensions(revoked.crl_entry_extensions.as_deref().unwrap_or(&[]), &[])?;
        }

        Ok(())
    }

    pub fn is_revoked(&self, serial_number: &SerialNumber) -> bool {
        self.revoked()
            .iter()
            .any(|revoked| &revoked.serial_number == serial_number)
    }

    /// Verifies that this CRL is signed by `issuer_key`.
    pub fn verify_signature(&self, issuer_key: &PublicKey) -> Result<()> {
        if self.inner.tbs_cert_list.signature != self.inner.signature_algorithm {
            return Err(Error::new("CRL signature algorithms differ"));
        }
        verify_signed(
            issuer_key,
            &self.inner.signature_algorithm,
            &self.der[self.tbs.clone()],
            &self.inner.signature,
        )
    }

    fn revoked(&self) -> &[x509_cert::crl::RevokedCert] {
        self.inner
            .tbs_cert_list
            .revoked_certificates
            .as_deref()
            .unwrap_or(&[])
    }
}

/// The hash an ECDSA signature is computed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignatureHash {
    Sha256,
    Sha384,
}

/// How an ECDSA signature is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignatureEncoding {
    /// An ASN.1 `ECDSA-Sig-Value`, as used in X.509.
    Der,
    /// The big-endian scalars `r || s`, each the size of the curve order.
    Fixed,
}

/// An ECDSA public key on P-256 or P-384.
pub(crate) enum PublicKey {
    P256(VerifyingKey<P256>),
    P384(VerifyingKey<P384>),
}

impl PublicKey {
    pub fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<Self> {
        if spki.algorithm.oid != rfc5912::ID_EC_PUBLIC_KEY {
            return Err(Error::new(format!(
                "unsupported public key algorithm {}",
                spki.algorithm.oid
            )));
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .ok_or_else(|| Error::new("EC public key is missing its curve"))?
            .decode_as::<ObjectIdentifier>()?;
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| Error::new("EC public key has unused bits"))?;

        if curve == rfc5912::SECP_256_R_1 {
            Ok(Self::P256(VerifyingKey::from_x962_uncompressed(point)?))
        } else if curve == rfc5912::SECP_384_R_1 {
            Ok(Self::P384(VerifyingKey::from_x962_uncompressed(point)?))
        } else {
            Err(Error::new(format!("unsupported curve {curve}")))
        }
    }

    /// Parses a P-256 public key from the uncompressed point `0x04 || x || y`.
    pub fn p256_from_x962_uncompressed(point: &[u8]) -> Result<Self> {
        Ok(Self::P256(VerifyingKey::from_x962_uncompressed(point)?))
    }

    pub fn verify(
        &self,
        hash: SignatureHash,
        encoding: SignatureEncoding,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let result = match (self, hash) {
            (Self::P256(key), SignatureHash::Sha256) => {
                verify_with::<_, Sha256>(key, encoding, message, signature)
            }
            (Self::P256(key), SignatureHash::Sha384) => {
                verify_with::<_, Sha384>(key, encoding, message, signature)
            }
            (Self::P384(key), SignatureHash::Sha256) => {
                verify_with::<_, Sha256>(key, encoding, message, signature)
            }
            (Self::P384(key), SignatureHash::Sha384) => {
                verify_with::<_, Sha384>(key, encoding, message, signature)
            }
        };
        result.map_err(|e| Error::new(format!("signature verification failed: {e}")))
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P256(_) => f.write_str("PublicKey::P256"),
            Self::P384(_) => f.write_str("PublicKey::P384"),
        }
    }
}

fn verify_with<C, H>(
    key: &VerifyingKey<C>,
    encoding: SignatureEncoding,
    message: &[u8],
    signature: &[u8],
) -> Result<(), graviola::Error>
where
    C: Curve,
    H: Hash,
{
    match encoding {
        SignatureEncoding::Der => key.verify_asn1::<H>(&[message], signature),
        SignatureEncoding::Fixed => key.verify::<H>(&[message], signature),
    }
}

fn verify_signed(
    key: &PublicKey,
    algorithm: &AlgorithmIdentifierOwned,
    message: &[u8],
    signature: &BitString,
) -> Result<()> {
    let hash = signature_hash(algorithm)?;
    let signature = signature
        .as_bytes()
        .ok_or_else(|| Error::new("signature has unused bits"))?;
    key.verify(hash, SignatureEncoding::Der, message, signature)
}

fn signature_hash(algorithm: &AlgorithmIdentifierOwned) -> Result<SignatureHash> {
    // RFC 5758 section 3.2: ECDSA algorithm identifiers have no parameters.
    if algorithm.parameters.is_some() {
        return Err(Error::new("ECDSA signature algorithm has parameters"));
    }

    if algorithm.oid == rfc5912::ECDSA_WITH_SHA_256 {
        Ok(SignatureHash::Sha256)
    } else if algorithm.oid == rfc5912::ECDSA_WITH_SHA_384 {
        Ok(SignatureHash::Sha384)
    } else {
        Err(Error::new(format!(
            "unsupported signature algorithm {}",
            algorithm.oid
        )))
    }
}

fn unique_extension(extensions: &[Extension], oid: ObjectIdentifier) -> Result<Option<&Extension>> {
    let mut matching = extensions
        .iter()
        .filter(|extension| extension.extn_id == oid);
    let first = matching.next();
    if matching.next().is_some() {
        return Err(Error::new(format!("duplicate extension {oid}")));
    }

    Ok(first)
}

fn decode_extension<'a, T>(extensions: &'a [Extension], oid: ObjectIdentifier) -> Result<Option<T>>
where
    T: Decode<'a, Error = der::Error>,
{
    let Some(extension) = unique_extension(extensions, oid)? else {
        return Ok(None);
    };

    Ok(Some(T::from_der(extension.extn_value.as_bytes())?))
}

fn check_extensions(extensions: &[Extension], handled_critical: &[ObjectIdentifier]) -> Result<()> {
    for (idx, extension) in extensions.iter().enumerate() {
        if extensions[..idx]
            .iter()
            .any(|earlier| earlier.extn_id == extension.extn_id)
        {
            return Err(Error::new(format!(
                "duplicate extension {}",
                extension.extn_id
            )));
        }
        if extension.critical && !handled_critical.contains(&extension.extn_id) {
            return Err(Error::new(format!(
                "unhandled critical extension {}",
                extension.extn_id
            )));
        }
    }

    Ok(())
}

/// The byte range of the signed part (the first field) of a `SEQUENCE { tbs, algorithm,
/// signature }`.
fn tbs_range(der: &[u8]) -> Result<Range<usize>> {
    let mut reader = SliceReader::new(der)?;
    let header = Header::decode(&mut reader)?;
    header.tag().assert_eq(Tag::Sequence)?;
    let start = usize::try_from(reader.position())?;
    let tbs = reader.tlv_bytes()?;

    Ok(start..start + tbs.len())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
