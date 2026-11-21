//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use crate::error::{Context, ContextError};
use crate::expireable::Expireable;
use crate::x509::{Certificate, Crl, PublicKey};

pub(crate) struct CertChainErrorDomain;
pub(crate) type Error = ContextError<CertChainErrorDomain>;

type Result<T, E = Error> = std::result::Result<T, E>;

/// Trusted material that certificate chains are validated against.
pub(crate) struct TrustStore<'a> {
    root: &'a Certificate,
    revocation: Revocation<'a>,
    time: SystemTime,
}

impl<'a> TrustStore<'a> {
    /// `root` must already be trusted, and so must every CRL in `revocation`.
    pub fn new(root: &'a Certificate, revocation: Revocation<'a>, time: SystemTime) -> Self {
        Self {
            root,
            revocation,
            time,
        }
    }
}

/// Whether chains are checked against CRLs.
pub(crate) enum Revocation<'a> {
    /// Every certificate in a chain, including the root, must be covered by a current CRL from
    /// its issuer, found here or among the CRLs passed to [`CertChain::validate_chain`].
    Required(Vec<&'a Crl>),
    NotChecked,
}

#[derive(Debug)]
pub(crate) struct CertChain {
    /// X509 certs ordered from leaf to root
    /// Each cert should be issued by the previous
    /// cert in the chain
    certs: Vec<Certificate>,
}

impl CertChain {
    pub fn from_pem_data(data: &[u8]) -> Result<CertChain> {
        let certs = Certificate::from_pem_chain(data).context("PEM")?;
        Self::new(certs)
    }

    pub fn new(maybe_unsorted_certs: impl IntoIterator<Item = Certificate>) -> Result<CertChain> {
        let mut certs = Vec::from_iter(maybe_unsorted_certs);
        if certs.is_empty() {
            return Err(Error::new("empty chain"));
        }
        Self::sort(&mut certs)?;

        Ok(CertChain { certs })
    }

    pub fn leaf(&self) -> &Certificate {
        &self.certs[0]
    }

    /// Returns a reference to a chain cert, where index 0 is the root,
    /// index 1 is the cert signed by the root, etc...
    pub fn idx_from_root(&self, idx: usize) -> Option<&Certificate> {
        if idx >= self.certs.len() {
            None
        } else {
            Some(&self.certs[self.certs.len() - idx - 1])
        }
    }

    pub fn leaf_pub_key(&self) -> Result<PublicKey> {
        self.leaf().public_key().context("leaf_pub_key")
    }

    pub fn root(&self) -> &Certificate {
        self.certs.last().expect("certs must not be empty")
    }

    /// Validate that this exact certificate chain leads from its leaf to the root of `trust`.
    ///
    /// # Arguments
    ///
    /// * `trust` The trusted root, the trusted CRLs if CRLs are checked, and the time to
    ///   validate at
    /// * `crls`  Additional CRLs that are not trusted, and must be issued by
    ///   a certificate in this certificate chain rooted in the trust store
    ///
    pub fn validate_chain(&self, trust: &TrustStore<'_>, crls: &[&Crl]) -> Result<()> {
        let result = self.validate_path(trust, crls);

        #[cfg(not(fuzzing))]
        result?;
        #[cfg(fuzzing)]
        drop(result);

        Ok(())
    }

    /// [`Self::validate_chain`], with failures reported in fuzzing builds too.
    pub fn validate_path(&self, trust: &TrustStore<'_>, crls: &[&Crl]) -> Result<()> {
        if self.root().der() != trust.root.der() {
            return Err(Error::new("chain is not rooted in the trusted certificate"));
        }

        let last = self.certs.len() - 1;
        for (idx, cert) in self.certs.iter().enumerate() {
            cert.check_extensions()
                .with_context(|| format!("certificate {idx}"))?;
            Self::check_validity(cert, trust.time).with_context(|| format!("certificate {idx}"))?;
            if idx > 0 {
                self.check_ca(idx)?;
            }

            let issuer = self.certs.get(idx + 1).unwrap_or(cert);
            if !cert.is_issued_by(issuer) {
                return Err(Error::new(format!(
                    "certificate {idx} is not issued by the next certificate"
                )));
            }

            // A path from the leaf ends at the first self-issued certificate, and at the
            // trusted root once a certificate names it as issuer. Requiring both of those to be
            // the last certificate means that path covers the whole chain.
            if idx < last && cert.is_self_issued() {
                return Err(Error::new(format!(
                    "certificate {idx} is self-issued but is not the root"
                )));
            }
            if idx + 1 < last && cert.is_issued_by(trust.root) {
                return Err(Error::new(format!(
                    "certificate {idx} is issued by the root but is not next to it"
                )));
            }

            // The root's own signature is checked by whoever trusts it.
            if idx < last {
                let issuer_key = issuer
                    .public_key()
                    .with_context(|| format!("certificate {}", idx + 1))?;
                cert.verify_signature(&issuer_key)
                    .with_context(|| format!("certificate {idx}"))?;
            }

            if let Revocation::Required(trusted_crls) = &trust.revocation {
                Self::check_revocation(
                    cert,
                    issuer,
                    trusted_crls.iter().chain(crls).copied(),
                    trust.time,
                )
                .with_context(|| format!("certificate {idx}"))?;
            }
        }

        Ok(())
    }

    fn check_validity(cert: &Certificate, time: SystemTime) -> Result<()> {
        if time < cert.not_before().to_system_time() {
            return Err(Error::new("certificate is not yet valid"));
        }
        // A certificate has expired at its notAfter second.
        if cert.not_after().to_system_time() <= time {
            return Err(Error::new("certificate has expired"));
        }

        Ok(())
    }

    /// Checks that the certificate at `idx`, which issued the one before it, is a CA that may
    /// issue the certificates below it.
    fn check_ca(&self, idx: usize) -> Result<()> {
        let cert = &self.certs[idx];
        let constraints = cert
            .basic_constraints()
            .with_context(|| format!("certificate {idx}"))?;
        let Some(constraints) = constraints.filter(|constraints| constraints.ca) else {
            return Err(Error::new(format!("certificate {idx} is not a CA")));
        };

        // The path length counts the intermediate certificates below this one, other than
        // self-issued ones.
        if let Some(path_len) = constraints.path_len_constraint {
            let below = self.certs[1..idx]
                .iter()
                .filter(|cert| !cert.is_self_issued())
                .count();
            if below > usize::from(path_len) {
                return Err(Error::new(format!(
                    "certificate {idx} path length constraint exceeded"
                )));
            }
        }

        Ok(())
    }

    /// Checks `cert` against every CRL from `issuer`, of which there must be at least one.
    fn check_revocation<'c>(
        cert: &Certificate,
        issuer: &Certificate,
        crls: impl Iterator<Item = &'c Crl>,
        time: SystemTime,
    ) -> Result<()> {
        let mut found = false;
        for crl in crls.filter(|crl| crl.issuer() == issuer.subject()) {
            found = true;

            let key_usage = issuer.key_usage().context("CRL issuer")?;
            if key_usage.is_some_and(|key_usage| !key_usage.crl_sign()) {
                return Err(Error::new("CRL issuer may not sign CRLs"));
            }
            crl.check_extensions().context("CRL")?;
            let issuer_key = issuer.public_key().context("CRL issuer")?;
            crl.verify_signature(&issuer_key).context("CRL")?;
            if !crl.is_current_at(time) {
                return Err(Error::new("CRL is expired or not yet valid"));
            }
            if crl.is_revoked(cert.serial_number()) {
                return Err(Error::new("certificate is revoked"));
            }
        }

        if !found {
            return Err(Error::new("no CRL from the issuer"));
        }

        Ok(())
    }

    /// Sorts the certificates from leaf->root, failing
    /// if the chain has any missing or extra links
    fn sort(certs: &mut [Certificate]) -> Result<()> {
        fn to_error() -> Error {
            Error::new("Invalid certificate chain")
        }

        // move the root into the last position
        let root_pos = certs
            .iter()
            .rposition(Certificate::is_self_issued)
            .ok_or_else(to_error)?;
        let end_pos = certs.len() - 1;
        certs.swap(end_pos, root_pos);

        // searches backwards so the common case where
        // the chain is already ordered is linear
        for curr in (1..certs.len()).rev() {
            let issuer = &certs[curr];
            // starting at curr - 1, find the cert issued by curr
            let nxt_pos = certs[0..curr]
                .iter()
                .rposition(|c| c.is_issued_by(issuer))
                .ok_or_else(to_error)?;
            certs.swap(curr - 1, nxt_pos);
        }
        Ok(())
    }
}

impl Expireable for CertChain {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        self.certs.iter().all(|cert| cert.is_valid_at(timestamp))
    }
}

#[cfg(test)]
/// Utilities for creating test certificates / crls
pub mod testutil {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use der::asn1::{AnyRef, BitString, OctetString};
    use der::oid::db::rfc5912;
    use der::{Decode, Encode, Sequence};
    use graviola::hashing::Sha256;
    use graviola::signing::ecdsa::{P256, SigningKey};
    use rand_core::TryRngCore as _;
    use x509_cert::certificate::Version;
    use x509_cert::crl::{RevokedCert, TbsCertList};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::BasicConstraints;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};

    use super::CertChain;
    use crate::x509::{Certificate, Crl};

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    /// `TBSCertificate` with every field this test code sets.
    #[derive(Sequence)]
    struct TbsCertificateFields {
        #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
        version: Version,
        serial_number: SerialNumber,
        signature: AlgorithmIdentifierOwned,
        issuer: Name,
        validity: Validity,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfoOwned,
        #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
        extensions: Vec<Extension>,
    }

    /// The outer `SEQUENCE` of a certificate or CRL.
    #[derive(Sequence)]
    struct SignedFields<'a> {
        tbs: AnyRef<'a>,
        algorithm: AlgorithmIdentifierOwned,
        signature: BitString,
    }

    impl CertChain {
        pub(crate) fn from_certs(certs: Vec<Certificate>) -> CertChain {
            CertChain { certs }
        }
    }

    pub(crate) fn serial_number() -> SerialNumber {
        let mut bytes = [0u8; 16];
        rand_core::OsRng
            .try_fill_bytes(&mut bytes)
            .expect("OS RNG is available");
        SerialNumber::new(&bytes).unwrap()
    }

    pub(crate) fn generate_key() -> SigningKey<P256> {
        SigningKey::<P256>::generate().unwrap()
    }

    /// The uncompressed point `0x04 || x || y` for `key`.
    pub(crate) fn public_point(key: &SigningKey<P256>) -> Vec<u8> {
        public_key_info(key)
            .subject_public_key
            .as_bytes()
            .unwrap()
            .to_vec()
    }

    /// Signs `data` with ECDSA-SHA256, returning the DER encoded signature.
    pub(crate) fn sign_der(key: &SigningKey<P256>, data: &[u8]) -> Vec<u8> {
        let mut signature = [0u8; 128];
        key.sign_asn1::<Sha256>(&[data], &mut signature)
            .unwrap()
            .to_vec()
    }

    /// Signs `data` with ECDSA-SHA256, returning `r || s`.
    pub(crate) fn sign_fixed(key: &SigningKey<P256>, data: &[u8]) -> [u8; 64] {
        let mut signature = [0u8; 64];
        key.sign::<Sha256>(&[data], &mut signature).unwrap();
        signature
    }

    fn public_key_info(key: &SigningKey<P256>) -> SubjectPublicKeyInfoOwned {
        let mut spki = [0u8; 128];
        SubjectPublicKeyInfoOwned::from_der(key.to_spki_der(&mut spki).unwrap()).unwrap()
    }

    fn ecdsa_with_sha256() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: rfc5912::ECDSA_WITH_SHA_256,
            parameters: None,
        }
    }

    /// A critical basic constraints extension.
    pub(crate) fn basic_constraints(ca: bool, path_len_constraint: Option<u8>) -> Extension {
        let constraints = BasicConstraints {
            ca,
            path_len_constraint,
        };
        Extension {
            extn_id: rfc5912::ID_CE_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(constraints.to_der().unwrap()).unwrap(),
        }
    }

    fn signed(key: &SigningKey<P256>, tbs: &[u8]) -> Vec<u8> {
        SignedFields {
            tbs: AnyRef::from_der(tbs).unwrap(),
            algorithm: ecdsa_with_sha256(),
            signature: BitString::from_bytes(&sign_der(key, tbs)).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    #[derive(Clone)]
    pub(crate) struct TestCert {
        pub key: Arc<SigningKey<P256>>,
        pub cert: Certificate,
    }

    impl TestCert {
        /// Create a self-issued certificate/key pair
        pub fn self_issued(cn: &str) -> TestCert {
            Self::new(None, cn)
        }

        /// Create a self-issued certificate/key pair with `extensions` in place of the default
        /// CA basic constraints
        pub fn self_issued_with_extensions(cn: &str, extensions: Vec<Extension>) -> TestCert {
            Self::build(None, None, cn, extensions)
        }

        /// Create a certificate/key pair signed by this certificate
        pub fn issue(&self, cn: &str) -> TestCert {
            Self::new(Some(self), cn)
        }

        /// Create a certificate/key pair signed by this certificate, with `extensions` in place
        /// of the default CA basic constraints
        pub fn issue_with_extensions(&self, cn: &str, extensions: Vec<Extension>) -> TestCert {
            Self::build(Some(self), Some(self), cn, extensions)
        }

        /// Create a certificate/key pair that names this certificate as its issuer, but is
        /// signed with the new cert's own key, so the signature does not verify against this
        /// certificate
        pub fn forge(&self, cn: &str) -> TestCert {
            Self::new_signed_by(Some(self), None, cn)
        }

        /// creates a test certificate/key pair, self-signed if no issuer
        pub fn new(issuer: Option<&TestCert>, cn: &str) -> TestCert {
            Self::new_signed_by(issuer, issuer, cn)
        }

        /// creates a test certificate/key pair naming `issuer` as its issuer (self-issued if
        /// none) and signed by `signer` (self-signed if none)
        fn new_signed_by(
            issuer: Option<&TestCert>,
            signer: Option<&TestCert>,
            cn: &str,
        ) -> TestCert {
            Self::build(issuer, signer, cn, vec![basic_constraints(true, None)])
        }

        fn build(
            issuer: Option<&TestCert>,
            signer: Option<&TestCert>,
            cn: &str,
            extensions: Vec<Extension>,
        ) -> TestCert {
            let key = generate_key();
            let name = Name::from_str(&format!("CN={cn}")).unwrap();

            let now = SystemTime::now();
            let validity = Validity::new(
                Time::try_from(now).unwrap(),
                Time::try_from(now + 365 * DAY).unwrap(),
            );

            let issuer_name = issuer.map_or_else(|| name.clone(), |c| c.cert.subject().clone());
            let tbs = TbsCertificateFields {
                version: Version::V3,
                serial_number: serial_number(),
                signature: ecdsa_with_sha256(),
                issuer: issuer_name,
                validity,
                subject: name,
                subject_public_key_info: public_key_info(&key),
                extensions,
            }
            .to_der()
            .unwrap();

            let signer = signer.map_or(&key, |c| &*c.key);
            let cert = Certificate::from_der(signed(signer, &tbs)).unwrap();

            TestCert {
                key: Arc::new(key),
                cert,
            }
        }

        pub fn empty_crl(&self) -> Crl {
            self.crl(&[])
        }

        pub fn crl(&self, revoked: &[SerialNumber]) -> Crl {
            let now = SystemTime::now();
            self.crl_between(revoked, now, now + 30 * DAY)
        }

        /// A CRL issued at `this_update` whose next update is `next_update`.
        pub fn crl_between(
            &self,
            revoked: &[SerialNumber],
            this_update: SystemTime,
            next_update: SystemTime,
        ) -> Crl {
            let now = Time::try_from(this_update).unwrap();
            let next_update = Time::try_from(next_update).unwrap();
            let revoked_certificates = (!revoked.is_empty()).then(|| {
                revoked
                    .iter()
                    .map(|serial_number| RevokedCert {
                        serial_number: serial_number.clone(),
                        revocation_date: now,
                        crl_entry_extensions: None,
                    })
                    .collect()
            });
            let tbs = TbsCertList {
                version: Version::V2,
                signature: ecdsa_with_sha256(),
                issuer: self.cert.subject().clone(),
                this_update: now,
                next_update: Some(next_update),
                revoked_certificates,
                crl_extensions: None,
            }
            .to_der()
            .unwrap();

            let crl_der = signed(&self.key, &tbs);
            Crl::from_der(crl_der).unwrap()
        }

        /// Create a chain of test certificates issued by this certificate, with the given common
        /// names.
        pub fn issue_chain(&self, cns: &[&str]) -> Vec<TestCert> {
            let mut vs = Vec::new();
            vs.push(self.clone());
            for cn in cns {
                vs.push(vs.last().unwrap().issue(cn));
            }
            vs.reverse();
            vs
        }

        /// Create a chain of test certificates with a self-signed root
        ///
        /// Ordered from leaf to root
        pub fn chain(len: usize) -> Vec<TestCert> {
            let mut vs = Vec::new();
            for i in 0..len {
                vs.push(TestCert::new(vs.last(), &i.to_string()))
            }
            vs.reverse();
            vs
        }
    }

    /// Creates a certificate chain of the specified length
    pub(crate) fn chain(len: usize) -> Vec<Certificate> {
        TestCert::chain(len).into_iter().map(|p| p.cert).collect()
    }

    pub(crate) fn cert_chain(len: usize) -> CertChain {
        CertChain { certs: chain(len) }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use der::asn1::OctetString;
    use der::oid::ObjectIdentifier;
    use x509_cert::ext::Extension;

    use super::testutil::*;
    use super::*;

    fn names(certs: &[Certificate]) -> Vec<String> {
        certs.iter().map(|c| c.common_name().unwrap()).collect()
    }

    #[test]
    fn sort_reversed() {
        let mut chain = chain(5);
        let expected = names(&chain);

        chain.reverse();
        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    #[test]
    fn sort_ordered() {
        let mut chain = chain(5);
        let expected = names(&chain);

        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    #[test]
    fn sort_unordered() {
        let mut chain = chain(5);
        let expected = names(&chain);
        chain.swap(4, 2);
        chain.swap(0, 3);
        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    #[test]
    fn sort_small() {
        let mut chain = chain(2);
        let expected = names(&chain);
        chain.reverse();

        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    #[test]
    fn sort_singleton() {
        let mut chain = chain(1);
        let expected = names(&chain);
        CertChain::sort(&mut chain).expect("Chain should be valid");
        assert_eq!(expected, names(&chain));
    }

    fn trust_store<'a>(root: &'a Certificate, crl: Option<&'a Crl>) -> TrustStore<'a> {
        let revocation = match crl {
            Some(crl) => Revocation::Required(vec![crl]),
            None => Revocation::NotChecked,
        };
        TrustStore::new(root, revocation, SystemTime::now())
    }

    #[test]
    fn validate_valid_chain() {
        let cert_chain = CertChain { certs: chain(4) };
        let trust = trust_store(cert_chain.root(), None);
        cert_chain
            .validate_chain(&trust, &[])
            .expect("should validate");
    }

    #[test]
    fn validate_invalid_chain() {
        let mut c = chain(4);
        let root = c.last().unwrap().clone();
        let trust = trust_store(&root, None);
        c.remove(2); // delete an intermediate certificate
        let cert_chain = CertChain { certs: c };
        assert!(cert_chain.validate_chain(&trust, &[]).is_err())
    }

    #[test]
    fn validate_untrusted_root() {
        let cert_chain = CertChain { certs: chain(3) };
        let other_root = TestCert::self_issued("0");
        let trust = trust_store(&other_root.cert, None);
        assert!(cert_chain.validate_chain(&trust, &[]).is_err())
    }

    #[test]
    fn validate_expired() {
        let cert_chain = CertChain { certs: chain(3) };
        let trust = TrustStore::new(
            cert_chain.root(),
            Revocation::NotChecked,
            SystemTime::now() + Duration::from_secs(2 * 365 * 24 * 60 * 60),
        );
        assert!(cert_chain.validate_chain(&trust, &[]).is_err())
    }

    #[test]
    fn validate_bad_signature() {
        let c = TestCert::chain(3);
        let forged = c[1].forge("leaf");
        let cert_chain = CertChain {
            certs: vec![forged.cert.clone(), c[1].cert.clone(), c[2].cert.clone()],
        };
        let trust = trust_store(&c[2].cert, None);
        assert!(cert_chain.validate_chain(&trust, &[]).is_err())
    }

    #[test]
    fn validate_missing_crl() {
        let c = TestCert::chain(3);
        let root_crl = c.last().unwrap().empty_crl();
        let trust = trust_store(&c.last().unwrap().cert, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.iter().map(|p| p.cert.clone()).collect(),
        };
        assert!(cert_chain.validate_chain(&trust, &[]).is_err())
    }

    #[test]
    fn validate_crl_wrong_signer() {
        let c = TestCert::chain(3);
        let root_crl = c.last().unwrap().empty_crl();
        // names the intermediate as issuer, but is signed by the root
        let mut impostor = c[1].clone();
        impostor.key = Arc::clone(&c[2].key);
        let intermediate_crl = impostor.empty_crl();
        let trust = trust_store(&c.last().unwrap().cert, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.iter().map(|p| p.cert.clone()).collect(),
        };
        assert!(
            cert_chain
                .validate_chain(&trust, &[&intermediate_crl])
                .is_err()
        )
    }

    #[test]
    fn validate_revoked_from_root() {
        let c = TestCert::chain(3);
        let root_crl = c.last().unwrap().crl(&[c[1].cert.serial_number().clone()]);
        let intermediate_crl = c[1].empty_crl();
        let trust = trust_store(&c.last().unwrap().cert, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.iter().map(|p| p.cert.clone()).collect(),
        };
        assert!(
            cert_chain
                .validate_chain(&trust, &[&intermediate_crl])
                .is_err()
        )
    }

    #[test]
    fn validate_revoked_from_intermediate() {
        let c = TestCert::chain(3);
        let root_crl = c.last().unwrap().empty_crl();
        let intermediate_crl = c[1].crl(&[c[0].cert.serial_number().clone()]);
        let trust = trust_store(&c.last().unwrap().cert, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.iter().map(|p| p.cert.clone()).collect(),
        };
        assert!(
            cert_chain
                .validate_chain(&trust, &[&intermediate_crl])
                .is_err()
        )
    }

    #[test]
    fn validate_other_revoked() {
        let c = TestCert::chain(3);
        // revoke some random serial numbers
        let root_crl = c.last().unwrap().crl(&[serial_number()]);
        let intermediate_crl = c[1].crl(&[serial_number()]);
        let trust = trust_store(&c.last().unwrap().cert, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.iter().map(|p| p.cert.clone()).collect(),
        };
        cert_chain
            .validate_chain(&trust, &[&intermediate_crl])
            .expect("should validate");
    }

    #[test]
    fn validate_no_revoked() {
        let c = TestCert::chain(3);
        let root_crl = c.last().unwrap().empty_crl();
        let intermediate_crl = c[1].empty_crl();
        let trust = trust_store(&c.last().unwrap().cert, Some(&root_crl));
        let cert_chain = CertChain {
            certs: c.iter().map(|p| p.cert.clone()).collect(),
        };
        cert_chain
            .validate_chain(&trust, &[&intermediate_crl])
            .expect("should validate");
    }

    #[test]
    fn new_chain_from_unsorted_certs() {
        let mut certs = chain(5);
        let expected = names(&certs);
        certs.swap(4, 2);
        certs.swap(0, 3);
        assert_matches!(CertChain::new(certs), Ok(CertChain { certs: actual }) => {
            assert_eq!(names(&actual), expected);
        });
    }

    #[test]
    fn validate_checks_chains_match() {
        let c1 = TestCert::chain(2);
        let c2 = TestCert::chain(2);
        let trust = trust_store(&c1.last().unwrap().cert, None);
        let cert_chain = CertChain {
            certs: [
                c1[0].cert.clone(),
                c2[0].cert.clone(),
                c2[1].cert.clone(),
                c1[1].cert.clone(),
            ]
            .to_vec(),
        };
        cert_chain
            .validate_chain(&trust, &[])
            .expect_err("provided chain does not match validated chain");
    }

    #[test]
    fn validate_checks_chain_lengths_match() {
        // The path from the leaf stops at the first copy of the root.
        let certs = TestCert::chain(2);
        let trust = trust_store(&certs.last().unwrap().cert, None);
        let cert_chain = CertChain {
            certs: [
                certs[0].cert.clone(),
                certs[1].cert.clone(),
                certs[1].cert.clone(),
            ]
            .to_vec(),
        };
        cert_chain
            .validate_chain(&trust, &[])
            .expect_err("provided chain is longer than validated chain");
    }

    fn validate_chain_of(certs: &[&TestCert], crls: &[&Crl]) -> Result<()> {
        let root = certs.last().unwrap();
        let root_crl = root.empty_crl();
        let trust = trust_store(&root.cert, Some(&root_crl));
        let cert_chain = CertChain {
            certs: certs.iter().map(|c| c.cert.clone()).collect(),
        };
        cert_chain.validate_chain(&trust, crls)
    }

    #[test]
    fn validate_path_length() {
        for (path_len, valid) in [(0, false), (1, true)] {
            let root = TestCert::self_issued_with_extensions(
                "root",
                vec![basic_constraints(true, Some(path_len))],
            );
            let intermediate = root.issue("intermediate");
            let leaf = intermediate.issue("leaf");
            let intermediate_crl = intermediate.empty_crl();
            let result = validate_chain_of(&[&leaf, &intermediate, &root], &[&intermediate_crl]);
            assert_eq!(result.is_ok(), valid, "path length {path_len}: {result:?}");
        }
    }

    #[test]
    fn validate_issuer_not_ca() {
        let root = TestCert::self_issued("root");
        let intermediate =
            root.issue_with_extensions("intermediate", vec![basic_constraints(false, None)]);
        let leaf = intermediate.issue("leaf");
        let intermediate_crl = intermediate.empty_crl();
        validate_chain_of(&[&leaf, &intermediate, &root], &[&intermediate_crl])
            .expect_err("intermediate is not a CA");
    }

    #[test]
    fn validate_unknown_critical_extension() {
        let root = TestCert::self_issued("root");
        let unknown = Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"),
            critical: true,
            extn_value: OctetString::new(vec![0x05, 0x00]).unwrap(),
        };
        let leaf = root.issue_with_extensions("leaf", vec![unknown.clone()]);
        validate_chain_of(&[&leaf, &root], &[]).expect_err("unknown critical extension");

        let known = Extension {
            critical: false,
            ..unknown
        };
        let leaf = root.issue_with_extensions("leaf", vec![known]);
        validate_chain_of(&[&leaf, &root], &[]).expect("non-critical extension is ignored");
    }

    #[test]
    fn validate_path_length_on_non_ca() {
        let root = TestCert::self_issued("root");
        let leaf = root.issue_with_extensions("leaf", vec![basic_constraints(false, Some(0))]);
        validate_chain_of(&[&leaf, &root], &[]).expect_err("path length on a non-CA");
    }

    #[test]
    fn validate_crl_time() {
        let c = TestCert::chain(3);
        let now = SystemTime::now();
        let day = Duration::from_secs(24 * 60 * 60);
        let chain: Vec<&TestCert> = c.iter().collect();

        let expired = c[1].crl_between(&[], now - 40 * day, now - 10 * day);
        validate_chain_of(&chain, &[&expired]).expect_err("CRL has expired");

        let future = c[1].crl_between(&[], now + day, now + 30 * day);
        validate_chain_of(&chain, &[&future]).expect_err("CRL is not yet valid");
    }
}
