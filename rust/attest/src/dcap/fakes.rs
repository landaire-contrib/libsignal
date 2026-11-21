//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Test-only builders for evidence/endorsements
//! signed by testing certificates
//!
//! # Usage
//! 1. Create a builder with [`FakeAttestation::builder`].
//! 2. Manipulate the default certificates on the enclosed [`SigningInfo`]
//! 3. Manipulate the default evidence/endorsements
//! 4. Create the final evidence/endorsements with [`FakeAttestation::sign`]

use std::time::SystemTime;

use chrono::Utc;
use graviola::signing::ecdsa::{P256, SigningKey};
use sha2::Digest;
use x509_cert::serial_number::SerialNumber;

use crate::cert_chain::CertChain;
use crate::cert_chain::testutil::{TestCert, generate_key, public_point, sign_fixed};
use crate::constants::SGX_TCB_EVALUATION_DATA_NUMBER_MIN;
use crate::dcap::ecdsa::{EcdsaSignature, EcdsaSigned};
use crate::dcap::endorsements::SgxEndorsements;
use crate::dcap::evidence::Evidence;
use crate::dcap::revocation_list::RevocationList;
use crate::dcap::{Attestation, attest_impl};
use crate::x509::PublicKey;

const EVIDENCE_BYTES: &[u8] = include_bytes!("../../tests/data/dcap.evidence");
const ENDORSEMENT_BYTES: &[u8] = include_bytes!("../../tests/data/dcap.endorsements");

pub(crate) struct SigningInfo {
    pub root: TestCert,
    pub pck_chain: Vec<TestCert>,
    pub pck_issuer_crl_chain: Vec<TestCert>,
    pub tcb_issuer_chain: Vec<TestCert>,
    pub qe_id_issuer_chain: Vec<TestCert>,
    pub attest_key: SigningKey<P256>,
    pub root_revoked: Vec<SerialNumber>,
    pub pck_revoked: Vec<SerialNumber>,
}

impl SigningInfo {
    pub fn revoke_from_root(&mut self, revoked: SerialNumber) {
        self.root_revoked.push(revoked);
    }

    pub fn revoke_from_pck(&mut self, revoked: SerialNumber) {
        self.pck_revoked.push(revoked);
    }

    fn crl(cert: &TestCert, revoked: &[SerialNumber]) -> RevocationList {
        RevocationList::from_crl(cert.crl(revoked))
    }

    fn root_crl(&self) -> RevocationList {
        Self::crl(&self.root, &self.root_revoked)
    }

    fn pck_crl(&self) -> RevocationList {
        Self::crl(&self.pck_issuer_crl_chain[0], &self.pck_revoked)
    }

    /// The attest public key as the raw coordinates `x || y`.
    fn serialize_attest_public_key(&self) -> [u8; 64] {
        let point = public_point(&self.attest_key);
        point[1..].try_into().expect("uncompressed P-256 point")
    }
}

impl Default for SigningInfo {
    fn default() -> Self {
        let root = TestCert::self_issued("root");
        let pck_chain =
            root.issue_chain(&["Intel SGX PCK Platform CA", "Intel SGX PCK Processor CA"]);
        assert_eq!(pck_chain.len(), 3);

        // should be the root and the pck intermediate cert
        let pck_issuer_crl_chain = vec![pck_chain[1].clone(), root.clone()];

        // in intel collateral, these are the same, but they could theoretically be different
        let tcb_issuer_chain = root.issue_chain(&["Intel SGX TCB Signing"]);
        let qe_id_issuer_chain = root.issue_chain(&["Intel SGX TCB Signing"]);

        Self {
            root,
            pck_chain,
            pck_issuer_crl_chain,
            tcb_issuer_chain,
            qe_id_issuer_chain,
            attest_key: generate_key(),
            root_revoked: Vec::new(),
            pck_revoked: Vec::new(),
        }
    }
}

pub(crate) struct FakeAttestation {
    pub root_key: PublicKey,
    pub evidence: Evidence<'static>,
    pub endorsements: SgxEndorsements,
}

impl FakeAttestation {
    /// Create a `[FakeAttestationBuilder]` with unsigned evidence/endorsements
    ///
    /// The initial values of evidence/endorsements are arbitrary but will pass attestation
    /// when signed. To perform a test, manipulate evidence/endorsements
    /// before [`FakeAttestationBuilder::sign`]ing them.
    pub fn builder() -> FakeAttestationBuilder {
        let uevidence = Evidence::try_from(EVIDENCE_BYTES).unwrap();
        let mut uendorsements = SgxEndorsements::try_from(ENDORSEMENT_BYTES).unwrap();
        let signing_info = SigningInfo::default();
        // by default, expire tcb_info/qe_id tomorrow
        let tomorrow = Utc::now() + chrono::Days::new(1);
        uendorsements.tcb_info.next_update = tomorrow;
        uendorsements.qe_id_info.next_update = tomorrow;
        uendorsements.qe_id_info.tcb_evaluation_data_number = SGX_TCB_EVALUATION_DATA_NUMBER_MIN;
        uendorsements.tcb_info.tcb_evaluation_data_number = SGX_TCB_EVALUATION_DATA_NUMBER_MIN;
        FakeAttestationBuilder {
            signing_info,
            uevidence,
            uendorsements,
        }
    }

    pub fn attest(self) -> Result<Attestation, super::Error> {
        attest_impl(
            self.evidence,
            self.endorsements,
            &self.root_key,
            SystemTime::now(),
        )
    }
}

pub(crate) struct FakeAttestationBuilder {
    pub signing_info: SigningInfo,

    // unsigned evidence/endorsements
    pub uevidence: Evidence<'static>,
    pub uendorsements: SgxEndorsements,
}

impl FakeAttestationBuilder {
    /// Create Evidence/Endorsements that have the appropriate report signatures, and QE report data
    ///
    /// Note that this will overwrite any manually set. If you'd like to test a corrupt signature,
    /// do it after signing.
    pub fn sign(mut self) -> FakeAttestation {
        self.uevidence.quote.support.attest_pub_key =
            self.signing_info.serialize_attest_public_key();
        self.uevidence
            .quote
            .support
            .qe_report_body
            .sgx_report_data_bytes = [0; 64];
        let hash = {
            let mut h = sha2::Sha256::new();
            h.update(self.uevidence.quote.support.attest_pub_key);
            h.update(self.uevidence.quote.support.auth_data);
            h.finalize()
        };
        self.uevidence
            .quote
            .support
            .qe_report_body
            .sgx_report_data_bytes[0..32]
            .copy_from_slice(&hash);

        self.uevidence.quote.support.isv_signature = EcdsaSignature(sign_fixed(
            &self.signing_info.attest_key,
            self.uevidence.quote.data(),
        ));
        self.uevidence.quote.support.qe_report_signature = EcdsaSignature(sign_fixed(
            &self.signing_info.pck_chain[0].key,
            self.uevidence.quote.support.data(),
        ));

        self.uendorsements.root_crl = self.signing_info.root_crl();
        self.uendorsements.pck_issuer_crl = self.signing_info.pck_crl();
        self.uendorsements.qe_id_issuer_chain = CertChain::from_certs(
            self.signing_info
                .qe_id_issuer_chain
                .into_iter()
                .map(|tc| tc.cert)
                .collect(),
        );
        self.uendorsements.tcb_issuer_chain = CertChain::from_certs(
            self.signing_info
                .tcb_issuer_chain
                .into_iter()
                .map(|tc| tc.cert)
                .collect(),
        );
        self.uendorsements.pck_issuer_crl_chain = CertChain::from_certs(
            self.signing_info
                .pck_issuer_crl_chain
                .into_iter()
                .map(|tc| tc.cert)
                .collect(),
        );
        self.uevidence.quote.support.pck_cert_chain = CertChain::from_certs(
            self.signing_info
                .pck_chain
                .into_iter()
                .map(|tc| tc.cert)
                .collect(),
        );
        FakeAttestation {
            root_key: self.signing_info.root.cert.public_key().unwrap(),
            evidence: self.uevidence,
            endorsements: self.uendorsements,
        }
    }
}
