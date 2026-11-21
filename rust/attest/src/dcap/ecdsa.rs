//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::error::Context;
use crate::x509::{PublicKey, SignatureEncoding, SignatureHash};

/// A raw P-256 ECDSA signature: the big-endian scalars `r || s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EcdsaSignature(pub [u8; 64]);

pub(crate) fn deserialize_ecdsa_signature<'de, D>(
    de: D,
) -> std::result::Result<EcdsaSignature, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let array: [u8; 64] = hex::deserialize(de)?;
    Ok(EcdsaSignature(array))
}

pub(crate) trait EcdsaSigned {
    fn data(&self) -> &[u8];
    fn signature(&self) -> &EcdsaSignature;

    /// Verifies the ECDSA-SHA256 signature over [`Self::data`].
    fn verify_signature(&self, public_key: &PublicKey) -> crate::dcap::Result<()> {
        let result = public_key
            .verify(
                SignatureHash::Sha256,
                SignatureEncoding::Fixed,
                self.data(),
                &self.signature().0,
            )
            .context("data did not match signature");

        #[cfg(not(fuzzing))]
        result?;
        #[cfg(fuzzing)]
        drop(result);

        Ok(())
    }
}
