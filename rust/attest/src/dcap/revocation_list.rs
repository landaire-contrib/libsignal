//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use der::oid::db::rfc5912;
use der::{Reader, SliceReader};

use crate::dcap::{Error, Expireable, Result};
use crate::error::Context;
use crate::x509::Crl;

#[derive(Debug)]
pub(crate) struct RevocationList {
    crl: Crl,
}

impl Expireable for RevocationList {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        self.crl
            .next_update()
            .is_some_and(|next_update| timestamp < next_update.to_system_time())
    }
}

impl RevocationList {
    /// Parses the DER CRL at the start of `data`. Collateral fields carry a trailing NUL, so
    /// bytes after the CRL are ignored.
    pub fn from_der_data(data: &[u8]) -> Result<RevocationList> {
        let mut reader = SliceReader::new(data)?;
        let crl = reader.tlv_bytes()?;
        let crl = Crl::from_der(crl.to_vec()).context("CRL")?;

        // all RFC 5280 CRLs should have authority key
        // identifiers and a CRL number
        let has_extension = |oid| {
            crl.extensions()
                .iter()
                .any(|extension| extension.extn_id == oid)
        };
        if !has_extension(rfc5912::ID_CE_AUTHORITY_KEY_IDENTIFIER)
            || !has_extension(rfc5912::ID_CE_CRL_NUMBER)
        {
            return Err(Error::new("CRL missing required extension"));
        }

        Ok(RevocationList { crl })
    }

    #[cfg(test)]
    pub fn from_crl(crl: Crl) -> RevocationList {
        RevocationList { crl }
    }

    pub fn crl(&self) -> &Crl {
        &self.crl
    }
}
