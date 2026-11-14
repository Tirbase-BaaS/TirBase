// SPDX-License-Identifier: AGPL-3.0-only

//! Post-execution author revocation check hook (PV-8.7).

#![allow(dead_code)]

use crate::errors::TirBaseError;
use crate::migration::migration_delta::MigrationId;
use std::fmt::Debug;
use std::sync::Arc;

pub trait AuthorRevocationChecker: Send + Sync + Debug {
    fn is_author_revoked(&self, author_did: &str) -> bool;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoAuthorRevocations;

impl AuthorRevocationChecker for NoAuthorRevocations {
    fn is_author_revoked(&self, _author_did: &str) -> bool {
        false
    }
}

pub type DynAuthorRevocationChecker = Arc<dyn AuthorRevocationChecker>;

pub fn check_author_not_revoked(
    checker: &dyn AuthorRevocationChecker,
    migration_id: &MigrationId,
    author_did: &str,
) -> Result<(), TirBaseError> {
    if checker.is_author_revoked(author_did) {
        return Err(TirBaseError::MigrationAuthorRevoked {
            migration_id: hex::encode(migration_id),
            author_did: author_did.to_string(),
        });
    }
    Ok(())
}
