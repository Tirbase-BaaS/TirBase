# Orphan API Allowlist

Items in this table are `pub` API items with no non-test callers outside their own crate,
approved for a bounded period. CI fails if any item is past its expiry version without
having gained a non-test cross-crate caller.

**Allowlist scope:** entries cover a named item and all paths nested under it (i.e., listing
`tirbase_core::api` also covers `tirbase_core::api::CoreHandle` and every item inside `api`).
The script matches an orphan against the entry itself and any `entry::…` path, so a single
module row approves that module's whole public surface until the module gains a non-test
cross-crate caller.

**How references are detected:** the scan builds rustdoc JSON for the library crates and then
scans the source of every workspace crate — including the application crates `tirbase-gateway`
and `tirbase-admin` — for `use` statements, qualified paths and parent-type references. A
module-level row near the end of this table therefore means *no* workspace crate references
that module at all, not merely that rustdoc could not see the reference.

**When to remove an entry:** once the item has at least one non-test caller in another crate
(e.g., `tirbase-gateway` imports `tirbase_core::api::CoreHandle`), remove the row. The script
will no longer flag it as an orphan once it is referenced cross-crate.

To add an entry:
1. Add a row with the exact FQN (or FQN prefix for a subtree), owner, justification, expiry.
2. Run `bash scripts/check-orphan-api.sh` locally to confirm exit 0.
3. Commit the updated file.

| Item | Owner | Justification | Expiry |
|------|-------|---------------|--------|
| `tirbase_types::CommandRole` | @tirbase-core-team | Role enum defined for PV-3.1; cross-crate wiring in tirbase-guard Phase 2 (+) | v0.3.0 |
| `tirbase_types::CommandRole::Auditor` | @tirbase-core-team | Enum variant; cross-crate wiring in Phase 2 | v0.3.0 |
| `tirbase_types::CommandRole::CommandIssuer` | @tirbase-core-team | Enum variant; cross-crate wiring in Phase 2 | v0.3.0 |
| `tirbase_types::CommandRole::PolicyAuthority` | @tirbase-core-team | Enum variant; cross-crate wiring in Phase 2 | v0.3.0 |
| `tirbase_types::CommandRole::RevocationManager` | @tirbase-core-team | Enum variant; cross-crate wiring in Phase 2 | v0.3.0 |
| `tirbase_types::CommandRole::TimeAnchor` | @tirbase-core-team | Enum variant; cross-crate wiring in Phase 2 | v0.3.0 |
| `tirbase_types::CommandRole::UpdateSigner` | @tirbase-core-team | Enum variant; cross-crate wiring in Phase 2 | v0.3.0 |
| `tirbase_types::DeviceKeyType` | @tirbase-core-team | Key-type indicator; wired in Phase 1 KeyProvider impl | v0.3.0 |
| `tirbase_types::DeviceKeyType::Ed25519` | @tirbase-core-team | Enum variant; wired in Phase 1 | v0.3.0 |
| `tirbase_types::DeviceKeyType::P256` | @tirbase-core-team | Enum variant; wired in Phase 1 | v0.3.0 |
| `tirbase_types::DeviceSignature` | @tirbase-core-team | Signature variant type; wired in Phase 1 KeyProvider | v0.3.0 |
| `tirbase_types::DeviceSignature::Ed25519` | @tirbase-core-team | Enum variant; wired in Phase 1 | v0.3.0 |
| `tirbase_types::DeviceSignature::P256` | @tirbase-core-team | Enum variant; wired in Phase 1 | v0.3.0 |
| `tirbase_types::Did` | @tirbase-core-team | DID newtype; cross-crate wiring in guard Phase 2 | v0.3.0 |
| `tirbase_types::FixedPointValue` | @tirbase-core-team | Fixed-point value type; wired in Phase 2 guard envelope checks | v0.3.0 |
| `tirbase_types::TargetId` | @tirbase-core-team | Target newtype; wired in guard Phase 2 command pipeline | v0.3.0 |
| `tirbase_types::UnitId` | @tirbase-core-team | Type alias; wired alongside FixedPointValue in Phase 2 | v0.3.0 |
| `tirbase_types::DeltaId` | @tirbase-core-team | Type alias [u8;32]; shared type, cross-crate wiring Phase 2+ | v0.3.0 |
| `tirbase_types::MigrationId` | @tirbase-core-team | Type alias [u8;32]; wired in migration Phase 6 | v0.3.0 |
| `tirbase_types::ProfileId` | @tirbase-core-team | Type alias [u8;16]; wired in Phase 2 EnvelopeProfile | v0.3.0 |
| `tirbase_guard::tirbase_types` | @tirbase-guard-team | Re-export of tirbase_types; guard body wired in –16 | v0.3.0 |
| `tirbase_drivers::tirbase_types` | @tirbase-drivers-team | Re-export of tirbase_types; driver body wired in + | v0.3.0 |
| `tirbase_sim::tirbase_types` | @tirbase-sim-team | Re-export of tirbase_types; simulator body wired in + | v0.3.0 |
| `tirbase_demo::tirbase_types` | @tirbase-demo-team | Re-export of tirbase_types; demo packs wired in + | v0.3.0 |
| `tirbase_core::api` | @tirbase-core-team | CoreHandle API module; tirbase-gateway wires this in Phase 9 (+) | v0.3.0 |
| `tirbase_core::api::CoreHandle` | @tirbase-core-team | Main API entry point; tirbase-gateway wires in Phase 9 | v0.3.0 |
| `tirbase_core::api::CoreHandle::init` | @tirbase-core-team | Init function; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::CoreHandle::register_migration_ca_key` | @tirbase-core-team | Wired in gateway init path Phase 9 | v0.3.0 |
| `tirbase_core::api::CoreHandle::register_root_ca_key` | @tirbase-core-team | Wired in gateway init path Phase 9 | v0.3.0 |
| `tirbase_core::api::CoreHandle::subscribe_durability_events` | @tirbase-core-team | Wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::DeploymentConfig` | @tirbase-core-team | Config type; wired in gateway init Phase 9 | v0.3.0 |
| `tirbase_core::api::DurabilityTierChanged` | @tirbase-core-team | Event type; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::InitConfig` | @tirbase-core-team | Init config; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types` | @tirbase-core-team | Public API types module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types::ConnectionStatus` | @tirbase-core-team | Mesh connection status; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types::ConnectionStatus::Connected` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::ConnectionStatus::Connecting` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::ConnectionStatus::Disconnected` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::DEFAULT_BISCUIT_TTL_SECS` | @tirbase-core-team | Constant; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types::DurabilityTier` | @tirbase-core-team | Durability tier type; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types::DurabilityTier::Tier1` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::DurabilityTier::Tier2` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::DurabilityTier::Uncommitted` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::MeshStatus` | @tirbase-core-team | Mesh status struct; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types::QueryResult` | @tirbase-core-team | Query result type; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types::TrustLevel` | @tirbase-core-team | Trust level enum; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types::TrustLevel::Revoked` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::TrustLevel::Unverified` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::TrustLevel::Verified` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::api::types::UnverifiedWarning` | @tirbase-core-team | Warning type; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::api::types::WriteResult` | @tirbase-core-team | Write result type; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::auth` | @tirbase-core-team | Auth module; used by gateway and admin in Phase 9 | v0.3.0 |
| `tirbase_core::auth::CapabilityManager` | @tirbase-core-team | Capability manager; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit` | @tirbase-core-team | Biscuit token submodule; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::BiscuitClaims` | @tirbase-core-team | Token claims type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::TTL_MAX_SECS` | @tirbase-core-team | TTL constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::TTL_MIN_SECS` | @tirbase-core-team | TTL constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::TTL_OVERRIDE_CEILING_SECS` | @tirbase-core-team | TTL constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::TokenVerifyError` | @tirbase-core-team | Error type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::TokenVerifyError::OtherFailure` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::TokenVerifyError::TokenExpired` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::create_token` | @tirbase-core-team | Token creation fn; wired in tirbase-admin Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::has_caveat` | @tirbase-core-team | Caveat check fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::verify_and_check_caveat` | @tirbase-core-team | Verify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::verify_token` | @tirbase-core-team | Verify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::verify_token_distinguish_expiry` | @tirbase-core-team | Verify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::biscuit::verify_token_expiry_only` | @tirbase-core-team | Verify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation` | @tirbase-core-team | Revocation submodule; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::DeviceRevocationStatus` | @tirbase-core-team | Status type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::ManagerSignature` | @tirbase-core-team | Signature type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::PendingRevocation` | @tirbase-core-team | Pending state type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::PendingRevocationStore` | @tirbase-core-team | Store type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::RevocationDelta` | @tirbase-core-team | Delta type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::RevocationStatus` | @tirbase-core-team | Status enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::RevocationStatus::Applied` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::RevocationStatus::Pending` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::RevocationSubsystem` | @tirbase-core-team | Subsystem type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::revocation::current_timestamp_micros` | @tirbase-core-team | Utility fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::root_ca` | @tirbase-core-team | Root CA submodule; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::auth::root_ca::RootCaRegistry` | @tirbase-core-team | Registry type; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::auth::trust` | @tirbase-core-team | Trust state machine submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::auth::trust::TrustLevelStateMachine` | @tirbase-core-team | State machine; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination` | @tirbase-core-team | Contamination engine module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::contamination::CausalContaminationEngine` | @tirbase-core-team | Engine type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::human_reaction` | @tirbase-core-team | Human reaction submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::human_reaction::WriteContext` | @tirbase-core-team | Context type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::human_reaction::on_write_commit` | @tirbase-core-team | Hook fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident` | @tirbase-core-team | Incident submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::AffectedRow` | @tirbase-core-team | Data type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::AuditEntry` | @tirbase-core-team | Audit type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::AuditOperation` | @tirbase-core-team | Audit op enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::AuditOperation::AdminClose` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::AuditOperation::VerifyData` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::CompositeIncidentInstance` | @tirbase-core-team | Composite type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::IncidentContextObject` | @tirbase-core-team | ICO type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::IncidentId` | @tirbase-core-team | ID type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::IncidentState` | @tirbase-core-team | State enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::IncidentState::Closed` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::IncidentState::Decomposed` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::IncidentState::Open` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::IncidentState::SupersededBy` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::TaintSource` | @tirbase-core-team | Taint source enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::TaintSource::BadMigration` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::TaintSource::DeviceRevocation` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::TaintSource::HumanReaction` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::incident::composite_merge` | @tirbase-core-team | Merge fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::resolution` | @tirbase-core-team | Resolution submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::resolution::DecompositionResult` | @tirbase-core-team | Result type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::resolution::admin_close` | @tirbase-core-team | Admin close fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::resolution::verify_data` | @tirbase-core-team | Verify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::contamination::taint` | @tirbase-core-team | Taint submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt` | @tirbase-core-team | CRDT engine module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::crdt::CrdtEngine` | @tirbase-core-team | CRDT engine type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::CrdtEngine::apply` | @tirbase-core-team | Apply fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::dag` | @tirbase-core-team | DAG submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::dag::ChangesetDag` | @tirbase-core-team | DAG type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::dag::DagNode` | @tirbase-core-team | Node type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::dag::compress_payload` | @tirbase-core-team | Compression fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::dag::decompress_payload` | @tirbase-core-team | Decompression fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta` | @tirbase-core-team | Delta submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::ActorId` | @tirbase-core-team | Actor ID type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::Delta` | @tirbase-core-team | Delta type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::DeltaId` | @tirbase-core-team | Delta ID type alias; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::DeltaTag` | @tirbase-core-team | Tag enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::DeltaTag::Contaminated` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::DeltaTag::ContaminatedByCorruptedMigration` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::DeltaTag::ContaminatedByHumanReaction` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::DeltaTag::Decontaminated` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::DeltaTag::ReplayComplete` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::DeltaTag::Resolved` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::Did` | @tirbase-core-team | DID type alias in crdt; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::Ed25519Signature` | @tirbase-core-team | Signature type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::PriorityClass` | @tirbase-core-team | Priority enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::PriorityClass::High` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::PriorityClass::Low` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::delta::PriorityClass::Medium` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::derive_did_from_public_key` | @tirbase-core-team | DID derivation fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::lww_incoming_wins` | @tirbase-core-team | LWW merge fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge` | @tirbase-core-team | Merge submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::MergeOutcome` | @tirbase-core-team | Outcome enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::MergeOutcome::Merged` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::MergeOutcome::Quarantined` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::MergeOutcome::Rejected` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::QuarantineReason` | @tirbase-core-team | Reason enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::QuarantineReason::BreakingSchemaChange` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::QuarantineReason::MissingOrMalformedHash` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::QuarantineReason::UnknownSchemaHash` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::merge::apply_incoming_delta` | @tirbase-core-team | Merge fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::rga_incoming_has_priority` | @tirbase-core-team | RGA merge fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::crdt::schema_hash` | @tirbase-core-team | Schema hash submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::diagnostics` | @tirbase-core-team | Diagnostics module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::diagnostics::DiagnosticEntry` | @tirbase-core-team | Entry type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::diagnostics::DiagnosticSeverity` | @tirbase-core-team | Severity enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::diagnostics::DiagnosticSeverity::Info` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::diagnostics::DiagnosticSeverity::Warning` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::diagnostics::emit_startup_diagnostics` | @tirbase-core-team | Startup fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability` | @tirbase-core-team | Durability module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::durability::DurabilitySubsystem` | @tirbase-core-team | Subsystem type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::anchor` | @tirbase-core-team | Anchor submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::anchor::AnchorAttestedLocation` | @tirbase-core-team | Location type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::anchor::AnchorAttestedLocation::check_signal_loss` | @tirbase-core-team | Method; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::anchor::AnchorMode` | @tirbase-core-team | Mode enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::anchor::AnchorMode::BeaconAttested` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::anchor::AnchorMode::SquadTagFallback` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::anchor::BeaconRegistryEntry` | @tirbase-core-team | Entry type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::anchor::TransportDegradationEvent` | @tirbase-core-team | Event type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_ledger` | @tirbase-core-team | Cloud ledger submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_ledger::CloudLedger` | @tirbase-core-team | Ledger type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_ledger::CloudLedgerConnection` | @tirbase-core-team | Connection type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_ledger::ReceiveOutcome` | @tirbase-core-team | Outcome enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_ledger::ReceiveOutcome::AlreadyCommitted` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_ledger::ReceiveOutcome::Committed` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_ledger::ReceiveOutcome::Rejected` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_ledger::RejectionRecord` | @tirbase-core-team | Record type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue` | @tirbase-core-team | Cloud queue submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::CloudConnection` | @tirbase-core-team | Connection type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::CloudOutboundQueue` | @tirbase-core-team | Queue type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::CloudSyncResult` | @tirbase-core-team | Result type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::MAX_QUEUE_DEPTH` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::QueueEntry` | @tirbase-core-team | Entry type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::RefetchOutcome` | @tirbase-core-team | Outcome enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::RefetchOutcome::Success` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::RefetchOutcome::Unavailable` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::cloud_sync_loop` | @tirbase-core-team | Sync loop fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::cloud_queue::refetch_for_cloud_sync` | @tirbase-core-team | Refetch fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::quorum` | @tirbase-core-team | Quorum submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::quorum::QuorumConfig` | @tirbase-core-team | Config type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::quorum::Tier1QuorumTracker` | @tirbase-core-team | Tracker type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::receipt` | @tirbase-core-team | Receipt submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::receipt::BeaconToken` | @tirbase-core-team | Token type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::receipt::DurabilityReceipt` | @tirbase-core-team | Receipt type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::receipt::ReceiptId` | @tirbase-core-team | ID type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::receipt::receipt_signing_payload` | @tirbase-core-team | Signing payload fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::receipt::verify_receipt` | @tirbase-core-team | Verify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::spatial` | @tirbase-core-team | Spatial diversity submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::durability::spatial::SpatialDiversityTracker` | @tirbase-core-team | Tracker type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors` | @tirbase-core-team | Error types module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError` | @tirbase-core-team | Main error enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::AuthorisationFailed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::CloudQueueFull` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::CompactionFailed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::DeltaMalformed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::DidResolutionFailed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::FragmentReassemblyFailed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::InvalidIncidentState` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::LocalStoreWriteFailed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::MeshUnavailable` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::MigrationCaSignatureInvalid` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::MigrationHashMismatch` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::MigrationInProgress` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::MigrationTransformTimeout` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::NoiseHandshakeFailed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::PeerRevoked` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::RefetchUnavailable` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::SchemaParseError` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::SchemaRegistrationFailed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::SignatureVerificationFailed` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::SpatialDiversityDegraded` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::ThresholdNotMet` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::UnknownMigrationHash` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::UnknownSchemaHash` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::UnsupportedTaintSource` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::errors::TirBaseError::VersionPathMismatch` | @tirbase-core-team | Error variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity` | @tirbase-core-team | Identity module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::identity::IdentityManager` | @tirbase-core-team | Manager type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::did` | @tirbase-core-team | DID submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::did::Did` | @tirbase-core-team | DID type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::did::derive_did` | @tirbase-core-team | DID derivation fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::did::load_identity` | @tirbase-core-team | Load fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::did::load_identity_from` | @tirbase-core-team | Load fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::did::persist_identity` | @tirbase-core-team | Persist fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::did::persist_identity_to` | @tirbase-core-team | Persist fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::did::resolve_did` | @tirbase-core-team | Resolve fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::keypair` | @tirbase-core-team | Keypair submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::keypair::generate_keypair` | @tirbase-core-team | Keygen fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::keypair::sign` | @tirbase-core-team | Sign fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::identity::keypair::verify` | @tirbase-core-team | Verify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration` | @tirbase-core-team | Migration module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::migration::SchemaMigrationEngine` | @tirbase-core-team | Engine type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::migration_delta` | @tirbase-core-team | Migration delta submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::migration_delta::CaSignature` | @tirbase-core-team | CA sig type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::migration_delta::ManagerSignature` | @tirbase-core-team | Manager sig type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::migration_delta::MigrationDelta` | @tirbase-core-team | Delta type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::migration_delta::MigrationId` | @tirbase-core-team | ID type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::migration_delta::MigrationRevocationDelta` | @tirbase-core-team | Revocation delta; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::quarantine` | @tirbase-core-team | Quarantine submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::quarantine::QuarantineEntry` | @tirbase-core-team | Entry type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::quarantine::QuarantineLedger` | @tirbase-core-team | Ledger type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::quarantine::QuarantineReason` | @tirbase-core-team | Reason enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::quarantine::QuarantineReason::BreakingSchemaChange` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::quarantine::QuarantineReason::MissingOrMalformedHash` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::quarantine::QuarantineReason::UnknownSchemaHash` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::revocation` | @tirbase-core-team | Migration revocation submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::revocation::RevocationRecord` | @tirbase-core-team | Record type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::revocation::RevokedMigrationRegistry` | @tirbase-core-team | Registry type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::revocation::resolve_did_key_to_public_key` | @tirbase-core-team | Resolve fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar` | @tirbase-core-team | Sidecar submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar::ReplayStatus` | @tirbase-core-team | Status enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar::ReplayStatus::Complete` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar::ReplayStatus::Conflict` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar::ReplayStatus::Pending` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar::ReplayStatus::Replayed` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar::ReplaySummary` | @tirbase-core-team | Summary type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar::SideCarEntry` | @tirbase-core-team | Entry type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::sidecar::SideCarLedger` | @tirbase-core-team | Ledger type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::version_path` | @tirbase-core-team | Version path submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::version_path::SchemaVersionPath` | @tirbase-core-team | Path type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox` | @tirbase-core-team | WASM sandbox submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::MigrationExecutionRegistry` | @tirbase-core-team | Registry type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::MigrationHostState` | @tirbase-core-team | Host state type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::MigrationResult` | @tirbase-core-team | Result enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::MigrationResult::Aborted` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::MigrationResult::Revoked` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::MigrationResult::Success` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::MigrationResult::TimedOut` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::execute_migration` | @tirbase-core-team | Migration exec fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::migration::wasm_sandbox::execute_migration_with_registry` | @tirbase-core-team | Migration exec fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema` | @tirbase-core-team | Schema module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::schema::Constraint` | @tirbase-core-team | Constraint enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::Constraint::NotNull` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::Constraint::PrimaryKey` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::Constraint::Unique` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::DefaultValue` | @tirbase-core-team | Default value enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::DefaultValue::Boolean` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::DefaultValue::Integer` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::DefaultValue::Null` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::DefaultValue::Real` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::DefaultValue::Text` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::FieldDef` | @tirbase-core-team | Field definition type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::FieldType` | @tirbase-core-team | Field type enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::FieldType::Blob` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::FieldType::Boolean` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::FieldType::Integer` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::FieldType::Real` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::FieldType::Text` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::Schema` | @tirbase-core-team | Schema type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::TableDef` | @tirbase-core-team | Table definition type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::hash` | @tirbase-core-team | Schema hash submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::hash::SchemaIdentifierHash` | @tirbase-core-team | Hash type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::hash::compute_schema_identifier_hash` | @tirbase-core-team | Hash fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser` | @tirbase-core-team | Schema parser submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule` | @tirbase-core-team | PEG parser Rule enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::COMMENT` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::EOI` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::WHITESPACE` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::bool_false` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::bool_true` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::column_list` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::compaction_aggressive` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::compaction_directive` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::compaction_none` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::constraint` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::default_modifier` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::default_value` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::field_def` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::field_type` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::ident` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::integer_literal` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::not_null_modifier` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::null_lit` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::primary_key_constraint` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::real_literal` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::schema` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::semver` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::string_literal` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::table_def` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::table_item` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::unique_constraint` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::Rule::version_directive` | @tirbase-core-team | Parser rule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::parser::parse` | @tirbase-core-team | Schema parse fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::printer` | @tirbase-core-team | Schema printer submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::schema::printer::print` | @tirbase-core-team | Schema print fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store` | @tirbase-core-team | Store module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::store::LocalStore` | @tirbase-core-team | Local store type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::compaction` | @tirbase-core-team | Compaction submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::compaction::CompactionPolicy` | @tirbase-core-team | Policy enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::compaction::CompactionPolicy::Aggressive` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::compaction::CompactionPolicy::None` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::compaction::compact_table` | @tirbase-core-team | Compaction fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::compaction::should_compact` | @tirbase-core-team | Predicate fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::projection` | @tirbase-core-team | Projection submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::projection::clear_row_contamination` | @tirbase-core-team | Mutation fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::projection::mark_row_contaminated` | @tirbase-core-team | Mutation fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::projection::project_table` | @tirbase-core-team | Projection fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::projection::record_delta_row` | @tirbase-core-team | Record fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::sqlite` | @tirbase-core-team | SQLite submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::sqlite::CREATE_SCHEMA_SQL` | @tirbase-core-team | SQL constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::store::sqlite::open` | @tirbase-core-team | Open fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport` | @tirbase-core-team | Transport module; wired in gateway Phase 9 | v0.3.0 |
| `tirbase_core::transport::MeshTransport` | @tirbase-core-team | Transport type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::MeshTransport::new` | @tirbase-core-team | Constructor; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::MeshTransport::send_delta` | @tirbase-core-team | Send fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::TirBaseBehaviour` | @tirbase-core-team | libp2p Behaviour type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::TirBaseBehaviourEvent` | @tirbase-core-team | Behaviour event enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::TirBaseBehaviourEvent::Gossipsub` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::TirBaseBehaviourEvent::Identify` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::TirBaseBehaviourEvent::Mdns` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::TirBaseBehaviourEvent::Ping` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::TransportConfig` | @tirbase-core-team | Config type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble` | @tirbase-core-team | BLE transport submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::BLE_CHUNK_HEADER_SIZE` | @tirbase-core-team | BLE constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::BLE_MAX_CHUNK_SIZE` | @tirbase-core-team | BLE constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::BLE_MAX_PAYLOAD` | @tirbase-core-team | BLE constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::BleAdapter` | @tirbase-core-team | BLE adapter type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::TIRBASE_BLE_CHAR_UUID` | @tirbase-core-team | BLE UUID constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::TIRBASE_BLE_SERVICE_UUID` | @tirbase-core-team | BLE UUID constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::fragment_for_ble` | @tirbase-core-team | Fragmentation fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::parse_ble_chunk` | @tirbase-core-team | Parse fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::ble::reassemble_ble_chunks` | @tirbase-core-team | Reassembly fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery` | @tirbase-core-team | Peer discovery submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::DiscoveredPeer` | @tirbase-core-team | Peer type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::PeerDiscovery` | @tirbase-core-team | Discovery type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::PeerState` | @tirbase-core-team | State type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::PeerTransport` | @tirbase-core-team | Transport enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::PeerTransport::BleBridge` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::PeerTransport::Explicit` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::PeerTransport::Mdns` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::PeerTransport::MultiHopRelay` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::RetryEntry` | @tirbase-core-team | Entry type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::ble_adapter` | @tirbase-core-team | BLE adapter submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::ble_adapter::TIRBASE_BLE_SERVICE_UUID` | @tirbase-core-team | UUID constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::ble_adapter::scan_ble_peers` | @tirbase-core-team | Scan fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::mdns_adapter` | @tirbase-core-team | mDNS adapter submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::mdns_adapter::handle_mdns_event` | @tirbase-core-team | Event handler; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::discovery::mdns_adapter::peer_id_to_did` | @tirbase-core-team | Conversion fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::fragment` | @tirbase-core-team | Fragmentation submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::fragment::DeltaFragment` | @tirbase-core-team | Fragment type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::fragment::MAX_FRAGMENTS_PER_DELTA` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::fragment::MAX_REASSEMBLY_SLOTS` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::fragment::ReassemblyBuffer` | @tirbase-core-team | Buffer type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::fragment::fragment` | @tirbase-core-team | Fragment fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::fragment::reassemble` | @tirbase-core-team | Reassemble fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message` | @tirbase-core-team | Message submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message::GossipMessage` | @tirbase-core-team | Message enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message::GossipMessage::InboundDelta` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message::GossipMessage::InboundDeltaFragment` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message::GossipMessage::InboundDurabilityReceipt` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message::GossipMessage::InboundMigrationDelta` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message::GossipMessage::InboundMigrationRevocationDelta` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message::GossipMessage::InboundRevocationDelta` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::message::GossipMessage::RelayDelta` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority` | @tirbase-core-team | Priority submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::PayloadFlag` | @tirbase-core-team | Flag enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::PayloadFlag::EmergencyAlert` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::PayloadFlag::LinkState` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::PayloadFlag::PeerReachability` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::PayloadFlag::Revocation` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::PayloadFlag::SafetyAlert` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::PayloadFlag::SessionValidity` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::classify` | @tirbase-core-team | Classify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::priority::classify_with_flags` | @tirbase-core-team | Classify fn; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::saturate` | @tirbase-core-team | Saturate mode submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::saturate::RENEWAL_WINDOW_SECS` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::saturate::SATURATE_LEASE_DURATION_SECS` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::saturate::SaturateLease` | @tirbase-core-team | Lease type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::saturate::SaturateModeStateMachine` | @tirbase-core-team | State machine type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::saturate::SaturateState` | @tirbase-core-team | State enum; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::saturate::SaturateState::Normal` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::saturate::SaturateState::Saturate` | @tirbase-core-team | Enum variant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::scheduler` | @tirbase-core-team | DRR scheduler submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::scheduler::DrrScheduler` | @tirbase-core-team | Scheduler type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::scheduler::QueuedDelta` | @tirbase-core-team | Delta queue entry; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session` | @tirbase-core-team | Noise session submodule; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::AsyncNoiseStream` | @tirbase-core-team | Stream type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::CREDENTIAL_VALIDITY_SECS` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::DuplexNoiseStream` | @tirbase-core-team | Stream type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::HandshakeFailureRecord` | @tirbase-core-team | Record type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::MAX_RESUMPTION_CACHE` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::MAX_ROTATION_INTERVAL_SECS` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::MIN_RETRY_BACKOFF_SECS` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::MIN_ROTATION_INTERVAL_SECS` | @tirbase-core-team | Constant; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::NoiseSession` | @tirbase-core-team | Session type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::PeerPair` | @tirbase-core-team | Peer pair type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::ResumptionCredential` | @tirbase-core-team | Credential type; wired in Phase 9 | v0.3.0 |
| `tirbase_core::transport::session::SessionManager` | @tirbase-core-team | Session manager type; wired in Phase 9 | v0.3.0 |
| `tirbase_types::envelope::ConstraintOperator` | @tirbase-core-team | Envelope constraint operator (PV-4.5, CLAIM-10.3); Stage 12 evaluation wired in | v0.3.0 |
| `tirbase_types::envelope::DeviceModel` | @tirbase-core-team | Device model validation view (PV-10.2, CLAIM-10.6); driver model wired in | v0.3.0 |
| `tirbase_types::envelope::DeviceParameter` | @tirbase-core-team | Device parameter validation view (PV-10.2, CLAIM-10.6); driver model wired in | v0.3.0 |
| `tirbase_types::envelope::EnvelopeProfile` | @tirbase-core-team | Signed envelope profile document (PV-4.5, CLAIM-10.4); guard/gateway pipeline wired in | v0.3.0 |
| `tirbase_types::envelope::EnvelopeProfileBody` | @tirbase-core-team | Unsigned profile body for signing/verification (PV-4.5, CLAIM-10.4) | v0.3.0 |
| `tirbase_types::envelope::LinearConstraint` | @tirbase-core-team | Cross-parameter constraint (PV-4.5, CLAIM-10.3); Stage 12 wired in | v0.3.0 |
| `tirbase_types::envelope::ParameterKind` | @tirbase-core-team | Parameter domain kind (PV-4.5, CLAIM-10.1); Stage 10-13 wired in | v0.3.0 |
| `tirbase_types::envelope::ParameterSpec` | @tirbase-core-team | Per-parameter spec (PV-4.5, CLAIM-10.2); Stage 10-13 wired in | v0.3.0 |
| `tirbase_guard::envelope::FieldError` | @tirbase-core-team | Profile validation field error (PV-4.5, CLAIM-10.6); guard install path wired in | v0.3.0 |
| `tirbase_guard::envelope::ProfileInstallError` | @tirbase-core-team | Profile install error (PV-4.5, CLAIM-10.4/10.6); guard install path wired in | v0.3.0 |
| `tirbase_guard::envelope::ProfileMap` | @tirbase-core-team | Target-to-profile hot-swap map (PV-4.5, CLAIM-10.5); CommandGuard wiring in | v0.3.0 |
| `tirbase_guard::envelope::install_profile` | @tirbase-core-team | Production profile install path (PV-4.5, CLAIM-10.4/10.6); guard/gateway wiring in | v0.3.0 |
| `tirbase_guard::envelope::profile_signing_bytes` | @tirbase-core-team | Domain-separated profile signing bytes (PV-4.5, CLAIM-10.4) | v0.3.0 |
| `tirbase_guard::envelope::validate_profile` | @tirbase-core-team | Install-time profile validation (PV-4.5, CLAIM-10.6); guard wiring in | v0.3.0 |
| `tirbase_guard::envelope::verify_profile_signature` | @tirbase-core-team | PolicyAuthority profile signature check (PV-4.5, CLAIM-10.4); guard wiring in | v0.3.0 |
| `tirbase_guard::signed_operation::CONTEXT_ENVELOPE_PROFILE` | @tirbase-core-team | Domain-separation context for EnvelopeProfile signatures (PV-4.5, CLAIM-10.4) | v0.3.0 |
| `tirbase_guard::command` | @tirbase-guard-team | No source reference from any other workspace crate; guard-internal signed-command surface pending a library consumer | v0.3.0 |
| `tirbase_guard::commit` | @tirbase-guard-team | No source reference from any other workspace crate; commit/effects outcome surface pending a library consumer | v0.3.0 |
| `tirbase_guard::device_transport` | @tirbase-guard-team | No source reference from any other workspace crate; device-transport surface pending a library consumer | v0.3.0 |
| `tirbase_guard::guard` | @tirbase-guard-team | No source reference from any other workspace crate; CommandGuard surface is exercised through `tirbase_guard::admit` instead | v0.3.0 |
| `tirbase_guard::permit` | @tirbase-guard-team | No source reference from any other workspace crate; sealed ActuationPermit is intentionally guard-internal (PV-4.3, CLAIM-11.2) | v0.3.0 |
| `tirbase_guard::policy` | @tirbase-guard-team | No source reference from any other workspace crate; policy lifecycle surface pending a library consumer | v0.3.0 |
| `tirbase_guard::signed_operation` | @tirbase-guard-team | No source reference from any other workspace crate; domain-separated signing surface pending a library consumer | v0.3.0 |
| `tirbase_guard::single_writer_lease` | @tirbase-guard-team | No source reference from any other workspace crate; single-writer lease surface pending a library consumer | v0.3.0 |
| `tirbase_sim::drivers` | @tirbase-sim-team | No source reference from any other workspace crate; simulated-driver surface is exercised only by simulator tests | v0.3.0 |
| `tirbase_sim::invariants` | @tirbase-sim-team | No source reference from any other workspace crate; invariant catalogue is exercised only by simulator tests | v0.3.0 |
| `tirbase_sim::models` | @tirbase-sim-team | Deterministic thermal/battery models (CLAIM-38.4/38.5) are consumed by the sim runtime and integration tests; no cross-crate caller yet | v0.3.0 |
| `tirbase_sim::network` | @tirbase-sim-team | Fault-injecting virtual network (CLAIM-38.3) is consumed by the sim runtime and integration tests; no cross-crate caller yet | v0.3.0 |
| `tirbase_sim::sim` | @tirbase-sim-team | SimClock/SimNode/scenario harness (CLAIM-38.2) is consumed by `TirBaseSim` and integration tests; no cross-crate caller yet | v0.3.0 |
| `tirbase_sim::TirBaseSim` | @tirbase-sim-team | Seeded simulator entry point (CLAIM-38.1) is exercised by `tirbase-sim` integration tests only | v0.3.0 |
| `tirbase_sim::DEFAULT_SCENARIO_NODES` | @tirbase-sim-team | Default scenario sizing constant (CLAIM-38.1) belongs to the simulator's own test harness | v0.3.0 |
| `tirbase_sim::DEFAULT_SCENARIO_MESSAGES_PER_TICK` | @tirbase-sim-team | Default scenario traffic constant (CLAIM-38.1) belongs to the simulator's own test harness | v0.3.0 |
| `tirbase_types::deserialize` | @tirbase-core-team | No source reference from any other workspace crate; helper module currently unused | v0.3.0 |
| `tirbase_types::fixed_point` | @tirbase-core-team | No source reference from any other workspace crate; public items are re-exported at the crate root and the remaining error variants are unused | v0.3.0 |
| `tirbase_types::units` | @tirbase-core-team | No source reference from any other workspace crate; unit constants are consumed through `UnitId`/`UnitDescriptor` rather than by name | v0.3.0 |
| `tirbase_types::ParseCommandRoleError` | @tirbase-core-team | No source reference from any other workspace crate; public CommandRole parse error type (PV-3.1) awaiting a consumer | v0.3.0 |
| `tirbase_core::fleet` | @tirbase-core-team | Fleet inventory CRDT collection (PV-11.3, CLAIM-37.5); consumed through `CoreHandle::fleet_*` and the migration fleet-precondition verifier, so the module's own public surface has no cross-crate caller yet | v0.3.0 |
