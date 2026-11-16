// SPDX-License-Identifier: AGPL-3.0-only

//! Master data service integration tests (CC-15).
//!
//! Proves versioning and effective dates (a revision appends a version and
//! closes the previous range; history is audited), that a master-data change
//! never rewrites a historical event's meaning, that invalid identifiers, units
//! and location hierarchies are rejected, that a real lot and a real excursion
//! resolve their site, location, item and party, that calibration state follows
//! the asset record, and that the JSON/CSV/EPCIS exports are stable.

use std::collections::BTreeSet;

use tirbase_gateway::excursion::mkt::{MktParameters, MKT_UNIT_ID};
use tirbase_gateway::excursion::{
    evaluate_detection, DetectionInputs, DetectionThresholds, ExcursionWorkflow,
};
use tirbase_gateway::lot::{LotDraft, LotKind, LotRegistry};
use tirbase_gateway::master_data::epcis::EpcisVocabulary;
use tirbase_gateway::master_data::{
    AuditAction, CalibrationStatus, CarrierAttributes, DeviceAttributes, EntityKind, EventRefs,
    LifecycleStatus, LocationAttributes, LocationKind, LotAttributes, MasterAttributes, MasterData,
    MasterDataError, MasterDraft, MasterQuery, PartyAttributes, PartyRole, QuantityUnit,
    SiteAttributes, StorageZoneAttributes, TradeItemAttributes, TransportMode, MAX_LOCATION_DEPTH,
};
use tirbase_types::{FixedPointValue, UNIT_DEG_C};

const ACTOR: &str = "did:key:z6MkMasterDataActor";

fn deci_c(value: i64) -> FixedPointValue {
    FixedPointValue::new(value, -1, UNIT_DEG_C)
}

/// Append the GS1 check digit to a body of digits.
fn gs1(body: &str) -> String {
    let mut sum = 0u32;
    for (index, character) in body.chars().rev().enumerate() {
        let digit = character.to_digit(10).expect("digits");
        sum += if index % 2 == 0 { digit * 3 } else { digit };
    }
    format!("{body}{}", (10 - sum % 10) % 10)
}

fn gln(seed: &str) -> String {
    gs1(seed)
}

fn gtin(seed: &str) -> String {
    gs1(seed)
}

fn site_draft(id: &str, name: &str, at_est: i64, operator: Option<&str>) -> MasterDraft {
    MasterDraft::new(
        id,
        at_est,
        LifecycleStatus::Active,
        MasterAttributes::Site(SiteAttributes {
            name: name.to_string(),
            gln: gln("400638133393"),
            country: "DE".to_string(),
            operator_party_id: operator.map(str::to_string),
        }),
        ACTOR,
    )
    .with_reason("initial site")
}

fn location_draft(
    id: &str,
    name: &str,
    site_id: &str,
    parent: Option<&str>,
    at_est: i64,
) -> MasterDraft {
    let mut draft = MasterDraft::new(
        id,
        at_est,
        LifecycleStatus::Active,
        MasterAttributes::Location(LocationAttributes {
            site_id: site_id.to_string(),
            parent_location_id: parent.map(str::to_string),
            name: name.to_string(),
            kind: LocationKind::ColdRoom,
            gln: None,
        }),
        ACTOR,
    )
    .with_site(site_id)
    .with_reason("initial location");
    if let Some(parent) = parent {
        draft = draft.with_parent(parent);
    }
    draft
}

fn party_draft(id: &str, name: &str, role: PartyRole, at_est: i64) -> MasterDraft {
    MasterDraft::new(
        id,
        at_est,
        LifecycleStatus::Active,
        MasterAttributes::Party(PartyAttributes {
            name: name.to_string(),
            gln: gln("400638133394"),
            role,
        }),
        ACTOR,
    )
    .with_reason("initial party")
}

fn item_draft(id: &str, name: &str, at_est: i64) -> MasterDraft {
    MasterDraft::new(
        id,
        at_est,
        LifecycleStatus::Active,
        MasterAttributes::TradeItem(TradeItemAttributes {
            gtin: gtin("0950110153000"),
            name: name.to_string(),
            uom: QuantityUnit::Kilogram,
            net_content: Some(25),
            brand_owner_party_id: Some("party-owner".to_string()),
        }),
        ACTOR,
    )
    .with_reason("initial item")
}

fn device_draft(id: &str, at_est: i64, calibration_interval: Option<u64>) -> MasterDraft {
    MasterDraft::new(
        id,
        at_est,
        LifecycleStatus::Active,
        MasterAttributes::Device(DeviceAttributes {
            site_id: "site-1".to_string(),
            location_id: "loc-1".to_string(),
            asset_id: format!("ASSET-{id}"),
            device_class: "temperature-sensor".to_string(),
            calibration: calibration_interval.map(|interval_secs| {
                tirbase_gateway::master_data::CalibrationAttributes {
                    calibrated_est: at_est,
                    interval_secs,
                    certificate_id: "CERT-2026-01".to_string(),
                    laboratory_party_id: Some("party-lab".to_string()),
                }
            }),
        }),
        ACTOR,
    )
    .with_site("site-1")
    .with_reason("device install")
}

/// Site → location → zone → parties → item → device, all effective at `at_est`.
fn seed(md: &MasterData, at_est: i64) {
    md.put(party_draft(
        "party-op",
        "Operator Ltd",
        PartyRole::Operator,
        at_est,
    ))
    .expect("operator");
    md.put(party_draft(
        "party-owner",
        "Brand Owner Ltd",
        PartyRole::Owner,
        at_est,
    ))
    .expect("owner");
    md.put(party_draft(
        "party-lab",
        "Calibration Lab",
        PartyRole::Laboratory,
        at_est,
    ))
    .expect("laboratory");
    md.put(site_draft("site-1", "Dock 1", at_est, Some("party-op")))
        .expect("site");
    md.put(location_draft("loc-1", "Cold room", "site-1", None, at_est))
        .expect("location");
    md.put(MasterDraft::new(
        "zone-1",
        at_est,
        LifecycleStatus::Active,
        MasterAttributes::StorageZone(StorageZoneAttributes {
            site_id: "site-1".to_string(),
            location_id: "loc-1".to_string(),
            name: "2-8C zone".to_string(),
            storage_class: "2-8C".to_string(),
            min_temp_c: deci_c(20),
            max_temp_c: deci_c(80),
        }),
        ACTOR,
    ))
    .expect("zone");
    md.put(item_draft("item-1", "Vaccine 25 kg", at_est))
        .expect("item");
    md.put(device_draft("dev-1", at_est, Some(86_400)))
        .expect("device");
}

// ---------------------------------------------------------------------------
// Versioning and effective dates
// ---------------------------------------------------------------------------

#[test]
fn versions_are_effective_from_their_start_and_history_is_audited() {
    let md = MasterData::open_in_memory().expect("master data");
    let first = md
        .put(site_draft("site-1", "Dock 1", 1_000, None))
        .expect("first version");
    assert_eq!(first.version, 1);
    assert_eq!(first.effective_from_est, 1_000);
    assert_eq!(first.effective_to_est, None);
    assert!(first.is_effective_at(1_000));

    // Before the record starts, there is no version in force at all.
    assert!(matches!(
        md.get(EntityKind::Site, "site-1", 999),
        Err(MasterDataError::NotEffective { .. })
    ));
    assert_eq!(
        md.get(EntityKind::Site, "site-1", 1_000)
            .expect("in force")
            .attributes
            .name(),
        "Dock 1"
    );

    // A revision appends; it never rewrites the first version.
    let second = md
        .put(
            MasterDraft::new(
                "site-1",
                2_000,
                LifecycleStatus::Active,
                MasterAttributes::Site(SiteAttributes {
                    name: "Dock 1 (renamed)".to_string(),
                    gln: gln("400638133393"),
                    country: "DE".to_string(),
                    operator_party_id: None,
                }),
                ACTOR,
            )
            .with_reason("rebrand"),
        )
        .expect("second version");
    assert_eq!(second.version, 2);

    let versions = md.versions(EntityKind::Site, "site-1").expect("versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].attributes.name(), "Dock 1");
    assert_eq!(versions[0].effective_to_est, Some(2_000));
    assert_eq!(versions[1].attributes.name(), "Dock 1 (renamed)");

    // Effective dates decide what an event at that instant sees.
    assert_eq!(
        md.get(EntityKind::Site, "site-1", 1_500)
            .expect("mid-range")
            .attributes
            .name(),
        "Dock 1"
    );
    assert_eq!(
        md.get(EntityKind::Site, "site-1", 2_500)
            .expect("after revision")
            .attributes
            .name(),
        "Dock 1 (renamed)"
    );

    // Audit history records both changes, with the superseded digest.
    let history = md.history(EntityKind::Site, "site-1").expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].action, AuditAction::Created);
    assert_eq!(history[1].action, AuditAction::Revised);
    assert_eq!(history[1].version, 2);
    assert_eq!(
        history[1].detail["previous_digest"],
        serde_json::json!(first.digest)
    );
    assert_eq!(history[1].reason, "rebrand");

    // Re-putting identical content is idempotent: no version, no audit row.
    let repeated = md
        .put(
            MasterDraft::new(
                "site-1",
                3_000,
                LifecycleStatus::Active,
                MasterAttributes::Site(SiteAttributes {
                    name: "Dock 1 (renamed)".to_string(),
                    gln: gln("400638133393"),
                    country: "DE".to_string(),
                    operator_party_id: None,
                }),
                ACTOR,
            )
            .with_reason("retry"),
        )
        .expect("idempotent");
    assert_eq!(repeated.version, 2);
    assert_eq!(
        md.versions(EntityKind::Site, "site-1")
            .expect("versions")
            .len(),
        2
    );
    assert_eq!(
        md.history(EntityKind::Site, "site-1")
            .expect("history")
            .len(),
        2
    );

    // A revision must take effect after the version it supersedes.
    assert!(matches!(
        md.put(MasterDraft::new(
            "site-1",
            2_000,
            LifecycleStatus::Active,
            MasterAttributes::Site(SiteAttributes {
                name: "Same instant".to_string(),
                gln: gln("400638133393"),
                country: "DE".to_string(),
                operator_party_id: None,
            }),
            ACTOR,
        )),
        Err(MasterDataError::EffectiveDate { .. })
    ));

    // Retired is terminal: it cannot come back to Active.
    md.retire(EntityKind::Site, "site-1", 4_000, ACTOR, "closed")
        .expect("retire");
    assert!(matches!(
        md.put(MasterDraft::new(
            "site-1",
            5_000,
            LifecycleStatus::Active,
            MasterAttributes::Site(SiteAttributes {
                name: "Reopened".to_string(),
                gln: gln("400638133393"),
                country: "DE".to_string(),
                operator_party_id: None,
            }),
            ACTOR,
        )),
        Err(MasterDataError::IllegalStatusTransition { .. })
    ));
}

// ---------------------------------------------------------------------------
// Historical events are not rewritten
// ---------------------------------------------------------------------------

fn hot_detection(at: i64) -> tirbase_gateway::excursion::DetectionOutcome {
    // The unit registry's temperature unit is deci-degrees Celsius; the MKT
    // calculation uses the same unit.
    let thresholds = DetectionThresholds {
        band_min_c: deci_c(20),
        band_max_c: deci_c(80),
        max_rate_c_per_sec: deci_c(2),
        drift_budget_c: deci_c(50),
        max_door_open_secs: 120,
        max_defrost_secs: 900,
        compressor_max_runtime_secs: 21_600,
        max_telemetry_gap_secs: 300,
        mkt_limit_c: deci_c(80),
        mkt: MktParameters::default(),
    };
    let _ = MKT_UNIT_ID;
    evaluate_detection(
        &thresholds,
        &DetectionInputs {
            temperature_c: Some(deci_c(120)),
            previous_temperature_c: Some(deci_c(50)),
            elapsed_secs: 300,
            samples: vec![deci_c(50), deci_c(50), deci_c(120), deci_c(120)],
            ..Default::default()
        },
        at,
    )
}

#[test]
fn a_master_data_change_does_not_rewrite_historical_events() {
    let md = MasterData::open_in_memory().expect("master data");
    let opened_est = 1_770_000_000;
    seed(&md, opened_est);

    // A real CC-12 lot and a real CC-11 excursion about it.
    let lots = LotRegistry::open_in_memory().expect("lots");
    let lot = lots
        .register(LotDraft::new(
            "LOT-1",
            "tenant-a",
            LotKind::Lot,
            "site-1",
            "loc-1",
            100,
            "kg",
            opened_est,
        ))
        .expect("register lot");
    md.link_lot(&lot, "item-1", opened_est, ACTOR)
        .expect("link lot");

    let wf = ExcursionWorkflow::open_in_memory().expect("workflow");
    let record_id = "exc-1";
    wf.detect(
        record_id,
        "tenant-a",
        "site-1",
        "dev-1",
        Some("LOT-1"),
        hot_detection(opened_est),
        opened_est,
    )
    .expect("detect");
    wf.open_quarantine(record_id, opened_est + 1)
        .expect("quarantine");
    let record = wf.get(record_id).expect("record");

    // Resolving at the event's own time finds its site, location, item and party.
    let lot_before = serde_json::to_value(&lot).expect("serialize lot");
    let record_before = serde_json::to_value(&record).expect("serialize record");

    let resolved = md.resolve_lot(&lot, opened_est);
    assert!(resolved.complete(), "{:?}", resolved.missing);
    assert_eq!(
        resolved.names(),
        vec![
            "Dock 1".to_string(),
            "Cold room".to_string(),
            "Vaccine 25 kg".to_string(),
            "Operator Ltd".to_string(),
        ]
    );
    resolved.require_complete().expect("complete");

    let event = md.resolve_excursion(&record, opened_est);
    assert!(event.complete(), "{:?}", event.missing);
    assert_eq!(
        event.location.expect("location").id,
        "loc-1",
        "the observing device supplies the location"
    );
    assert_eq!(event.trade_item.expect("item").id, "item-1");
    assert_eq!(event.party.expect("party").id, "party-op");
    assert_eq!(event.device.expect("device").id, "dev-1");

    // Master data changes afterwards: the site and the item are renamed, the
    // operator changes, and the location is retired.
    let changed_at = opened_est + 10_000;
    md.put(
        MasterDraft::new(
            "site-1",
            changed_at,
            LifecycleStatus::Active,
            MasterAttributes::Site(SiteAttributes {
                name: "Dock 1 (new operator)".to_string(),
                gln: gln("400638133393"),
                country: "DE".to_string(),
                operator_party_id: Some("party-owner".to_string()),
            }),
            ACTOR,
        )
        .with_reason("operator change"),
    )
    .expect("revise site");
    md.put(
        MasterDraft::new(
            "item-1",
            changed_at,
            LifecycleStatus::Active,
            MasterAttributes::TradeItem(TradeItemAttributes {
                gtin: gtin("0950110153000"),
                name: "Vaccine 25 kg (2027 label)".to_string(),
                uom: QuantityUnit::Kilogram,
                net_content: Some(25),
                brand_owner_party_id: Some("party-owner".to_string()),
            }),
            ACTOR,
        )
        .with_reason("label change"),
    )
    .expect("revise item");

    // The historical event still resolves to the values in force when it happened.
    let resolved_again = md.resolve_lot(&lot, opened_est);
    assert_eq!(
        resolved_again.names(),
        vec![
            "Dock 1".to_string(),
            "Cold room".to_string(),
            "Vaccine 25 kg".to_string(),
            "Operator Ltd".to_string(),
        ],
        "a master data change must not rewrite a historical resolution"
    );
    assert_eq!(resolved_again, md.resolve_lot(&lot, opened_est));

    // A new event sees the new values.
    let current = md.resolve_lot(&lot, changed_at + 1);
    assert_eq!(
        current.names(),
        vec![
            "Dock 1 (new operator)".to_string(),
            "Cold room".to_string(),
            "Vaccine 25 kg (2027 label)".to_string(),
            "Brand Owner Ltd".to_string(),
        ]
    );

    // And the stored domain records are untouched: no rewrite happened.
    assert_eq!(
        serde_json::to_value(&lot).expect("serialize lot"),
        lot_before
    );
    assert_eq!(
        serde_json::to_value(wf.get(record_id).expect("record")).expect("serialize record"),
        record_before
    );
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn invalid_identifiers_units_and_hierarchies_are_rejected() {
    let md = MasterData::open_in_memory().expect("master data");
    seed(&md, 1_000);

    // GS1 identifiers: wrong length and wrong check digit.
    let mut bad_gln = site_draft("site-bad", "Bad", 1_000, None);
    if let MasterAttributes::Site(attributes) = &mut bad_gln.attributes {
        attributes.gln = "4006381333932".to_string();
    }
    assert!(matches!(
        md.put(bad_gln),
        Err(MasterDataError::InvalidIdentifier { ref field, .. }) if field == "gln"
    ));

    let mut bad_gtin = item_draft("item-bad", "Bad", 1_000);
    if let MasterAttributes::TradeItem(attributes) = &mut bad_gtin.attributes {
        attributes.gtin = "095011015300".to_string();
    }
    assert!(matches!(
        md.put(bad_gtin),
        Err(MasterDataError::InvalidIdentifier { ref field, .. }) if field == "gtin"
    ));

    // A malformed internal identifier.
    assert!(matches!(
        md.put(location_draft("bad id", "Bad", "site-1", None, 1_000)),
        Err(MasterDataError::InvalidIdentifier { ref field, .. }) if field == "id"
    ));

    // Parent must exist.
    assert!(matches!(
        md.put(location_draft(
            "loc-orphan",
            "Orphan",
            "site-1",
            Some("loc-missing"),
            1_000
        )),
        Err(MasterDataError::Hierarchy { .. })
    ));

    // Parent must belong to the same site.
    md.put(site_draft("site-2", "Dock 2", 1_000, None))
        .expect("second site");
    md.put(location_draft(
        "loc-other",
        "Other site room",
        "site-2",
        None,
        1_000,
    ))
    .expect("other site location");
    assert!(md
        .put(location_draft(
            "loc-cross",
            "Cross",
            "site-1",
            Some("loc-other"),
            1_000
        ))
        .is_err());

    // No self-parenting.
    assert!(matches!(
        md.put(location_draft(
            "loc-1",
            "Cold room",
            "site-1",
            Some("loc-1"),
            1_500
        )),
        Err(MasterDataError::Hierarchy { .. })
    ));

    // No cycles: a -> b is fine, b's parent a2 -> ... -> b is not.
    md.put(location_draft("loc-a", "A", "site-1", Some("loc-1"), 1_000))
        .expect("a");
    md.put(location_draft("loc-b", "B", "site-1", Some("loc-a"), 1_000))
        .expect("b");
    let cycle = md.put(location_draft("loc-a", "A", "site-1", Some("loc-b"), 1_500));
    match cycle {
        Err(MasterDataError::Hierarchy { detail }) => {
            assert!(detail.contains("cycle"), "{detail}");
        }
        other => panic!("expected a cycle rejection, got {other:?}"),
    }

    // Depth is bounded.
    let mut parent = "loc-b".to_string();
    for depth in 0..MAX_LOCATION_DEPTH {
        let id = format!("loc-deep-{depth}");
        let draft = location_draft(&id, "Deep", "site-1", Some(&parent), 1_000);
        match md.put(draft) {
            Ok(_) => parent = id,
            Err(MasterDataError::Hierarchy { .. }) => break,
            Err(other) => panic!("unexpected: {other}"),
        }
    }
    let beyond = md.put(location_draft(
        "loc-too-deep",
        "Too deep",
        "site-1",
        Some(&parent),
        1_000,
    ));
    match beyond {
        Err(MasterDataError::Hierarchy { detail }) => {
            assert!(detail.contains("nesting"), "{detail}");
        }
        other => panic!("expected a depth rejection, got {other:?}"),
    }

    // A zone's location must be in the zone's site.
    assert!(matches!(
        md.put(MasterDraft::new(
            "zone-cross",
            1_000,
            LifecycleStatus::Active,
            MasterAttributes::StorageZone(StorageZoneAttributes {
                site_id: "site-1".to_string(),
                location_id: "loc-other".to_string(),
                name: "Cross".to_string(),
                storage_class: "2-8C".to_string(),
                min_temp_c: deci_c(20),
                max_temp_c: deci_c(80),
            }),
            ACTOR,
        )),
        Err(MasterDataError::Hierarchy { .. })
    ));

    // Zone bands must be Celsius, deci-degrees, and ordered.
    assert!(matches!(
        md.put(MasterDraft::new(
            "zone-units",
            1_000,
            LifecycleStatus::Active,
            MasterAttributes::StorageZone(StorageZoneAttributes {
                site_id: "site-1".to_string(),
                location_id: "loc-1".to_string(),
                name: "Kelvin".to_string(),
                storage_class: "2-8C".to_string(),
                min_temp_c: FixedPointValue::new(2, 0, UNIT_DEG_C),
                max_temp_c: deci_c(80),
            }),
            ACTOR,
        )),
        Err(MasterDataError::Invalid { ref field, .. }) if field == "min_temp_c"
    ));
    assert!(matches!(
        md.put(MasterDraft::new(
            "zone-order",
            1_000,
            LifecycleStatus::Active,
            MasterAttributes::StorageZone(StorageZoneAttributes {
                site_id: "site-1".to_string(),
                location_id: "loc-1".to_string(),
                name: "Inverted".to_string(),
                storage_class: "2-8C".to_string(),
                min_temp_c: deci_c(80),
                max_temp_c: deci_c(20),
            }),
            ACTOR,
        )),
        Err(MasterDataError::Invalid { ref field, .. }) if field == "min_temp_c"
    ));

    // Unknown units are refused rather than guessed.
    assert!(matches!(
        QuantityUnit::parse("bushel"),
        Err(MasterDataError::UnknownUnit { .. })
    ));

    // A lot must name a real item, with the item's unit.
    assert!(matches!(
        md.put(
            MasterDraft::new(
                "LOT-X",
                1_000,
                LifecycleStatus::Active,
                MasterAttributes::Lot(LotAttributes {
                    trade_item_id: "item-missing".to_string(),
                    site_id: "site-1".to_string(),
                    location_id: "loc-1".to_string(),
                    quantity: 10,
                    uom: QuantityUnit::Kilogram,
                    lot_kind: None,
                }),
                ACTOR,
            )
            .with_site("site-1")
        ),
        Err(MasterDataError::Hierarchy { .. })
    ));
    assert!(matches!(
        md.put(MasterDraft::new(
            "LOT-Y",
            1_000,
            LifecycleStatus::Active,
            MasterAttributes::Lot(LotAttributes {
                trade_item_id: "item-1".to_string(),
                site_id: "site-1".to_string(),
                location_id: "loc-1".to_string(),
                quantity: 10,
                uom: QuantityUnit::Litre,
                lot_kind: None,
            }),
            ACTOR,
        )
        .with_site("site-1")),
        Err(MasterDataError::Invalid { ref field, .. }) if field == "uom"
    ));

    // A retired record cannot be referenced by a new record.
    md.retire(
        EntityKind::Location,
        "loc-a",
        2_000,
        ACTOR,
        "decommissioned",
    )
    .expect("retire location");
    assert!(matches!(
        md.put(location_draft(
            "loc-under-retired",
            "Under retired",
            "site-1",
            Some("loc-a"),
            2_500
        )),
        Err(MasterDataError::Hierarchy { .. })
    ));

    // Calibration cannot postdate the version that records it, and its lab must
    // be a laboratory.
    assert!(matches!(
        md.put(MasterDraft::new(
            "dev-bad-cal",
            1_000,
            LifecycleStatus::Active,
            MasterAttributes::Device(DeviceAttributes {
                site_id: "site-1".to_string(),
                location_id: "loc-1".to_string(),
                asset_id: "ASSET-1".to_string(),
                device_class: "temperature-sensor".to_string(),
                calibration: Some(tirbase_gateway::master_data::CalibrationAttributes {
                    calibrated_est: 2_000,
                    interval_secs: 3_600,
                    certificate_id: "CERT".to_string(),
                    laboratory_party_id: None,
                }),
            }),
            ACTOR,
        )),
        Err(MasterDataError::Invalid { .. })
    ));
    assert!(matches!(
        md.put(MasterDraft::new(
            "dev-bad-lab",
            3_000,
            LifecycleStatus::Active,
            MasterAttributes::Device(DeviceAttributes {
                site_id: "site-1".to_string(),
                location_id: "loc-1".to_string(),
                asset_id: "ASSET-1".to_string(),
                device_class: "temperature-sensor".to_string(),
                calibration: Some(tirbase_gateway::master_data::CalibrationAttributes {
                    calibrated_est: 3_000,
                    interval_secs: 3_600,
                    certificate_id: "CERT".to_string(),
                    laboratory_party_id: Some("party-owner".to_string()),
                }),
            }),
            ACTOR,
        )),
        Err(MasterDataError::Invalid { ref field, .. }) if field == "calibration.laboratory_party_id"
    ));
}

// ---------------------------------------------------------------------------
// Carriers, calibration and stores
// ---------------------------------------------------------------------------

#[test]
fn carriers_and_calibration_state_are_master_data() {
    let md = MasterData::open_in_memory().expect("master data");
    seed(&md, 1_000);

    md.put(MasterDraft::new(
        "carrier-1",
        1_000,
        LifecycleStatus::Active,
        MasterAttributes::Carrier(CarrierAttributes {
            name: "Reefer Logistics".to_string(),
            carrier_code: "RLXU".to_string(),
            gln: Some(gln("400638133395")),
            mode: TransportMode::Road,
        }),
        ACTOR,
    ))
    .expect("carrier");
    let resolved = md.resolve(
        &EventRefs {
            carrier_id: Some("carrier-1".to_string()),
            ..EventRefs::default()
        },
        1_000,
    );
    assert_eq!(resolved.carrier.expect("carrier").id, "carrier-1");

    // dev-1 was calibrated at 1_000 for 86 400 s.
    assert_eq!(
        md.calibration_status("dev-1", 1_000).expect("status"),
        CalibrationStatus::Valid { due_est: 87_400 }
    );
    assert_eq!(
        md.calibration_status("dev-1", 87_400 - 8_000)
            .expect("status"),
        CalibrationStatus::DueSoon { due_est: 87_400 }
    );
    assert_eq!(
        md.calibration_status("dev-1", 87_400).expect("status"),
        CalibrationStatus::Expired { due_est: 87_400 }
    );
    assert!(!md
        .calibration_status("dev-1", 87_400)
        .expect("status")
        .is_usable());

    md.put(device_draft("dev-2", 1_000, None))
        .expect("device 2");
    assert_eq!(
        md.calibration_status("dev-2", 1_000).expect("status"),
        CalibrationStatus::NotRequired
    );
    assert!(matches!(
        md.calibration_status("dev-missing", 1_000),
        Err(MasterDataError::NotFound { .. })
    ));

    // An unresolved reference is reported, not silently ignored.
    let partial = md.resolve(
        &EventRefs {
            site_id: Some("site-1".to_string()),
            location_id: Some("loc-1".to_string()),
            trade_item_id: Some("item-missing".to_string()),
            party_id: Some("party-op".to_string()),
            ..EventRefs::default()
        },
        1_000,
    );
    assert!(!partial.complete());
    assert_eq!(partial.missing, vec!["trade_item:item-missing".to_string()]);
    assert!(matches!(
        partial.require_complete(),
        Err(MasterDataError::Unresolved { .. })
    ));
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

#[test]
fn query_and_exports_cover_epcis_and_reporting() {
    let md = MasterData::open_in_memory().expect("master data");
    seed(&md, 1_000);

    let all = md.query(&MasterQuery::default(), 1_000).expect("query");
    assert_eq!(all.len(), 8, "one version per seeded record");

    let sites = md
        .query(
            &MasterQuery {
                kinds: vec![EntityKind::Site, EntityKind::Location],
                site_id: Some("site-1".to_string()),
                status: Some(LifecycleStatus::Active),
                text: Some("dock".to_string()),
                limit: Some(1),
            },
            1_000,
        )
        .expect("filtered");
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].id, "site-1");

    // Canonical export: stable digest for the same instant, different once the
    // master data changes.
    let export = md
        .export_json(&MasterQuery::default(), 1_000)
        .expect("export json");
    let again = md
        .export_json(&MasterQuery::default(), 1_000)
        .expect("export json");
    assert_eq!(export.digest, again.digest);
    assert_eq!(export.entries.len(), 8);
    let json = export.to_json().expect("json");
    assert!(json.contains("\"schema\":\"TirBase/v1/MasterDataExport\""));

    // Reporting CSV has a header and one row per record.
    let csv = md
        .export_csv(
            &MasterQuery {
                kinds: vec![EntityKind::TradeItem],
                ..MasterQuery::default()
            },
            1_000,
        )
        .expect("csv");
    let mut lines = csv.lines();
    assert_eq!(
        lines.next().expect("header"),
        "kind,id,version,status,site_id,parent_id,name,gs1,uom,effective_from_est,\
         effective_to_est,digest"
    );
    let row = lines.next().expect("row");
    assert!(row.starts_with("trade_item,item-1,1,active,"), "{row}");
    assert!(row.contains(",Vaccine 25 kg,"), "{row}");
    assert!(row.contains(",kg,"), "{row}");
    assert_eq!(lines.count(), 0);

    // EPCIS vocabulary: the site becomes an SGLN BizLocation element, the party
    // gln is exported, and records without a GS1 id are counted, not invented.
    let document = md
        .export_epcis(EpcisVocabulary::BizLocation, 1_000, 1_500)
        .expect("epcis");
    assert_eq!(document.document_type, "Vocabulary");
    assert_eq!(document.vocabulary_type, "BizLocation");
    assert_eq!(document.creation_date, 1_500);
    let ids: Vec<&str> = document
        .vocabulary_element_list
        .iter()
        .map(|element| element.id.as_str())
        .collect();
    assert!(ids.contains(&"urn:epc:id:sgln:4006381333931.0"), "{ids:?}");
    assert!(document.skipped_without_gs1 >= 1, "zone has no SGLN");
    let json = document.to_json().expect("epcis json");
    assert!(json.contains("\"vocabularyType\": \"BizLocation\""));

    let read_points = md
        .export_epcis(EpcisVocabulary::ReadPoint, 1_000, 1_500)
        .expect("read points");
    assert_eq!(read_points.vocabulary_type, "ReadPoint");
    assert!(read_points
        .vocabulary_element_list
        .iter()
        .all(|element| element.id.contains("sgln")));

    // History survives: every record got exactly one audit row here.
    let kinds: BTreeSet<EntityKind> = all.iter().map(|version| version.kind).collect();
    for kind in kinds {
        for version in all.iter().filter(|version| version.kind == kind) {
            assert_eq!(
                md.history(kind, &version.id).expect("history").len(),
                1,
                "{kind:?} {}",
                version.id
            );
        }
    }
}
