// SPDX-License-Identifier: AGPL-3.0-only

//! Property tests for POS-04 effective-window maths, overlap rejection and
//! rollback preservation.

use std::collections::BTreeMap;

use proptest::prelude::*;
use tirbase_pos::{
    CatalogItemId, CatalogVersion, CatalogVersionId, Currency, EffectiveWindow, EmployeeId, Money,
    PosError, PriceBookVersion, PriceBookVersionId, Timestamp, VersionAuditEventKind, VersionRef,
    VersionStore,
};

fn usd() -> Currency {
    Currency::from_code("USD").unwrap()
}

fn ts(value: i64) -> Timestamp {
    Timestamp::from_millis(value)
}

fn employee() -> EmployeeId {
    EmployeeId::new("emp-1").unwrap()
}

fn window(from: i64, until: i64) -> EffectiveWindow {
    EffectiveWindow::new(ts(from), Some(ts(until))).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn effective_windows_contain_boundaries_and_overlap_symmetrically(
        a_start in -100_i64..100,
        a_len in 1_i64..100,
        b_start in -100_i64..100,
        b_len in 1_i64..100,
    ) {
        let a = window(a_start, a_start + a_len);
        let b = window(b_start, b_start + b_len);

        prop_assert!(a.contains(ts(a_start)));
        prop_assert!(!a.contains(ts(a_start + a_len)));
        prop_assert_eq!(a.overlaps(b), b.overlaps(a));
        prop_assert_eq!(
            a.overlaps(b),
            a_start < b_start + b_len && b_start < a_start + a_len
        );
    }

    #[test]
    fn catalog_publication_accepts_exactly_non_overlapping_windows(
        a_start in -100_i64..100,
        a_len in 1_i64..100,
        b_start in -100_i64..100,
        b_len in 1_i64..100,
    ) {
        let a_window = window(a_start, a_start + a_len);
        let b_window = window(b_start, b_start + b_len);
        let mut store = VersionStore::new();
        let a = CatalogVersion::new(
            CatalogVersionId::new("catalog-a").unwrap(),
            a_window,
            vec![],
            vec![],
        )
        .unwrap();
        let b = CatalogVersion::new(
            CatalogVersionId::new("catalog-b").unwrap(),
            b_window,
            vec![],
            vec![],
        )
        .unwrap();
        store.publish_catalog(a, employee(), ts(0)).unwrap();

        let expected_overlap = a_window.overlaps(b_window);
        let result = store.publish_catalog(b, employee(), ts(0));
        if expected_overlap {
            let is_overlap = matches!(
                result,
                Err(PosError::OverlappingEffectiveWindow { .. })
            );
            prop_assert!(is_overlap);
            prop_assert_eq!(store.audit_events().len(), 1);
        } else {
            prop_assert!(result.is_ok());
            prop_assert_eq!(store.audit_events().len(), 2);
        }
    }

    #[test]
    fn rollback_reissues_the_old_price_and_records_it(price in 1_i64..10_000) {
        let mut store = VersionStore::new();
        let old = PriceBookVersion::new(
            PriceBookVersionId::new("price-old").unwrap(),
            window(0, 10),
            usd(),
            BTreeMap::from([(CatalogItemId::new("coffee").unwrap(), Money::new(usd(), price))]),
            BTreeMap::new(),
        )
        .unwrap();
        store.publish_price_book(old, employee(), ts(0)).unwrap();
        store
            .rollback_price_book(
                PriceBookVersionId::new("price-rollback").unwrap(),
                &PriceBookVersionId::new("price-old").unwrap(),
                window(10, 20),
                "revert",
                employee(),
                ts(10),
            )
            .unwrap();

        let effective = store.effective_price_book(usd(), ts(10)).unwrap();
        prop_assert_eq!(
            effective.item_price(&CatalogItemId::new("coffee").unwrap()),
            Some(Money::new(usd(), price))
        );
        prop_assert_eq!(
            store.audit_events().last().unwrap().kind.clone(),
            VersionAuditEventKind::RolledBack {
                replacement: VersionRef::PriceBook(
                    PriceBookVersionId::new("price-rollback").unwrap()
                ),
                reverted_to: VersionRef::PriceBook(
                    PriceBookVersionId::new("price-old").unwrap()
                ),
                reason: "revert".into(),
            }
        );
    }
}
