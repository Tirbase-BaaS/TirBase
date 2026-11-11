//! Table-driven authorization-matrix tests (PV-3.3, CLAIM-56.1, P19).
//!
//! Auto-generates a negative test for every `—` cell in
//! `tirbase_guard::auth_matrix::AUTHORIZATION_MATRIX` and verifies wrong-role
//! credentials are rejected with a typed authorization error. Also provides a
//! proptest (P19) covering all denied cells.

use proptest::prelude::*;
use tirbase_guard::auth_matrix::{
    check_role_authorization, denied_cells, role_index, AUTHORIZATION_MATRIX, MATRIX_ROLES,
    MatrixAuthorizationError, MatrixCell,
};

#[test]
fn authorization_matrix_has_expected_shape() {
    assert_eq!(AUTHORIZATION_MATRIX.len(), 19);
    for row in AUTHORIZATION_MATRIX {
        assert_eq!(row.cells.len(), 6);
    }
}

#[test]
fn denied_cells_count_matches_matrix() {
    let mut expected = 0usize;
    for row in AUTHORIZATION_MATRIX {
        for (idx, role) in MATRIX_ROLES.iter().enumerate() {
            if matches!(row.cells[idx], MatrixCell::Denied) {
                expected += 1;
                let _ = role_index(*role);
            }
        }
    }
    assert_eq!(denied_cells().count(), expected);
    assert!(expected > 0);
}

#[test]
fn auto_generated_negative_tests_for_every_denied_cell() {
    // Table-driven: every `—` cell must reject with a typed authorization error.
    let mut failures: Vec<String> = Vec::new();
    for row in AUTHORIZATION_MATRIX {
        for (idx, role) in MATRIX_ROLES.iter().enumerate() {
            if matches!(row.cells[idx], MatrixCell::Denied) {
                match check_role_authorization(row.operation, *role) {
                    Ok(()) => failures.push(format!(
                        "DENIED cell accepted: op='{}' role={}",
                        row.operation.as_str(),
                        role.as_str()
                    )),
                    Err(MatrixAuthorizationError {
                        operation,
                        attempted_role,
                    }) => {
                        if operation != row.operation || attempted_role != *role {
                            failures.push(format!(
                                "typed error mismatch for op='{}' role={}",
                                row.operation.as_str(),
                                role.as_str()
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "authorization matrix violations ({}):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn allowed_cells_are_not_denied() {
    for row in AUTHORIZATION_MATRIX {
        for (idx, role) in MATRIX_ROLES.iter().enumerate() {
            if matches!(row.cells[idx], MatrixCell::Allowed) {
                assert!(
                    check_role_authorization(row.operation, *role).is_ok(),
                    "allowed cell rejected: op='{}' role={}",
                    row.operation.as_str(),
                    role.as_str()
                );
            }
        }
    }
}

fn denied_pairs() -> Vec<(usize, usize)> {
    // (operation index, role index) for denied cells
    let mut v = Vec::new();
    for (op_i, row) in AUTHORIZATION_MATRIX.iter().enumerate() {
        for (role_i, cell) in row.cells.iter().enumerate() {
            if matches!(cell, MatrixCell::Denied) {
                v.push((op_i, role_i));
            }
        }
    }
    v
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// P19 (PV-3.3): for every `—` cell, a credential of the wrong role is
    /// rejected with a typed authorization error.
    #[test]
    fn p19_every_denied_cell_rejects_wrong_role_with_typed_error(
        pick in 0usize..(19usize * 6usize),
        _noise in 0u64..10_000u64,
    ) {
        let pairs = denied_pairs();
        prop_assert!(!pairs.is_empty());
        // Deterministically cover all denied cells across cases by cycling picks,
        // while also exercising property-based selection.
        let idx = pick % pairs.len();
        let (op_i, role_i) = pairs[idx];
        let op = AUTHORIZATION_MATRIX[op_i].operation;
        let role = MATRIX_ROLES[role_i];
        let res = check_role_authorization(op, role);
        prop_assert!(res.is_err(), "denied cell accepted: {:?} {:?}", op, role);
        let err = res.unwrap_err();
        prop_assert_eq!(err.operation, op);
        prop_assert_eq!(err.attempted_role, role);
    }

    /// Exhaustive P19 sweep over all denied cells (property-run harness).
    #[test]
    fn p19_all_denied_cells_rejected(_seed in 0u64..64u64) {
        for (op, role) in denied_cells() {
            let err = check_role_authorization(op, role)
                .expect_err("denied cell must be rejected");
            prop_assert_eq!(err.operation, op);
            prop_assert_eq!(err.attempted_role, role);
        }
    }
}
