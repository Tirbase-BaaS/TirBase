# TriBase Verification Claims

This file records formally-verified or test-proven security and correctness claims.

| Claim ID   | Claim                                                                                                                                                                | Status | Test |
|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------|------|
| CLAIM-G1.4 | Revocation delta applied on a mesh node causes subsequent deltas from the revoked DID to be rejected at `apply_incoming_delta` | Proven | `revoked_author_mesh_delta_rejected_at_apply_incoming_delta` |
| CLAIM-G1.5 | `core_activate_saturate_mode` has a real production caller path wired through the init-time `SaturateModeStateMachine` configuration in `CoreHandle::init`; two real `CoreHandle` instances verify the full activation path; removing the root CA key wiring from `CoreHandle::init` causes the test to fail | Proven | `saturate_mode_wiring_two_core_handle_instances_activate_via_production_caller` |
