# TriBase Verification Claims

This file records formally-verified or test-proven security and correctness claims.

| Claim ID   | Claim                                                                                                                                                                | Status | Test |
|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------|------|
| CLAIM-G1.4 | Revocation delta applied on a mesh node causes subsequent deltas from the revoked DID to be rejected at `apply_incoming_delta` | Proven | `revoked_author_mesh_delta_rejected_at_apply_incoming_delta` |
