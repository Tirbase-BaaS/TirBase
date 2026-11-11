#![no_main]

//! Fuzz target for EnvelopeProfile untrusted parse paths (CLAIM-40.1, PV-6.6, PV-12.6).
//! Exercises serde/CBOR/JSON decode of `tirbase_types::envelope::EnvelopeProfile`
//! and the guard's canonical signing-bytes computation. No panic on arbitrary input.

use libfuzzer_sys::fuzz_target;
use tirbase_types::envelope::EnvelopeProfile;

fuzz_target!(|data: &[u8]| {
    // JSON wire form.
    if let Ok(profile) = serde_json::from_slice::<EnvelopeProfile>(data) {
        let _ = serde_json::to_vec(&profile);
        let _ = tirbase_guard::envelope::profile_signing_bytes(&profile);
    }
    // CBOR form (profile body/wire may be transported as CBOR).
    if let Ok(profile) = ciborium::de::from_reader::<EnvelopeProfile, _>(data) {
        let _ = tirbase_guard::envelope::profile_signing_bytes(&profile);
    }
    // Text form for UTF-8 JSON payloads.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<EnvelopeProfile>(s);
    }
});
