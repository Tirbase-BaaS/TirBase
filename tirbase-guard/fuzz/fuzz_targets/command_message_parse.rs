#![no_main]

//! Fuzz target for CommandMessage untrusted parse paths (CLAIM-40.1, PV-6.6, PV-12.6).
//! Exercises JSON/CBOR decode of `tirbase_types::command::CommandMessage` and the
//! guard's canonical signing-bytes computation. No panic on arbitrary input.

use libfuzzer_sys::fuzz_target;
use tirbase_types::command::CommandMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(cmd) = serde_json::from_slice::<CommandMessage>(data) {
        let _ = serde_json::to_vec(&cmd);
        let _ = tirbase_guard::command::command_signing_bytes(&cmd);
    }
    if let Ok(cmd) = ciborium::de::from_reader::<CommandMessage, _>(data) {
        let _ = tirbase_guard::command::command_signing_bytes(&cmd);
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<CommandMessage>(s);
    }
});
