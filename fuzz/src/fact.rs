#![no_main]

use agent_env::Fact;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for line in text.lines().take(256) {
            let _ = serde_json::from_str::<Fact>(line);
        }
    }
});
