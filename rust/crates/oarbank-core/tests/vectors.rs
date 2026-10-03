//! The SDK's shared vectors (spec/vectors/*.json), replayed against oarbank-core.

use std::path::PathBuf;

use oarbank_core::{canonical, portable};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vendor/oarbank-sdk/spec/vectors").join(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    serde_json::from_str(&text).unwrap()
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect()
}

#[test]
fn canonical_json_cases() {
    let v = vectors("canonical-json.json");
    let cases = v["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let want = c["canonical"].as_str().unwrap();
        assert_eq!(canonical::canonical_json(&c["input"]).unwrap(), want);
        // the text path: the input re-serialised and parsed with the integer guard
        let text = serde_json::to_string(&c["input"]).unwrap();
        assert_eq!(canonical::canonical_json_str(&text).unwrap(), want, "{text}");
        assert_eq!(hex::encode(Sha256::digest(want.as_bytes())), c["sha256"].as_str().unwrap());
    }
    // Canonical output is not always a fixed point: the float 1e16 prints as the integer literal 10000000000000000,
    // which a re-parse reads as an integer beyond 2^53 and refuses, in the SDK as here.
    assert_eq!(canonical::canonical_json_str("1e16").unwrap(), "10000000000000000");
    assert!(canonical::canonical_json_str("10000000000000000").is_err());
}

#[test]
fn canonical_json_refusals() {
    let v = vectors("canonical-json.json");
    for r in v["refused"].as_array().unwrap() {
        match &r["value"] {
            Value::String(s) => {
                let x: f64 = s.parse().unwrap(); // "NaN", "Infinity": Python floats
                assert!(canonical::float(x).is_err() && canonical::float(-x).is_err(), "{s}");
                assert!(canonical::canonical_json_str(s).is_err(), "{s}");
            }
            n => {
                assert!(canonical::canonical_json(n).is_err(), "{n}");
                assert!(canonical::canonical_json_str(&n.to_string()).is_err(), "{n}");
                assert!(canonical::canonical_json_str(&format!("-{n}")).is_err(), "-{n}");
            }
        }
    }
}

#[test]
fn job_key_cases_and_integral_floats_agree() {
    for c in vectors("job-key.json")["cases"].as_array().unwrap() {
        let got = canonical::job_key(
            c["module_id"].as_str().unwrap(),
            c["compat"].as_str().unwrap(),
            &c["key_inputs"],
            c["stage"].as_str(),
        )
        .unwrap();
        assert_eq!(got, c["job_key"].as_str().unwrap());
    }
    let a = canonical::job_key("dev.x.y", "c", &serde_json::json!({"n": 3}), None).unwrap();
    assert_eq!(a, canonical::job_key("dev.x.y", "c", &serde_json::json!({"n": 3.0}), None).unwrap());
}

#[test]
fn portable_path_cases() {
    let v = vectors("portable-path.json");
    for p in strs(&v["accept"]) {
        assert!(portable::is_portable_path(p, false), "{p}");
        assert!(portable::is_portable_path(p, true), "{p}");
    }
    for p in strs(&v["accept_with_dotfiles"]) {
        assert!(portable::is_portable_path(p, true), "{p}");
        assert!(!portable::is_portable_path(p, false), "{p}");
    }
    for p in strs(&v["reject"]) {
        assert!(!portable::is_portable_path(p, true), "{p:?}");
        assert!(!portable::is_portable_path(p, false), "{p:?}");
    }
    for pair in v["casefold_collisions"].as_array().unwrap() {
        let pair = strs(pair);
        assert_eq!(portable::casefold_collisions(&pair), vec![(pair[0].to_string(), pair[1].to_string())]);
    }
}

#[test]
fn platform_token_cases() {
    let v = vectors("platform-token.json");
    assert!(strs(&v["accept"]).into_iter().all(portable::is_platform_token));
    assert!(!strs(&v["reject"]).into_iter().any(portable::is_platform_token));
    assert_eq!(strs(&v["known"]), portable::KNOWN_PLATFORMS.to_vec());
    assert_eq!(portable::oci_platform("linux-amd64"), "linux/amd64");
    assert!(portable::is_platform_token(&portable::host_platform()));
}
