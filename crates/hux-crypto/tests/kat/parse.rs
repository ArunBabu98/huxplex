//! Reader for the `.kat` fixture format (G1 task C10).
//!
//! Shared by the integration tests and by `src/kat_tests.rs`, which includes it with `#[path]`
//! because the signature vectors can only be reproduced through the crate's test-only signing
//! entry point. One parser, so the two cannot disagree about what a fixture says.
//!
//! The format is deliberately trivial — `[kind]` headers, `name = hex` fields, indented
//! continuation lines, `#` comments — so a reimplementation in any language can read the vectors
//! without a dependency.

#![allow(dead_code)]

use std::collections::BTreeMap;

pub struct Vector {
    pub kind: String,
    fields: BTreeMap<String, Vec<u8>>,
}

impl Vector {
    pub fn get(&self, name: &str) -> &[u8] {
        self.fields
            .get(name)
            .unwrap_or_else(|| panic!("[{}] vector has no `{name}` field", self.kind))
    }

    pub fn array<const N: usize>(&self, name: &str) -> [u8; N] {
        let bytes = self.get(name);
        bytes.try_into().unwrap_or_else(|_| {
            panic!(
                "[{}] `{name}` is {} bytes, expected {N}",
                self.kind,
                bytes.len()
            )
        })
    }
}

/// Parses a fixture file. Panics on malformed input — a fixture that cannot be read is a broken
/// test, and must fail loudly rather than yield zero vectors and pass.
pub fn parse(text: &str) -> Vec<Vector> {
    let mut vectors = Vec::new();
    let mut current: Option<(String, BTreeMap<String, String>)> = None;
    let mut field: Option<String> = None;

    let mut finish = |current: &mut Option<(String, BTreeMap<String, String>)>| {
        if let Some((kind, raw)) = current.take() {
            let fields = raw
                .into_iter()
                .map(|(k, v)| {
                    let bytes = hex::decode(&v)
                        .unwrap_or_else(|e| panic!("[{kind}] `{k}` is not hex: {e}"));
                    (k, bytes)
                })
                .collect();
            vectors.push(Vector { kind, fields });
        }
    };

    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(kind) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            finish(&mut current);
            current = Some((kind.to_string(), BTreeMap::new()));
            field = None;
        } else if line.starts_with(' ') {
            let (_, raw) = current
                .as_mut()
                .expect("continuation line before any [kind]");
            let name = field.as_ref().expect("continuation line before any field");
            raw.get_mut(name).unwrap().push_str(line.trim());
        } else {
            let (name, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("not a `name = hex` line: {line}"));
            let (_, raw) = current.as_mut().expect("field before any [kind]");
            let name = name.trim().to_string();
            assert!(
                raw.insert(name.clone(), value.trim().to_string()).is_none(),
                "duplicate field `{name}`"
            );
            field = Some(name);
        }
    }
    finish(&mut current);

    assert!(!vectors.is_empty(), "fixture contains no vectors");
    vectors
}

pub fn of_kind<'a>(vectors: &'a [Vector], kind: &'a str) -> impl Iterator<Item = &'a Vector> {
    let mut found = vectors.iter().filter(move |v| v.kind == kind).peekable();
    assert!(found.peek().is_some(), "fixture has no [{kind}] vectors");
    found
}
