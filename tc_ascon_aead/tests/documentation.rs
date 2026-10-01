//! Every public type and method, and every trait method an engine or
//! parameter container implements, documents its timing.

/// Declaration prefixes whose doc comments must state their timing.
const DECLARATIONS: &[&str] = &[
    "pub struct ",
    "pub fn ",
    "pub const fn ",
    "fn init(",
    "fn fmt(",
    "fn source(",
    "fn default(",
    "fn process_aad_bytes(",
    "fn process_bytes(",
    "fn do_final(",
    "fn mac(",
    "fn reset(",
    "fn update_output_len(",
    "fn output_len(",
    "fn underlying_cipher(",
    "fn key(",
    "fn nonce(",
    "fn mac_size(",
    "fn initial_aad(",
];

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        // Helpers inside test modules are not part of the contract.
        if line == "#[cfg(test)]" {
            break;
        }
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment);
            docs.push('\n');
            continue;
        }
        if line.starts_with("#[") || attribute_depth > 0 {
            attribute_depth += line.chars().filter(|&c| c == '[').count() as i32;
            attribute_depth -= line.chars().filter(|&c| c == ']').count() as i32;
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if DECLARATIONS.iter().any(|prefix| line.starts_with(prefix)) {
            checked += 1;
            let docs = docs.to_ascii_lowercase();
            if docs.contains("constant time") == docs.contains("variable time") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (checked, missing)
}

#[test]
fn the_scanner_requires_exactly_one_timing_classification_on_each_declaration() {
    let fixture = "\
/// Constant time.
pub struct Documented {}
pub struct Undocumented {}
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
/// Constant time and variable time.
fn init() {}
fn do_final() {}
/// Constant time when the cipher's is.
fn process_bytes() {}
fn reset() {}
impl Trait for Type {
    fn drop() {}
}
#[cfg(test)]
mod tests {
    fn mac() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 7);
    assert_eq!(
        missing,
        [
            "pub struct Undocumented {}",
            "fn init() {}",
            "fn do_final() {}",
            "fn reset() {}",
        ]
    );
}

#[test]
fn every_public_api_and_implemented_trait_method_has_an_unambiguous_timing_doc() {
    let mut report = Vec::new();
    for (name, source) in [
        ("aead128.rs", include_str!("../src/aead128.rs")),
        ("legacy.rs", include_str!("../src/legacy.rs")),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        if checked == 0 {
            report.push(format!("{name}: no declarations scanned"));
        }
        for line in missing {
            report.push(format!("{name}: {line}"));
        }
    }
    assert!(
        report.is_empty(),
        "missing timing docs:\n{}",
        report.join("\n")
    );
}
