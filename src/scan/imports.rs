use super::{ScanError, ScanOptions};
use crate::report::{Finding, Severity};
use std::collections::BTreeMap;
use wasmparser::{Parser as WasmParser, Payload};

pub(super) fn scan_component_imports(
    component_bytes: &[u8],
    options: &ScanOptions,
) -> Result<Vec<Finding>, ScanError> {
    let trusted_prefixes = [
        "wasi_snapshot_preview1",
        "wasi:",
        "vtx:",
        "vtx",
        "__wbindgen_",
    ];

    let mut imports: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for payload in WasmParser::new(0).parse_all(component_bytes) {
        let payload = payload.map_err(|e| ScanError::WasmParse(e.to_string()))?;
        if let Payload::ImportSection(reader) = payload {
            for import in reader {
                let import = import.map_err(|e| ScanError::WasmParse(e.to_string()))?;
                imports
                    .entry(import.module.to_string())
                    .or_default()
                    .push(import.name.to_string());
            }
        }
    }

    let mut unknown = Vec::new();
    for (module, names) in &imports {
        let trusted = trusted_prefixes.iter().any(|p| module.starts_with(p));
        if !trusted {
            unknown.push(serde_json::json!({ "module": module, "names": names }));
        }
    }

    let mut findings = Vec::new();
    if !unknown.is_empty() {
        let severity = if options.allow_unknown_imports {
            Severity::Medium
        } else {
            Severity::High
        };
        findings.push(Finding {
            id: "imports.unknown_namespace".to_string(),
            severity,
            message: "Found imports from unknown namespace(s); may indicate non-standard host functions or supply-chain risk".to_string(),
            evidence: Some(serde_json::json!({ "unknown": unknown })),
        });
    }

    Ok(findings)
}
