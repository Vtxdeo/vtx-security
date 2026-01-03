use crate::report::{Finding, Report, Severity, SignatureInfo};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use thiserror::Error;
use wasmparser::{Parser as WasmParser, Payload};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub require_contract_exports: bool,
    pub allow_unknown_imports: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            require_contract_exports: true,
            allow_unknown_imports: true,
        }
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("failed to read file: {0}")]
    ReadFile(String),
    #[error("invalid vtx package: {0}")]
    InvalidVtx(String),
    #[error("wasm parse error: {0}")]
    WasmParse(String),
}

pub fn scan_vtx_file(path: &Path, options: &ScanOptions) -> Result<Report, ScanError> {
    let vtx_bytes =
        std::fs::read(path).map_err(|e| ScanError::ReadFile(format!("{}: {}", path.display(), e)))?;
    let vtx_sha256 = sha256_hex(&vtx_bytes);

    let (vtx_version, vtx_meta, component_bytes) = vtx_format::decode_with_metadata(&vtx_bytes)
        .map_err(|e| ScanError::InvalidVtx(e.to_string()))?;
    let component_sha256 = sha256_hex(component_bytes);

    let mut findings = Vec::new();
    let (author, sdk_version, signature, meta_findings) = extract_metadata(vtx_meta, component_bytes)?;
    findings.extend(meta_findings);
    if author.is_none() {
        findings.push(Finding {
            id: "meta.missing_author".to_string(),
            severity: Severity::Medium,
            message: "Author metadata not found (report.author is null)".to_string(),
            evidence: None,
        });
    }
    if sdk_version.is_none() {
        findings.push(Finding {
            id: "meta.missing_sdk_version".to_string(),
            severity: Severity::Medium,
            message: "SDK version not found (report.sdk_version is null)".to_string(),
            evidence: None,
        });
    }
    if !signature.present {
        findings.push(Finding {
            id: "meta.missing_signature".to_string(),
            severity: Severity::High,
            message: "Signature not found (report.signature.present=false)".to_string(),
            evidence: None,
        });
    }
    findings.extend(scan_component_contract(component_bytes, options)?);
    findings.extend(scan_component_imports(component_bytes, options)?);

    Ok(Report {
        target_path: path.display().to_string(),
        vtx_sha256,
        vtx_format_version: vtx_version,
        component_sha256,
        author,
        sdk_version,
        signature,
        findings,
    })
}

fn scan_component_contract(
    component_bytes: &[u8],
    options: &ScanOptions,
) -> Result<Vec<Finding>, ScanError> {
    let mut found_handle = false;
    let mut found_manifest = false;
    let mut exports = Vec::<String>::new();

    for payload in WasmParser::new(0).parse_all(component_bytes) {
        let payload = payload.map_err(|e| ScanError::WasmParse(e.to_string()))?;
        if let Payload::ComponentExportSection(reader) = payload {
            for export in reader {
                let export = export.map_err(|e| ScanError::WasmParse(e.to_string()))?;
                let name = export.name.0;
                exports.push(name.to_string());

                match name {
                    "handle" | "vtx:api/plugin/handle" | "vtx:api/plugin#handle" => {
                        found_handle = true
                    }
                    "get-manifest"
                    | "vtx:api/plugin/get-manifest"
                    | "vtx:api/plugin#get-manifest" => found_manifest = true,
                    _ => {}
                }
            }
        }
    }

    let mut findings = Vec::new();
    if options.require_contract_exports && !found_handle {
        findings.push(Finding {
            id: "contract.missing_handle".to_string(),
            severity: Severity::High,
            message: "Missing required export: handle".to_string(),
            evidence: Some(serde_json::json!({ "exports": exports })),
        });
    }
    if options.require_contract_exports && !found_manifest {
        findings.push(Finding {
            id: "contract.missing_get_manifest".to_string(),
            severity: Severity::High,
            message: "Missing required export: get-manifest".to_string(),
            evidence: Some(serde_json::json!({ "exports": exports })),
        });
    }

    Ok(findings)
}

fn scan_component_imports(
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

fn extract_metadata(
    vtx_meta: Option<&[u8]>,
    component_bytes: &[u8],
) -> Result<(Option<String>, Option<String>, SignatureInfo, Vec<Finding>), ScanError> {
    let mut author: Option<String> = None;
    let mut sdk_version: Option<String> = None;
    let mut signature = SignatureInfo {
        present: false,
        scheme: None,
        signer: None,
        value: None,
        verified: None,
    };

    let mut findings = Vec::new();
    if let Some(meta) = vtx_meta {
        if let Err(e) = parse_vtx_container_metadata(meta, &mut author, &mut sdk_version, &mut signature) {
            findings.push(Finding {
                id: "meta.vtx_container_invalid".to_string(),
                severity: Severity::Medium,
                message: format!("Invalid vtx v2 metadata JSON: {}", e),
                evidence: None,
            });
        }
    }

    let mut depth = 0usize;
    for payload in WasmParser::new(0).parse_all(component_bytes) {
        let payload = payload.map_err(|e| ScanError::WasmParse(e.to_string()))?;
        match payload {
            Payload::ModuleSection { .. } | Payload::ComponentSection { .. } => depth += 1,
            Payload::End { .. } => {
                depth = depth.saturating_sub(1);
            }
            Payload::CustomSection(c) if depth == 0 => match c.name() {
                "producers" => {
                    if sdk_version.is_none() {
                        sdk_version = parse_sdk_version_from_producers(c.data(), c.data_offset())?;
                    }
                }
                "vtx.meta" | "vtx-metadata" => {
                    if author.is_none() || sdk_version.is_none() || !signature.present {
                        let _ = parse_vtx_meta_json(c.data(), &mut author, &mut sdk_version, &mut signature);
                    }
                }
                "vtx.author" => {
                    if author.is_none() {
                        author = parse_utf8_trimmed(c.data());
                    }
                }
                "vtx.sdk" => {
                    if sdk_version.is_none() {
                        sdk_version = parse_utf8_trimmed(c.data());
                    }
                }
                "vtx.signature" => {
                    if !signature.present {
                        signature = parse_signature_section(c.data());
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok((author, sdk_version, signature, findings))
}

fn parse_vtx_container_metadata(
    bytes: &[u8],
    author: &mut Option<String>,
    sdk_version: &mut Option<String>,
    signature: &mut SignatureInfo,
) -> Result<(), ScanError> {
    let text = std::str::from_utf8(bytes).map_err(|e| ScanError::WasmParse(e.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| ScanError::WasmParse(e.to_string()))?;

    if author.is_none() {
        *author = value
            .get("author")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    if sdk_version.is_none() {
        *sdk_version = value
            .get("sdk_version")
            .or_else(|| value.get("sdkVersion"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    if !signature.present {
        if let Some(sig) = value.get("signature") {
            if let Some(obj) = sig.as_object() {
                signature.present = true;
                signature.scheme = obj.get("scheme").and_then(|v| v.as_str()).map(|s| s.to_string());
                signature.signer = obj.get("signer").and_then(|v| v.as_str()).map(|s| s.to_string());
                signature.value = obj.get("value").and_then(|v| v.as_str()).map(|s| s.to_string());
                signature.verified = obj.get("verified").and_then(|v| v.as_bool());
            }
        }
    }

    Ok(())
}

fn parse_sdk_version_from_producers(
    bytes: &[u8],
    offset: usize,
) -> Result<Option<String>, ScanError> {
    let section = wasmparser::ProducersSectionReader::new(bytes, offset)
        .map_err(|e| ScanError::WasmParse(e.to_string()))?;

    let mut candidates = Vec::<(String, String)>::new();
    for field in section {
        let field = field.map_err(|e| ScanError::WasmParse(e.to_string()))?;
        if field.name == "sdk" {
            for value in field.values {
                let value = value.map_err(|e| ScanError::WasmParse(e.to_string()))?;
                candidates.push((value.name.to_string(), value.version.to_string()));
            }
        }
    }

    if candidates.is_empty() {
        return Ok(None);
    }

    if let Some((_, ver)) = candidates
        .iter()
        .find(|(name, _)| name.contains("vtx") || name.contains("vtx-sdk"))
    {
        return Ok(Some(ver.clone()));
    }

    Ok(Some(candidates[0].1.clone()))
}

fn parse_vtx_meta_json(
    bytes: &[u8],
    author: &mut Option<String>,
    sdk_version: &mut Option<String>,
    signature: &mut SignatureInfo,
) -> Result<(), ScanError> {
    let text = std::str::from_utf8(bytes).map_err(|e| ScanError::WasmParse(e.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| ScanError::WasmParse(e.to_string()))?;

    if author.is_none() {
        *author = value
            .get("author")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    if sdk_version.is_none() {
        *sdk_version = value
            .get("sdk_version")
            .or_else(|| value.get("sdkVersion"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }

    if !signature.present {
        if let Some(sig) = value.get("signature") {
            if let Some(obj) = sig.as_object() {
                signature.present = true;
                signature.scheme = obj.get("scheme").and_then(|v| v.as_str()).map(|s| s.to_string());
                signature.signer = obj.get("signer").and_then(|v| v.as_str()).map(|s| s.to_string());
                signature.value = obj.get("value").and_then(|v| v.as_str()).map(|s| s.to_string());
                signature.verified = obj.get("verified").and_then(|v| v.as_bool());
            }
        }
    }

    Ok(())
}

fn parse_signature_section(bytes: &[u8]) -> SignatureInfo {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(obj) = value.as_object() {
                return SignatureInfo {
                    present: true,
                    scheme: obj.get("scheme").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    signer: obj.get("signer").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    value: obj.get("value").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    verified: obj.get("verified").and_then(|v| v.as_bool()),
                };
            }
        }
    }

    SignatureInfo {
        present: true,
        scheme: Some("opaque".to_string()),
        signer: None,
        value: Some(hex::encode(bytes)),
        verified: None,
    }
}

fn parse_utf8_trimmed(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
