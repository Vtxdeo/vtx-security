mod contract;
mod imports;
mod metadata;
mod wasm_rules;

use crate::report::{Finding, Report, Severity};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

use contract::scan_component_contract;
use imports::scan_component_imports;
use metadata::extract_metadata;
use wasm_rules::scan_component_wasm_risks;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub require_contract_exports: bool,
    pub allow_unknown_imports: bool,
    pub max_initial_memory_pages: u64,
    pub max_memory_pages: u64,
    pub max_table_elements: u32,
    pub max_function_count: u32,
    pub max_data_segments: u32,
    pub max_data_bytes: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            require_contract_exports: true,
            allow_unknown_imports: true,
            max_initial_memory_pages: 512,
            max_memory_pages: 4096,
            max_table_elements: 100_000,
            max_function_count: 10_000,
            max_data_segments: 1_000,
            max_data_bytes: 64 * 1024 * 1024,
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
    let vtx_bytes = std::fs::read(path)
        .map_err(|e| ScanError::ReadFile(format!("{}: {}", path.display(), e)))?;
    let vtx_sha256 = sha256_hex(&vtx_bytes);

    let decoded = vtx_format::decode_with_metadata(&vtx_bytes)
        .map_err(|e| ScanError::InvalidVtx(e.to_string()))?;
    let vtx_version = decoded.version;
    let vtx_meta = decoded.metadata;
    let component_bytes = decoded.component;
    let component_sha256 = sha256_hex(component_bytes);

    let mut findings = Vec::new();
    let (author, sdk_version, signature, meta_findings) =
        extract_metadata(vtx_meta, component_bytes)?;
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
    findings.extend(scan_component_wasm_risks(component_bytes, options)?);

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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
