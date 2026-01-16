use super::{ScanError, ScanOptions};
use crate::report::{Finding, Severity};
use wasmparser::{Parser as WasmParser, Payload};

pub(super) fn scan_component_contract(
    component_bytes: &[u8],
    options: &ScanOptions,
) -> Result<Vec<Finding>, ScanError> {
    let mut found_handle = false;
    let mut found_manifest = false;
    let mut found_capabilities = false;
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
                    "get-capabilities"
                    | "vtx:api/plugin/get-capabilities"
                    | "vtx:api/plugin#get-capabilities" => found_capabilities = true,
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
    if options.require_contract_exports && !found_capabilities {
        findings.push(Finding {
            id: "contract.missing_get_capabilities".to_string(),
            severity: Severity::High,
            message: "Missing required export: get-capabilities".to_string(),
            evidence: Some(serde_json::json!({ "exports": exports })),
        });
    }

    Ok(findings)
}
