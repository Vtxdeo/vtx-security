use super::super::{ScanError, ScanOptions};
use super::analyze::process_module_payload;
use super::rules::finalize_module;
use super::state::ModuleRiskState;
use crate::report::Finding;
use wasmparser::{Encoding, Parser as WasmParser, Payload};

pub(crate) fn scan_component_wasm_risks(
    component_bytes: &[u8],
    options: &ScanOptions,
) -> Result<Vec<Finding>, ScanError> {
    let mut findings = Vec::new();
    let mut module_index = 0usize;
    let mut root_module: Option<ModuleRiskState> = None;

    for payload in WasmParser::new(0).parse_all(component_bytes) {
        let payload = payload.map_err(|e| ScanError::WasmParse(e.to_string()))?;
        match payload {
            Payload::Version { encoding, .. } => {
                if matches!(encoding, Encoding::Module) {
                    root_module = Some(ModuleRiskState {
                        module_index,
                        ..Default::default()
                    });
                }
            }
            Payload::ModuleSection { parser, .. } => {
                scan_module(
                    parser,
                    component_bytes,
                    module_index,
                    options,
                    &mut findings,
                )?;
                module_index = module_index.saturating_add(1);
            }
            Payload::ComponentSection { parser, .. } => {
                scan_component_section(
                    parser,
                    component_bytes,
                    options,
                    &mut findings,
                    &mut module_index,
                )?;
            }
            _ => {
                if let Some(state) = root_module.as_mut() {
                    process_module_payload(state, payload)?;
                }
            }
        }
    }

    if let Some(state) = root_module.take() {
        finalize_module(state, options, &mut findings);
    }

    Ok(findings)
}

fn scan_component_section(
    parser: WasmParser,
    bytes: &[u8],
    options: &ScanOptions,
    findings: &mut Vec<Finding>,
    module_index: &mut usize,
) -> Result<(), ScanError> {
    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| ScanError::WasmParse(e.to_string()))?;
        match payload {
            Payload::ModuleSection { parser, .. } => {
                scan_module(parser, bytes, *module_index, options, findings)?;
                *module_index = module_index.saturating_add(1);
            }
            Payload::ComponentSection { parser, .. } => {
                scan_component_section(parser, bytes, options, findings, module_index)?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn scan_module(
    parser: WasmParser,
    bytes: &[u8],
    module_index: usize,
    options: &ScanOptions,
    findings: &mut Vec<Finding>,
) -> Result<(), ScanError> {
    let mut state = ModuleRiskState {
        module_index,
        ..Default::default()
    };

    for payload in parser.parse_all(bytes) {
        let payload = payload.map_err(|e| ScanError::WasmParse(e.to_string()))?;
        process_module_payload(&mut state, payload)?;
    }

    finalize_module(state, options, findings);
    Ok(())
}
