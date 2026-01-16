use super::super::ScanError;
use super::container::parse_vtx_meta_json;
use super::signature::parse_signature_section;
use super::utils::{parse_sdk_version_from_producers, parse_utf8_trimmed};
use crate::report::SignatureInfo;
use wasmparser::{Parser as WasmParser, Payload};

pub(super) fn scan_custom_sections(
    component_bytes: &[u8],
    author: &mut Option<String>,
    sdk_version: &mut Option<String>,
    signature: &mut SignatureInfo,
) -> Result<(), ScanError> {
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
                        *sdk_version = parse_sdk_version_from_producers(c.data(), c.data_offset())?;
                    }
                }
                "vtx.meta" | "vtx-metadata" => {
                    if author.is_none() || sdk_version.is_none() || !signature.present {
                        let _ = parse_vtx_meta_json(c.data(), author, sdk_version, signature);
                    }
                }
                "vtx.author" => {
                    if author.is_none() {
                        *author = parse_utf8_trimmed(c.data());
                    }
                }
                "vtx.sdk" => {
                    if sdk_version.is_none() {
                        *sdk_version = parse_utf8_trimmed(c.data());
                    }
                }
                "vtx.signature" => {
                    if !signature.present {
                        *signature = parse_signature_section(c.data());
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok(())
}
