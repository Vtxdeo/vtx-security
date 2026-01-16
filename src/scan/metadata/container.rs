use super::super::ScanError;
use super::signature::parse_signature_object;
use crate::report::SignatureInfo;

pub(super) fn parse_vtx_container_metadata(
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
            parse_signature_object(sig, signature);
        }
    }

    Ok(())
}

pub(super) fn parse_vtx_meta_json(
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
            parse_signature_object(sig, signature);
        }
    }

    Ok(())
}
