use super::super::ScanError;

pub(super) fn parse_utf8_trimmed(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub(super) fn parse_sdk_version_from_producers(
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
