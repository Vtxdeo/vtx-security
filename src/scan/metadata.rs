mod container;
mod custom_sections;
mod signature;
mod utils;

use super::ScanError;
use crate::report::{Finding, Severity, SignatureInfo};

use container::parse_vtx_container_metadata;
use custom_sections::scan_custom_sections;

type MetadataResult = (Option<String>, Option<String>, SignatureInfo, Vec<Finding>);

pub(super) fn extract_metadata(
    vtx_meta: Option<&[u8]>,
    component_bytes: &[u8],
) -> Result<MetadataResult, ScanError> {
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
        if let Err(e) =
            parse_vtx_container_metadata(meta, &mut author, &mut sdk_version, &mut signature)
        {
            findings.push(Finding {
                id: "meta.vtx_container_invalid".to_string(),
                severity: Severity::Medium,
                message: format!("Invalid vtx v2 metadata JSON: {}", e),
                evidence: None,
            });
        }
    }

    scan_custom_sections(
        component_bytes,
        &mut author,
        &mut sdk_version,
        &mut signature,
    )?;

    Ok((author, sdk_version, signature, findings))
}
