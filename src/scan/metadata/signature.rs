use crate::report::SignatureInfo;

pub(super) fn parse_signature_object(value: &serde_json::Value, signature: &mut SignatureInfo) {
    if let Some(obj) = value.as_object() {
        signature.present = true;
        signature.scheme = obj
            .get("scheme")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        signature.signer = obj
            .get("signer")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        signature.value = obj
            .get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        signature.verified = obj.get("verified").and_then(|v| v.as_bool());
    }
}

pub(super) fn parse_signature_section(bytes: &[u8]) -> SignatureInfo {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(obj) = value.as_object() {
                return SignatureInfo {
                    present: true,
                    scheme: obj
                        .get("scheme")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    signer: obj
                        .get("signer")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    value: obj
                        .get("value")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
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
