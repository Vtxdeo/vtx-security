use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub target_path: String,
    pub vtx_sha256: String,
    pub vtx_format_version: u8,
    pub component_sha256: String,
    pub author: Option<String>,
    pub sdk_version: Option<String>,
    pub signature: SignatureInfo,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn has_at_least(&self, min: Severity) -> bool {
        self.findings.iter().any(|f| severity_ge(f.severity, min))
    }
}

fn severity_ge(a: Severity, b: Severity) -> bool {
    severity_rank(a) >= severity_rank(b)
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}
