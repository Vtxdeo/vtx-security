use super::super::ScanOptions;
use super::state::ModuleRiskState;
use crate::report::{Finding, Severity};
use std::collections::BTreeMap;

pub(super) fn finalize_module(
    state: ModuleRiskState,
    options: &ScanOptions,
    findings: &mut Vec<Finding>,
) {
    let module_index = state.module_index;

    for (idx, mem) in state.memories.iter().enumerate() {
        let source = if mem.imported { "import" } else { "defined" };
        if mem.ty.shared {
            findings.push(Finding {
                id: "wasm.memory.shared".to_string(),
                severity: Severity::High,
                message: "Shared memory is enabled; risk of data races or cross-thread abuse"
                    .to_string(),
                evidence: Some(serde_json::json!({
                    "module_index": module_index,
                    "memory_index": idx,
                    "source": source,
                })),
            });
        }
        if mem.ty.memory64 {
            findings.push(Finding {
                id: "wasm.memory.memory64".to_string(),
                severity: Severity::High,
                message: "memory64 is enabled; large address space can increase attack surface"
                    .to_string(),
                evidence: Some(serde_json::json!({
                    "module_index": module_index,
                    "memory_index": idx,
                    "source": source,
                })),
            });
        }
        if mem.ty.maximum.is_none() {
            findings.push(Finding {
                id: "wasm.memory.max_missing".to_string(),
                severity: Severity::Medium,
                message: "Memory maximum is not declared".to_string(),
                evidence: Some(serde_json::json!({
                    "module_index": module_index,
                    "memory_index": idx,
                    "source": source,
                    "initial_pages": mem.ty.initial,
                })),
            });
        }
        if mem.ty.initial > options.max_initial_memory_pages {
            findings.push(Finding {
                id: "wasm.memory.initial_too_large".to_string(),
                severity: Severity::Medium,
                message: "Initial memory size exceeds configured threshold".to_string(),
                evidence: Some(serde_json::json!({
                    "module_index": module_index,
                    "memory_index": idx,
                    "source": source,
                    "initial_pages": mem.ty.initial,
                    "max_allowed": options.max_initial_memory_pages,
                })),
            });
        }
        if let Some(max) = mem.ty.maximum {
            if max > options.max_memory_pages {
                findings.push(Finding {
                    id: "wasm.memory.max_too_large".to_string(),
                    severity: Severity::High,
                    message: "Maximum memory size exceeds configured threshold".to_string(),
                    evidence: Some(serde_json::json!({
                        "module_index": module_index,
                        "memory_index": idx,
                        "source": source,
                        "max_pages": max,
                        "max_allowed": options.max_memory_pages,
                    })),
                });
            }
        }
    }

    for (idx, table) in state.tables.iter().enumerate() {
        let source = if table.imported { "import" } else { "defined" };
        if table.ty.maximum.is_none() {
            findings.push(Finding {
                id: "wasm.table.max_missing".to_string(),
                severity: Severity::Medium,
                message: "Table maximum is not declared".to_string(),
                evidence: Some(serde_json::json!({
                    "module_index": module_index,
                    "table_index": idx,
                    "source": source,
                    "initial_elements": table.ty.initial,
                })),
            });
        }
        if let Some(max) = table.ty.maximum {
            if max > u64::from(options.max_table_elements) {
                findings.push(Finding {
                    id: "wasm.table.max_too_large".to_string(),
                    severity: Severity::Medium,
                    message: "Table maximum exceeds configured threshold".to_string(),
                    evidence: Some(serde_json::json!({
                        "module_index": module_index,
                        "table_index": idx,
                        "source": source,
                        "max_elements": max,
                        "max_allowed": options.max_table_elements,
                    })),
                });
            }
        }
    }

    let function_total = state.function_imports.saturating_add(state.function_defs);
    if function_total > options.max_function_count {
        findings.push(Finding {
            id: "wasm.function.count_high".to_string(),
            severity: Severity::Medium,
            message: "Function count exceeds configured threshold".to_string(),
            evidence: Some(serde_json::json!({
                "module_index": module_index,
                "function_imports": state.function_imports,
                "function_defs": state.function_defs,
                "max_allowed": options.max_function_count,
            })),
        });
    }

    if state.data_segments > options.max_data_segments {
        findings.push(Finding {
            id: "wasm.data.segment_count_high".to_string(),
            severity: Severity::Medium,
            message: "Data segment count exceeds configured threshold".to_string(),
            evidence: Some(serde_json::json!({
                "module_index": module_index,
                "data_segments": state.data_segments,
                "max_allowed": options.max_data_segments,
            })),
        });
    }
    if state.data_bytes > options.max_data_bytes {
        findings.push(Finding {
            id: "wasm.data.total_bytes_high".to_string(),
            severity: Severity::High,
            message: "Total data segment bytes exceed configured threshold".to_string(),
            evidence: Some(serde_json::json!({
                "module_index": module_index,
                "data_bytes": state.data_bytes,
                "max_allowed": options.max_data_bytes,
            })),
        });
    }

    if state.has_call_indirect {
        findings.push(Finding {
            id: "wasm.op.call_indirect".to_string(),
            severity: Severity::Medium,
            message: "Uses call_indirect; dynamic dispatch can increase attack surface".to_string(),
            evidence: Some(serde_json::json!({ "module_index": module_index })),
        });
    }
    if state.has_memory_grow {
        findings.push(Finding {
            id: "wasm.op.memory_grow".to_string(),
            severity: Severity::Medium,
            message: "Uses memory.grow; runtime memory expansion may amplify DoS risk".to_string(),
            evidence: Some(serde_json::json!({ "module_index": module_index })),
        });
    }
    if state.has_bulk_memory {
        findings.push(Finding {
            id: "wasm.op.bulk_memory".to_string(),
            severity: Severity::Low,
            message: "Uses bulk memory or table operations".to_string(),
            evidence: Some(serde_json::json!({ "module_index": module_index })),
        });
    }

    emit_import_finding(
        findings,
        "wasm.imports.filesystem",
        Severity::High,
        "Uses WASI filesystem imports",
        module_index,
        &state.imports_fs,
    );
    emit_import_finding(
        findings,
        "wasm.imports.network",
        Severity::High,
        "Uses WASI network imports",
        module_index,
        &state.imports_net,
    );
    emit_import_finding(
        findings,
        "wasm.imports.process",
        Severity::Medium,
        "Uses WASI process control imports",
        module_index,
        &state.imports_process,
    );
    emit_import_finding(
        findings,
        "wasm.imports.environment",
        Severity::Medium,
        "Uses WASI environment or args imports",
        module_index,
        &state.imports_env,
    );
    emit_import_finding(
        findings,
        "wasm.imports.time",
        Severity::Low,
        "Uses WASI time imports",
        module_index,
        &state.imports_time,
    );
    emit_import_finding(
        findings,
        "wasm.imports.random",
        Severity::Low,
        "Uses WASI random imports",
        module_index,
        &state.imports_random,
    );
}

fn emit_import_finding(
    findings: &mut Vec<Finding>,
    id: &str,
    severity: Severity,
    message: &str,
    module_index: usize,
    imports: &BTreeMap<String, Vec<String>>,
) {
    if imports.is_empty() {
        return;
    }

    findings.push(Finding {
        id: id.to_string(),
        severity,
        message: message.to_string(),
        evidence: Some(serde_json::json!({
            "module_index": module_index,
            "imports": imports,
        })),
    });
}
