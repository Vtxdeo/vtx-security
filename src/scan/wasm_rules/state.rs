use std::collections::BTreeMap;
use wasmparser::{MemoryType, TableType};

#[derive(Default)]
pub(super) struct ModuleRiskState {
    pub(super) module_index: usize,
    pub(super) memories: Vec<MemoryRecord>,
    pub(super) tables: Vec<TableRecord>,
    pub(super) function_imports: u32,
    pub(super) function_defs: u32,
    pub(super) data_segments: u32,
    pub(super) data_bytes: u64,
    pub(super) has_call_indirect: bool,
    pub(super) has_memory_grow: bool,
    pub(super) has_bulk_memory: bool,
    pub(super) imports_fs: BTreeMap<String, Vec<String>>,
    pub(super) imports_net: BTreeMap<String, Vec<String>>,
    pub(super) imports_process: BTreeMap<String, Vec<String>>,
    pub(super) imports_env: BTreeMap<String, Vec<String>>,
    pub(super) imports_time: BTreeMap<String, Vec<String>>,
    pub(super) imports_random: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Copy)]
pub(super) struct MemoryRecord {
    pub(super) imported: bool,
    pub(super) ty: MemoryType,
}

#[derive(Clone, Copy)]
pub(super) struct TableRecord {
    pub(super) imported: bool,
    pub(super) ty: TableType,
}
