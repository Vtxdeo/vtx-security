use super::imports::classify_import;
use super::state::{MemoryRecord, ModuleRiskState, TableRecord};
use super::super::ScanError;
use wasmparser::{Operator, Payload, TypeRef};

pub(super) fn process_module_payload(
    state: &mut ModuleRiskState,
    payload: Payload,
) -> Result<(), ScanError> {
    match payload {
        Payload::ImportSection(reader) => {
            for import in reader {
                let import = import.map_err(|e| ScanError::WasmParse(e.to_string()))?;
                classify_import(
                    import.module,
                    import.name,
                    &mut state.imports_fs,
                    &mut state.imports_net,
                    &mut state.imports_process,
                    &mut state.imports_env,
                    &mut state.imports_time,
                    &mut state.imports_random,
                );

                match import.ty {
                    TypeRef::Func(_) => {
                        state.function_imports = state.function_imports.saturating_add(1);
                    }
                    TypeRef::Memory(mem) => {
                        state.memories.push(MemoryRecord {
                            imported: true,
                            ty: mem,
                        });
                    }
                    TypeRef::Table(table) => {
                        state.tables.push(TableRecord {
                            imported: true,
                            ty: table,
                        });
                    }
                    _ => {}
                }
            }
        }
        Payload::MemorySection(reader) => {
            for mem in reader {
                let mem = mem.map_err(|e| ScanError::WasmParse(e.to_string()))?;
                state.memories.push(MemoryRecord {
                    imported: false,
                    ty: mem,
                });
            }
        }
        Payload::TableSection(reader) => {
            for table in reader {
                let table = table.map_err(|e| ScanError::WasmParse(e.to_string()))?;
                state.tables.push(TableRecord {
                    imported: false,
                    ty: table.ty,
                });
            }
        }
        Payload::FunctionSection(reader) => {
            let mut count = 0u32;
            for _ in reader {
                count = count.saturating_add(1);
            }
            state.function_defs = state.function_defs.saturating_add(count);
        }
        Payload::DataSection(reader) => {
            for data in reader {
                let data = data.map_err(|e| ScanError::WasmParse(e.to_string()))?;
                state.data_segments = state.data_segments.saturating_add(1);
                state.data_bytes = state
                    .data_bytes
                    .saturating_add(data.data.len() as u64);
            }
        }
        Payload::CodeSectionEntry(body) => {
            let ops = body
                .get_operators_reader()
                .map_err(|e| ScanError::WasmParse(e.to_string()))?;
            for op in ops.into_iter() {
                let op = op.map_err(|e| ScanError::WasmParse(e.to_string()))?;
                match op {
                    Operator::CallIndirect { .. } => state.has_call_indirect = true,
                    Operator::MemoryGrow { .. } => state.has_memory_grow = true,
                    Operator::MemoryCopy { .. }
                    | Operator::MemoryFill { .. }
                    | Operator::MemoryInit { .. }
                    | Operator::DataDrop { .. }
                    | Operator::TableCopy { .. }
                    | Operator::TableFill { .. }
                    | Operator::TableInit { .. }
                    | Operator::ElemDrop { .. }
                    | Operator::TableGrow { .. } => state.has_bulk_memory = true,
                    _ => {}
                }
            }
        }
        _ => {}
    }

    Ok(())
}
