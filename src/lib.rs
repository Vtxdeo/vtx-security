mod report;
mod scan;

pub use report::{Finding, Report, Severity};
pub use scan::{scan_vtx_file, ScanError, ScanOptions};
