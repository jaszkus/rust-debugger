







use super::db::XRefKind;
use crate::analysis::pipeline::AnalysisResult;
use crate::parser::ParsedBinary;
use rustc_hash::FxHashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportCallee {
    pub import_offset: u64,
    pub library: String,
    pub name: String,
    
    pub via: u64,
}

fn import_for_stub<'a>(
    binary: &'a ParsedBinary,
    library: &str,
    name: &str,
) -> Option<&'a crate::parser::Import> {
    binary.all_imports().find(|i| {
        i.name.eq_ignore_ascii_case(name)
            && (library.is_empty()
                || i.library.is_empty()
                || i.library.eq_ignore_ascii_case(library)
                || i.library
                    .to_ascii_lowercase()
                    .starts_with(&library.to_ascii_lowercase()))
    })
}


pub fn function_import_callees(
    binary: &ParsedBinary,
    analysis: &AnalysisResult,
) -> FxHashMap<u64, Vec<ImportCallee>> {
    let mut by_target: FxHashMap<u64, ImportCallee> = FxHashMap::default();
    for imp in binary.all_imports() {
        if imp.offset == 0 {
            continue;
        }
        by_target.entry(imp.offset).or_insert_with(|| ImportCallee {
            import_offset: imp.offset,
            library: imp.library.clone(),
            name: imp.name.clone(),
            via: imp.offset,
        });
    }
    
    for stub in analysis.stubs.values() {
        if stub.kind != crate::analysis::StubKind::ImportThunk {
            continue;
        }
        let Some((lib, name)) = stub.target_name.split_once('!') else {
            continue;
        };
        let Some(imp) = import_for_stub(binary, lib, name) else {
            continue;
        };
        let callee = ImportCallee {
            import_offset: imp.offset,
            library: if lib.is_empty() {
                imp.library.clone()
            } else {
                lib.to_string()
            },
            name: name.to_string(),
            via: stub.func_entry,
        };
        by_target.entry(stub.func_entry).or_insert(callee.clone());
        if stub.jump_addr != 0 {
            by_target.entry(stub.jump_addr).or_insert(callee);
        }
    }

    let mut spans: Vec<(u64, u64)> = analysis
        .functions
        .iter()
        .map(|f| (f.entry, f.end))
        .collect();
    spans.sort_unstable();
    let owner = |addr: u64| -> Option<u64> {
        let i = spans.partition_point(|&(s, _)| s <= addr);
        let &(s, e) = spans.get(i.checked_sub(1)?)?;
        (addr < e).then_some(s)
    };

    let mut out: FxHashMap<u64, Vec<ImportCallee>> = FxHashMap::default();
    for xr in &analysis.xrefs.all {
        if !matches!(
            xr.kind,
            XRefKind::Call
                | XRefKind::CallIndirect
                | XRefKind::TailCall
                | XRefKind::Jump
                | XRefKind::JumpIndirect
        ) {
            continue;
        }
        let Some(callee) = by_target.get(&xr.to) else {
            continue;
        };
        let Some(from_func) = owner(xr.from) else {
            continue;
        };
        let list = out.entry(from_func).or_default();
        if !list.iter().any(|c| {
            c.import_offset == callee.import_offset && c.via == callee.via
        }) {
            list.push(callee.clone());
        }
    }
    for list in out.values_mut() {
        list.sort_by_key(|c| (c.name.to_ascii_lowercase(), c.via));
    }
    out
}
