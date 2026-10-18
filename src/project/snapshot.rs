use super::analysis_codec::{
    read_analysis, read_insn, read_types, write_analysis, write_insn, write_types,
};
use super::binary_codec::{R, W};
use super::{fnv1a64, MAGIC, MAGIC_ZSTD, VERSION};
use crate::analysis::AnalysisResult;
use crate::disasm::DisasmResult;
use crate::gui::ProgramData;

#[allow(dead_code)]
pub struct ProjectSnapshot {
    pub source_path: String,
    pub project_name: String,
    pub saved_at: u64,
    pub src_len: u64,
    pub src_mtime: u64,
    pub disasm: DisasmResult,
    pub analysis: AnalysisResult,
    pub annotations: Annotations,
}

#[derive(Debug)]
pub struct Annotations {
    pub comments: rustc_hash::FxHashMap<u64, String>,
    pub comments_ex: rustc_hash::FxHashMap<(u64, crate::gui::CommentKind), String>,
    pub user_func_names: rustc_hash::FxHashMap<u64, String>,
    pub bookmarks: Vec<crate::gui::Bookmark>,
    pub patches: Vec<crate::gui::PatchRecord>,
    pub patch_seq: u64,
    pub user_labels: rustc_hash::FxHashMap<u64, String>,
    pub label_sources: rustc_hash::FxHashMap<u64, crate::gui::SourceType>,
    pub function_tags: rustc_hash::FxHashMap<u64, Vec<String>>,
    pub user_xrefs: Vec<crate::gui::UserXRef>,
    pub types: crate::type_system::DataTypeManager,
    pub data_types_at: rustc_hash::FxHashMap<u64, crate::type_system::TypeId>,
}

fn source_meta(path: &str) -> (u64, u64) {
    std::fs::metadata(path)
        .map(|m| {
            let len = m.len();
            let mtime = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            (len, mtime)
        })
        .unwrap_or((0, 0))
}

pub fn save_project_db(program: &ProgramData, path: &str) -> Result<(), String> {
    let source = if !program.file_path.is_empty() {
        program.file_path.as_str()
    } else {
        path.strip_suffix(".rdb").unwrap_or(path)
    };
    let (src_len, src_mtime) = source_meta(source);
    let disasm = program.disasm.as_ref().ok_or("no disassembly to save")?;
    let analysis = program.analysis.as_ref().cloned().unwrap_or_default();

    let mut w = W::new();
    w.buf.extend_from_slice(MAGIC);
    w.u32(VERSION);
    w.u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    w.str(source);
    w.str(&program.current_program_name);
    w.u64(src_len);
    w.u64(src_mtime);

    w.str(&disasm.arch);
    let insns = &disasm.instructions;
    w.u32(insns.len() as u32);
    for insn in insns.iter() {
        write_insn(&mut w, insn);
    }

    write_analysis(&mut w, &analysis);

    w.hashmap_u64_str(&program.comments);
    w.u32(program.comments_ex.len() as u32);
    let mut cex: Vec<(&(u64, crate::gui::CommentKind), &String)> =
        program.comments_ex.iter().collect();
    cex.sort_by(|a, b| {
        let ((aa, ak), _) = a;
        let ((ba, bk), _) = b;
        aa.cmp(ba).then(ak.tag().cmp(&bk.tag()))
    });
    for ((addr, kind), text) in cex {
        w.u64(*addr);
        w.u8(kind.tag());
        w.str(text);
    }
    w.hashmap_u64_str(&program.user_func_names);
    w.u32(program.bookmarks.len() as u32);
    for b in &program.bookmarks {
        w.u64(b.addr);
        w.str(&b.note);
        w.u8(match b.kind {
            crate::gui::BookmarkKind::Note => 0,
            crate::gui::BookmarkKind::Info => 1,
            crate::gui::BookmarkKind::Error => 2,
            crate::gui::BookmarkKind::Analysis => 3,
        });
    }
    w.u32(program.patches.len() as u32);
    for p in &program.patches {
        w.u64(p.id);
        w.u64(p.offset as u64);
        w.u64(p.vaddr);
        w.bytes(&p.original);
        w.bytes(&p.new);
        w.str(&p.description);
        w.u64(p.timestamp);
    }
    w.u64(program.patch_seq);
    w.hashmap_u64_str(&program.user_labels);
    w.u32(program.label_sources.len() as u32);
    let mut ls: Vec<(&u64, &crate::gui::SourceType)> = program.label_sources.iter().collect();
    ls.sort_by(|a, b| a.0.cmp(b.0));
    for (addr, src) in ls {
        w.u64(*addr);
        w.u8(src.tag());
    }
    w.u32(program.function_tags.len() as u32);
    let mut ft: Vec<(&u64, &Vec<String>)> = program.function_tags.iter().collect();
    ft.sort_by(|a, b| a.0.cmp(b.0));
    for (addr, tags) in ft {
        w.u64(*addr);
        w.u32(tags.len() as u32);
        for t in tags {
            w.str(t);
        }
    }
    w.u32(program.user_xrefs.len() as u32);
    for x in &program.user_xrefs {
        w.u64(x.from);
        w.u64(x.to);
        w.str(&x.note);
        w.str(&x.kind);
        w.i32(x.op_index);
    }
    write_types(&mut w, &program.types);
    w.u32(program.data_types_at.len() as u32);
    let mut dta: Vec<(&u64, &u32)> = program.data_types_at.iter().collect();
    dta.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in dta {
        w.u64(*k);
        w.u32(*v);
    }

    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let tmp = format!("{}.{}.tmp", path, std::process::id());
    let mut data = w.buf;
    let hash = fnv1a64(&data);
    data.extend_from_slice(&hash.to_le_bytes());
    let mut out = data[..8].to_vec();
    let payload = &data[8..];
    out.extend_from_slice(MAGIC_ZSTD);
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    match zstd::bulk::compress(payload, 3) {
        Ok(c) => out.extend_from_slice(&c),
        Err(_) => {
            out = data;
        }
    }
    let hash = fnv1a64(&out);
    out.extend_from_slice(&hash.to_le_bytes());
    let data = out;
    std::fs::write(&tmp, &data).map_err(|e| format!("cannot write project DB {}: {}", tmp, e))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| format!("cannot finalize project DB {}: {}", path, e))?;
    Ok(())
}

pub fn db_path_for(source: &str) -> String {
    format!("{}.rdb", source)
}

pub fn projects_root() -> std::path::PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return std::path::Path::new(&appdata)
            .join("rust-debugger")
            .join("projects");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::Path::new(&home)
            .join(".local")
            .join("share")
            .join("rust-debugger")
            .join("projects");
    }
    std::path::PathBuf::from("projects")
}

fn sanitize_project_name(source: &str) -> String {
    let stem = std::path::Path::new(source)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed".into());
    let mut h: u64 = 0xcbf29ce484222325;
    for b in source.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let safe: String = stem
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = safe.chars().take(48).collect::<String>();
    format!("{}_{:016x}", trimmed, h)
}

pub fn project_dir_for(source: &str) -> std::path::PathBuf {
    projects_root().join(sanitize_project_name(source))
}

#[derive(Debug, Clone)]
pub struct ProjectLocator {
    pub dir: std::path::PathBuf,
    #[allow(dead_code)]
    pub name: String,
}

impl ProjectLocator {
    pub fn for_source(source: &str) -> Self {
        let dir = project_dir_for(source);
        let name = sanitize_project_name(source);
        Self { dir, name }
    }
    pub fn db_path(&self) -> String {
        self.dir.join("program.rdb").to_string_lossy().to_string()
    }
    #[allow(dead_code)]
    pub fn ensure_dir(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| format!("cannot create project dir {}: {}", self.dir.display(), e))
    }
}

pub fn db_path_in_project(source: &str) -> String {
    ProjectLocator::for_source(source).db_path()
}

pub fn resolve_db_path(source: &str) -> String {
    let legacy = db_path_for(source);
    if std::path::Path::new(&legacy).exists() {
        return legacy;
    }
    let proj = db_path_in_project(source);
    if std::path::Path::new(&proj).exists() {
        return proj;
    }
    proj
}

fn rd_fail(e: String) -> Option<ProjectSnapshot> {
    if std::env::var_os("RDDB_DEBUG").is_some() {
        eprintln!("RDDB load error: {}", e);
    }
    None
}

pub fn load_project_db(path: &str) -> Option<ProjectSnapshot> {
    let mut bytes = std::fs::read(path).ok()?;
    if bytes.len() < 12 {
        return rd_fail("truncated".into());
    }
    let expected = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    bytes.truncate(bytes.len() - 8);
    if fnv1a64(&bytes) != expected {
        return rd_fail("checksum mismatch".into());
    }
    if bytes.len() >= 16 && bytes[8..12] == *MAGIC_ZSTD {
        let raw_len = u64::from_le_bytes(bytes[12..20].try_into().unwrap()) as usize;
        let ok = raw_len <= (1usize << 32);
        let decompressed = if ok {
            zstd::bulk::decompress(&bytes[20..], raw_len.max(1)).ok()
        } else {
            None
        };
        let Some(decompressed) = decompressed else {
            return rd_fail("bad zstd payload".into());
        };
        let mut full = bytes[..8].to_vec();
        full.extend_from_slice(&decompressed);
        bytes = full;
    }
    let mut r = R::new(&bytes);
    if r.take(4).ok().filter(|m| *m == MAGIC).is_none() {
        return rd_fail("bad magic".into());
    }
    let db_ver = r.u32().ok()?;
    if db_ver != 1 && db_ver != 2 && db_ver != 3 && db_ver != 4 && db_ver != VERSION {
        return rd_fail("bad version".into());
    }
    let saved_at = r.u64().ok()?;
    let source_path = match r.str() {
        Ok(s) => s,
        Err(e) => return rd_fail(e),
    };
    let project_name = match r.str() {
        Ok(s) => s,
        Err(e) => return rd_fail(e),
    };
    let src_len = r.u64().ok()?;
    let src_mtime = r.u64().ok()?;

    let (cur_len, cur_mtime) = source_meta(&source_path);
    if cur_len != src_len || cur_mtime != src_mtime {
        return rd_fail(format!(
            "stale: src {} ({}:{}) != db ({}:{})",
            source_path, cur_len, cur_mtime, src_len, src_mtime
        ));
    }

    let arch = match r.str() {
        Ok(a) => a,
        Err(e) => return rd_fail(e),
    };
    let count = match r.u32() {
        Ok(c) => c as usize,
        Err(e) => return rd_fail(e),
    };
    let mut instructions = Vec::with_capacity(count.min(1 << 26));
    for _ in 0..count {
        match read_insn(&mut r) {
            Ok(i) => instructions.push(i),
            Err(e) => return rd_fail(e),
        }
    }
    let disasm = DisasmResult {
        instructions: std::sync::Arc::new(instructions),
        arch,
    };

    let analysis = match read_analysis(&mut r, db_ver) {
        Ok(a) => a,
        Err(e) => return rd_fail(e),
    };

    let annotations = match read_annotations(&mut r, db_ver) {
        Ok(a) => a,
        Err(e) => return rd_fail(e),
    };

    Some(ProjectSnapshot {
        source_path,
        project_name,
        saved_at,
        src_len,
        src_mtime,
        disasm,
        analysis,
        annotations,
    })
}

fn read_annotations(r: &mut R, db_ver: u32) -> Result<Annotations, String> {
    let comments = r.hashmap_u64_str()?;
    let mut comments_ex = rustc_hash::FxHashMap::default();
    if db_ver >= 2 {
        let n = r.u32()? as usize;
        for _ in 0..n.min(1 << 20) {
            let addr = r.u64()?;
            let kind = crate::gui::CommentKind::from_tag(r.u8()?);
            let text = r.str()?;
            comments_ex.insert((addr, kind), text);
        }
    } else {
        for (addr, text) in &comments {
            comments_ex.insert((*addr, crate::gui::CommentKind::Eol), text.clone());
        }
    }
    let mut ann = Annotations {
        comments,
        comments_ex,
        user_func_names: r.hashmap_u64_str()?,
        bookmarks: {
            let n = r.u32()? as usize;
            let mut v = Vec::with_capacity(n.min(1 << 20));
            for _ in 0..n {
                let addr = r.u64()?;
                let note = r.str()?;
                let kind = if db_ver >= 2 {
                    match r.u8()? {
                        1 => crate::gui::BookmarkKind::Info,
                        2 => crate::gui::BookmarkKind::Error,
                        3 => crate::gui::BookmarkKind::Analysis,
                        _ => crate::gui::BookmarkKind::Note,
                    }
                } else {
                    crate::gui::BookmarkKind::Note
                };
                v.push(crate::gui::Bookmark { addr, note, kind });
            }
            v
        },
        patches: {
            let n = r.u32()? as usize;
            let mut v = Vec::with_capacity(n.min(1 << 20));
            for _ in 0..n {
                v.push(crate::gui::PatchRecord {
                    id: r.u64()?,
                    offset: r.u64()? as usize,
                    vaddr: r.u64()?,
                    original: r.bytes()?,
                    new: r.bytes()?,
                    description: r.str()?,
                    timestamp: r.u64()?,
                });
            }
            v
        },
        patch_seq: r.u64()?,
        user_labels: r.hashmap_u64_str()?,
        label_sources: if db_ver >= 2 {
            let n = r.u32()? as usize;
            let mut m = rustc_hash::FxHashMap::with_capacity_and_hasher(
                n.min(1 << 20),
                rustc_hash::FxBuildHasher,
            );
            for _ in 0..n {
                let addr = r.u64()?;
                let tag = r.u8()?;
                let st = if db_ver >= 3 {
                    crate::gui::SourceType::from_tag(tag)
                } else {
                    crate::gui::SourceType::from_tag_v2(tag)
                };
                m.insert(addr, st);
            }
            m
        } else {
            rustc_hash::FxHashMap::default()
        },
        function_tags: if db_ver >= 2 {
            let n = r.u32()? as usize;
            let mut m = rustc_hash::FxHashMap::with_capacity_and_hasher(
                n.min(1 << 20),
                rustc_hash::FxBuildHasher,
            );
            for _ in 0..n {
                let addr = r.u64()?;
                let c = r.u32()? as usize;
                let mut tags = Vec::with_capacity(c.min(1024));
                for _ in 0..c {
                    tags.push(r.str()?);
                }
                m.insert(addr, tags);
            }
            m
        } else {
            rustc_hash::FxHashMap::default()
        },
        user_xrefs: {
            let n = r.u32()? as usize;
            let mut v = Vec::with_capacity(n.min(1 << 20));
            for _ in 0..n {
                let from = r.u64()?;
                let to = r.u64()?;
                let note = r.str()?;
                let (kind, op_index) = if db_ver >= 3 {
                    (r.str()?, r.i32()?)
                } else {
                    (String::new(), -1)
                };
                v.push(crate::gui::UserXRef {
                    from,
                    to,
                    note,
                    kind,
                    op_index,
                });
            }
            v
        },
        types: read_types(r, db_ver)?,
        data_types_at: {
            let n = r.u32()? as usize;
            let mut m = rustc_hash::FxHashMap::with_capacity_and_hasher(
                n.min(1 << 20),
                rustc_hash::FxBuildHasher,
            );
            for _ in 0..n {
                let k = r.u64()?;
                let v = r.u32()?;
                m.insert(k, v);
            }
            m
        },
    };
    {
        let valid: Vec<u64> = ann
            .data_types_at
            .iter()
            .filter_map(|(k, v)| {
                if ann.types.get(*v).is_some() {
                    None
                } else {
                    Some(*k)
                }
            })
            .collect();
        for k in valid {
            ann.data_types_at.remove(&k);
        }
    }
    Ok(ann)
}

pub fn apply_annotations(program: &mut ProgramData, a: &Annotations) {
    program.comments = a.comments.clone();
    program.comments_ex = a.comments_ex.clone();
    program.user_func_names = a.user_func_names.clone();
    program.bookmarks = a.bookmarks.clone();
    program.patches = a.patches.clone();
    program.patch_seq = a.patch_seq;
    program.user_labels = a.user_labels.clone();
    program.label_sources = a.label_sources.clone();
    program.function_tags = a.function_tags.clone();
    program.user_xrefs = a.user_xrefs.clone();
    program.types = a.types.clone();
    program.data_types_at = a.data_types_at.clone();
    program.dirty = false;
}
