use crate::parser::ParsedBinary;

const COR20_HEADER_SIZE: usize = 72;

#[derive(Debug, Clone)]
pub struct DotNetInfo {
    pub runtime_version: String,
    pub cor20_flags: u32,
    pub entry_point_token: u32,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub streams: Vec<StreamHeader>,
    pub strings_heap_size: usize,
    pub blob_heap_size: usize,
    pub guid_heap_size: usize,
    pub user_strings_heap_size: usize,
    pub tables_present: Vec<u8>,
    pub typedefs: Vec<DotNetType>,
    pub methods: Vec<DotNetMethod>,
    pub member_refs: Vec<DotNetMemberRef>,
    pub type_refs: Vec<DotNetTypeRef>,
}

#[derive(Debug, Clone)]
pub struct StreamHeader {
    pub offset: u32,
    pub size: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct DotNetType {
    pub flags: u32,
    pub name: String,
    pub namespace: String,
    pub method_list_index: u32,
}

#[derive(Debug, Clone)]
pub struct DotNetTypeRef {
    pub name: String,
    pub namespace: String,
}

#[derive(Debug, Clone)]
pub struct DotNetMethod {
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: String,
    #[allow(dead_code)]
    pub signature_blob_index: u32,
    pub owner_type: String,
}

#[derive(Debug, Clone)]
pub struct DotNetMemberRef {
    pub parent: String,
    pub name: String,
    #[allow(dead_code)]
    pub signature_blob_index: u32,
}

pub fn is_dotnet(bin: &ParsedBinary) -> bool {
    if !bin.format.starts_with("PE") {
        return false;
    }
    bin.imports
        .iter()
        .any(|i| i.library.eq_ignore_ascii_case("mscoree.dll"))
        || find_cor20_rva_size(&bin.data).is_some()
}

fn find_cor20_rva_size(data: &[u8]) -> Option<(u32, u32)> {
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let opt_hdr_size = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().ok()?) as usize;
    let opt_hdr = coff + 20;
    if opt_hdr + 2 > data.len() {
        return None;
    }
    let magic = u16::from_le_bytes(data[opt_hdr..opt_hdr + 2].try_into().ok()?);
    let dir_off = match magic {
        0x10b => opt_hdr + 96,
        0x20b => opt_hdr + 112,
        _ => return None,
    };
    let cor_dir = dir_off + 14 * 8;
    if cor_dir + 8 > data.len() || cor_dir + 8 > opt_hdr + opt_hdr_size {
        return None;
    }
    let rva = u32::from_le_bytes(data[cor_dir..cor_dir + 4].try_into().ok()?);
    let size = u32::from_le_bytes(data[cor_dir + 4..cor_dir + 8].try_into().ok()?);
    if rva == 0 || size == 0 {
        return None;
    }
    Some((rva, size))
}

fn rva_to_offset(bin: &ParsedBinary, rva: u32) -> Option<usize> {
    let target = bin.image_base.checked_add(rva as u64)?;
    for sec in &bin.sections {
        let sec_end = sec.vaddr.checked_add(sec.size)?;
        if target >= sec.vaddr && target < sec_end {
            return sec
                .offset
                .checked_add(target - sec.vaddr)
                .map(|o| o as usize);
        }
    }
    None
}

pub fn parse(bin: &ParsedBinary) -> Result<DotNetInfo, String> {
    if !bin.format.starts_with("PE") {
        return Err("Not a PE file".into());
    }
    let (cor_rva, _cor_size) =
        find_cor20_rva_size(&bin.data).ok_or("CLR Runtime Header (data dir 14) not present")?;
    let cor_off = rva_to_offset(bin, cor_rva).ok_or("CLR header RVA outside any section")?;
    if cor_off + COR20_HEADER_SIZE > bin.data.len() {
        return Err("CLR header truncated".into());
    }
    let h = &bin.data[cor_off..cor_off + COR20_HEADER_SIZE];

    let metadata_rva = le_u32(&h[8..12]).ok_or("CLR header metadata_rva truncated")?;
    let metadata_size = le_u32(&h[12..16]).ok_or("CLR header metadata_size truncated")?;
    let cor20_flags = le_u32(&h[16..20]).ok_or("CLR header flags truncated")?;
    let entry_point_token = le_u32(&h[20..24]).ok_or("CLR header entry token truncated")?;

    let md_off = rva_to_offset(bin, metadata_rva).ok_or("Metadata RVA outside any section")?;
    if md_off + 16 > bin.data.len() {
        return Err("Metadata root truncated".into());
    }
    let mr = &bin.data[md_off..];
    if &mr[0..4] != b"BSJB" {
        return Err("Metadata signature 'BSJB' not found at expected offset".into());
    }
    let version_length = le_u32(&mr[12..16]).ok_or("Metadata version length truncated")? as usize;
    if 16 + version_length > mr.len() {
        return Err("Metadata version string truncated".into());
    }
    let version_bytes = &mr[16..16 + version_length];
    let runtime_version = std::str::from_utf8(
        &version_bytes[..version_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(version_bytes.len())],
    )
    .unwrap_or("?")
    .to_string();
    let mut p = 16 + version_length;
    p += 2;
    if p + 2 > mr.len() {
        return Err("Stream count truncated".into());
    }
    let stream_count = le_u16(&mr[p..p + 2]).ok_or("Stream count truncated")? as usize;
    p += 2;

    let mut streams = Vec::new();
    for _ in 0..stream_count {
        if p + 8 > mr.len() {
            return Err("Stream header truncated".into());
        }
        let s_off = le_u32(&mr[p..p + 4]).ok_or("Stream offset truncated")?;
        let s_size = le_u32(&mr[p + 4..p + 8]).ok_or("Stream size truncated")?;
        p += 8;
        let name_start = p;
        let mut name_end = p;
        while name_end < mr.len() && mr[name_end] != 0 {
            name_end += 1;
        }
        let name = std::str::from_utf8(&mr[name_start..name_end])
            .unwrap_or("?")
            .to_string();
        let total_name_len = (name_end - name_start) + 1;
        let padded = (total_name_len + 3) & !3;
        p += padded;
        streams.push(StreamHeader {
            offset: s_off,
            size: s_size,
            name,
        });
    }

    let strings_stream = streams.iter().find(|s| s.name == "#Strings").cloned();
    let blob_stream = streams.iter().find(|s| s.name == "#Blob").cloned();
    let guid_stream = streams.iter().find(|s| s.name == "#GUID").cloned();
    let us_stream = streams.iter().find(|s| s.name == "#US").cloned();
    let tables_stream = streams
        .iter()
        .find(|s| s.name == "#~" || s.name == "#-")
        .cloned();

    let strings_heap_offset = strings_stream.as_ref().map(|s| md_off + s.offset as usize);
    let strings_heap_end = strings_stream.as_ref().map(|s| {
        md_off
            .saturating_add(s.offset as usize)
            .saturating_add(s.size as usize)
            .min(bin.data.len())
    });

    let read_cstr = |idx: u32| -> String {
        let (Some(start), Some(end)) = (strings_heap_offset, strings_heap_end) else {
            return String::new();
        };
        let pos = match start.checked_add(idx as usize) {
            Some(p) if p < end => p,
            _ => return String::new(),
        };
        let mut e = pos;
        while e < end && bin.data[e] != 0 {
            e += 1;
        }
        std::str::from_utf8(&bin.data[pos..e])
            .unwrap_or("?")
            .to_string()
    };

    let mut typedefs = Vec::new();
    let mut methods = Vec::new();
    let mut member_refs = Vec::new();
    let mut type_refs = Vec::new();
    let mut tables_present = Vec::new();

    if let Some(ts) = tables_stream {
        let tbl_off = md_off + ts.offset as usize;
        if tbl_off + 24 > bin.data.len() {
            return Err("Tables stream header truncated".into());
        }
        let heap_sizes = bin.data[tbl_off + 6];
        let valid = u64::from_le_bytes(
            bin.data[tbl_off + 8..tbl_off + 16]
                .try_into()
                .map_err(|_| "Tables valid mask truncated")?,
        );
        let _sorted = u64::from_le_bytes(
            bin.data[tbl_off + 16..tbl_off + 24]
                .try_into()
                .map_err(|_| "Tables sorted mask truncated")?,
        );
        let strings_idx_size = if heap_sizes & 0x01 != 0 {
            4usize
        } else {
            2usize
        };
        let guid_idx_size = if heap_sizes & 0x02 != 0 {
            4usize
        } else {
            2usize
        };
        let blob_idx_size = if heap_sizes & 0x04 != 0 {
            4usize
        } else {
            2usize
        };

        let mut row_counts = [0u32; 64];
        let mut p = tbl_off + 24;
        for (i, slot) in row_counts.iter_mut().enumerate() {
            if valid & (1u64 << i) != 0 {
                if p + 4 > bin.data.len() {
                    return Err("Row count truncated".into());
                }
                *slot = le_u32(&bin.data[p..p + 4]).ok_or("Row count truncated")?;
                tables_present.push(i as u8);
                p += 4;
            }
        }

        let table_row_size: [Option<usize>; 64] =
            compute_row_sizes(strings_idx_size, guid_idx_size, blob_idx_size, &row_counts);

        let mut row_offsets = [0usize; 64];
        let mut cursor = p;
        for i in 0..64 {
            row_offsets[i] = cursor;
            if let Some(sz) = table_row_size[i] {
                cursor = cursor.saturating_add(sz.saturating_mul(row_counts[i] as usize));
                if cursor > bin.data.len() {
                    break;
                }
            } else if row_counts[i] > 0 {
                break;
            }
        }

        let typeref_rows = row_counts[1] as usize;
        let typeref_row_size = table_row_size[1].unwrap_or(0);
        if typeref_rows > 0 && typeref_row_size > 0 && row_offsets[1] != 0 {
            let mut row_off = row_offsets[1];
            for _ in 0..typeref_rows {
                if row_off + typeref_row_size > bin.data.len() {
                    break;
                }
                let r = &bin.data[row_off..row_off + typeref_row_size];
                let mut q = coded_index_size(&row_counts, &[38, 35, 26]);
                let name_idx = read_idx(&r[q..], strings_idx_size);
                q += strings_idx_size;
                let ns_idx = read_idx(&r[q..], strings_idx_size);
                let (name, ns) = (read_cstr(name_idx), read_cstr(ns_idx));
                type_refs.push(DotNetTypeRef {
                    name: if name.is_empty() {
                        format!("<typeref{}>", type_refs.len() + 1)
                    } else {
                        name
                    },
                    namespace: ns,
                });
                row_off += typeref_row_size;
            }
        }

        let typedef_rows = row_counts[2] as usize;
        let typedef_row_size = table_row_size[2].unwrap_or(0);
        let type_defs_decodable = typedef_rows > 0 && typedef_row_size > 0 && row_offsets[2] != 0;
        if type_defs_decodable {
            let row_size = typedef_row_size;
            let typedeforref_idx = coded_index_size(&row_counts, &[2, 1, 27]);
            let field_idx_size = simple_idx_size(row_counts[4]);
            let method_idx_size = simple_idx_size(row_counts[6]);
            let mut row_off = row_offsets[2];
            for _ in 0..typedef_rows {
                if row_off + row_size > bin.data.len() {
                    break;
                }
                let r = &bin.data[row_off..row_off + row_size];
                let flags = le_u32(&r[0..4]).ok_or("TypeDef flags truncated")?;
                let mut q = 4;
                let name_idx = read_idx(&r[q..], strings_idx_size);
                q += strings_idx_size;
                let ns_idx = read_idx(&r[q..], strings_idx_size);
                q += strings_idx_size;
                q += typedeforref_idx;
                q += field_idx_size;
                let method_list = read_idx(&r[q..], method_idx_size);
                typedefs.push(DotNetType {
                    flags,
                    name: read_cstr(name_idx),
                    namespace: read_cstr(ns_idx),
                    method_list_index: method_list,
                });
                row_off += row_size;
            }
        }

        let method_rows = row_counts[6] as usize;
        let method_row_size = table_row_size[6].unwrap_or(0);
        let methods_decodable = method_rows > 0 && method_row_size > 0 && row_offsets[6] != 0;
        if methods_decodable {
            let row_size = method_row_size;
            let mut row_off = row_offsets[6];
            let param_idx_size = simple_idx_size(row_counts[8]);
            for _ in 0..method_rows {
                if row_off + row_size > bin.data.len() {
                    break;
                }
                let r = &bin.data[row_off..row_off + row_size];
                let rva = le_u32(&r[0..4]).ok_or("MethodDef RVA truncated")?;
                let impl_flags = le_u16(&r[4..6]).ok_or("MethodDef implflags truncated")?;
                let flags = le_u16(&r[6..8]).ok_or("MethodDef flags truncated")?;
                let mut q = 8;
                let name_idx = read_idx(&r[q..], strings_idx_size);
                q += strings_idx_size;
                let sig_idx = read_idx(&r[q..], blob_idx_size);
                q += blob_idx_size;
                let _param_list = read_idx(&r[q..], param_idx_size);
                methods.push(DotNetMethod {
                    rva,
                    impl_flags,
                    flags,
                    name: read_cstr(name_idx),
                    signature_blob_index: sig_idx,
                    owner_type: String::new(),
                });
                row_off += row_size;
            }
            let typedef_count = typedefs.len();
            for i in 0..typedef_count {
                let start = typedefs[i].method_list_index as usize;
                if start == 0 {
                    continue;
                }
                let end = if i + 1 < typedef_count {
                    typedefs[i + 1].method_list_index as usize
                } else {
                    methods.len() + 1
                };
                let qualified = if typedefs[i].namespace.is_empty() {
                    typedefs[i].name.clone()
                } else {
                    format!("{}.{}", typedefs[i].namespace, typedefs[i].name)
                };
                for m_idx in start.saturating_sub(1)..end.saturating_sub(1).min(methods.len()) {
                    if methods[m_idx].owner_type.is_empty() {
                        methods[m_idx].owner_type = qualified.clone();
                    }
                }
            }
        }

        let mr_rows = row_counts[0x0A] as usize;
        let mr_row_size = table_row_size[0x0A].unwrap_or(0);
        if mr_rows > 0 && mr_row_size > 0 && row_offsets[0x0A] != 0 {
            let parent_idx = coded_index_size(&row_counts, &[2, 1, 26, 6, 27]);
            let mut row_off = row_offsets[0x0A];
            for _ in 0..mr_rows {
                if row_off + mr_row_size > bin.data.len() {
                    break;
                }
                let r = &bin.data[row_off..row_off + mr_row_size];
                let class_coded = read_idx(r, parent_idx);
                let mut q = parent_idx;
                let name_idx = read_idx(&r[q..], strings_idx_size);
                q += strings_idx_size;
                let sig_idx = read_idx(&r[q..], blob_idx_size);
                let tag = (class_coded & 0x7) as usize;
                let row = (class_coded >> 3) as usize;
                let parent = match tag {
                    0 => typedefs
                        .get(row.saturating_sub(1))
                        .map(|t| qualified(&t.namespace, &t.name))
                        .unwrap_or_else(|| format!("<typedef:{}>", row)),
                    1 => type_refs
                        .get(row.saturating_sub(1))
                        .map(|t| qualified(&t.namespace, &t.name))
                        .unwrap_or_else(|| format!("<typeref:{}>", row)),
                    3 => methods
                        .get(row.saturating_sub(1))
                        .map(|m| {
                            if m.owner_type.is_empty() {
                                m.name.clone()
                            } else {
                                format!("{}::{}", m.owner_type, m.name)
                            }
                        })
                        .unwrap_or_else(|| format!("<method:{}>", row)),
                    _ => format!("<parent:{}:{}>", tag, row),
                };
                member_refs.push(DotNetMemberRef {
                    parent,
                    name: {
                        let n = read_cstr(name_idx);
                        if n.is_empty() {
                            format!("<memberref{}>", member_refs.len() + 1)
                        } else {
                            n
                        }
                    },
                    signature_blob_index: sig_idx,
                });
                row_off += mr_row_size;
            }
        }
    }

    Ok(DotNetInfo {
        runtime_version,
        cor20_flags,
        entry_point_token,
        metadata_rva,
        metadata_size,
        strings_heap_size: strings_stream
            .as_ref()
            .map(|s| s.size as usize)
            .unwrap_or(0),
        blob_heap_size: blob_stream.as_ref().map(|s| s.size as usize).unwrap_or(0),
        guid_heap_size: guid_stream.as_ref().map(|s| s.size as usize).unwrap_or(0),
        user_strings_heap_size: us_stream.as_ref().map(|s| s.size as usize).unwrap_or(0),
        streams,
        tables_present,
        typedefs,
        methods,
        member_refs,
        type_refs,
    })
}

fn qualified(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", namespace, name)
    }
}

pub fn resolve_token(info: &DotNetInfo, token: u32) -> String {
    let table = token >> 24;
    let row = (token & 0x00FF_FFFF) as usize;
    if row == 0 {
        return format!("{:#x}", token);
    }
    let i = row.saturating_sub(1);
    match table {
        0x01 => info
            .type_refs
            .get(i)
            .map(|t| qualified(&t.namespace, &t.name))
            .unwrap_or_else(|| format!("TypeRef:{:#x}", token)),
        0x02 => info
            .typedefs
            .get(i)
            .map(|t| qualified(&t.namespace, &t.name))
            .unwrap_or_else(|| format!("TypeDef:{:#x}", token)),
        0x06 => info
            .methods
            .get(i)
            .map(|m| {
                if m.owner_type.is_empty() {
                    m.name.clone()
                } else {
                    format!("{}::{}", m.owner_type, m.name)
                }
            })
            .unwrap_or_else(|| format!("MethodDef:{:#x}", token)),
        0x0A => info
            .member_refs
            .get(i)
            .map(|m| format!("{}::{}", m.parent, m.name))
            .unwrap_or_else(|| format!("MemberRef:{:#x}", token)),
        _ => format!("{:#x}", token),
    }
}

fn read_idx(buf: &[u8], size: usize) -> u32 {
    if size == 4 && buf.len() >= 4 {
        u32::from_le_bytes(buf[..4].try_into().unwrap())
    } else if size == 2 && buf.len() >= 2 {
        u16::from_le_bytes(buf[..2].try_into().unwrap()) as u32
    } else {
        0
    }
}

#[inline]
fn le_u16(b: &[u8]) -> Option<u16> {
    b.get(..2)?.try_into().ok().map(u16::from_le_bytes)
}

#[inline]
fn le_u32(b: &[u8]) -> Option<u32> {
    b.get(..4)?.try_into().ok().map(u32::from_le_bytes)
}

fn simple_idx_size(rows: u32) -> usize {
    if rows >= 0x10000 {
        4
    } else {
        2
    }
}

fn coded_index_size(row_counts: &[u32; 64], target_tables: &[usize]) -> usize {
    let tag_bits = match target_tables.len() {
        0 | 1 => 0,
        2 => 1,
        3 | 4 => 2,
        5..=8 => 3,
        9..=16 => 4,
        _ => 5,
    };
    let max_rows = target_tables
        .iter()
        .map(|&i| row_counts[i])
        .max()
        .unwrap_or(0);
    if max_rows >= (1u32 << (16 - tag_bits)) {
        4
    } else {
        2
    }
}

fn compute_row_sizes(
    strings_idx: usize,
    guid_idx: usize,
    blob_idx: usize,
    row_counts: &[u32; 64],
) -> [Option<usize>; 64] {
    let mut sz = [None; 64];
    let s = strings_idx;
    let g = guid_idx;
    let b = blob_idx;
    let simple = simple_idx_size;
    let tdor = coded_index_size(row_counts, &[2, 1, 27]);
    let hcm = coded_index_size(row_counts, &[6, 4, 1, 23, 26]);
    let hca = coded_index_size(
        row_counts,
        &[
            6, 4, 1, 2, 8, 9, 10, 0, 14, 17, 20, 23, 26, 27, 28, 32, 35, 38, 39, 40, 41, 42,
        ],
    );
    let hfm = coded_index_size(row_counts, &[4, 33]);
    let hds = coded_index_size(row_counts, &[2, 6, 32]);
    let mfp = coded_index_size(row_counts, &[2, 1, 26, 6, 27]);
    let hs = coded_index_size(row_counts, &[6, 4]);
    let mdor = coded_index_size(row_counts, &[6, 10]);
    let mfo = coded_index_size(row_counts, &[4, 6]);
    let ic = coded_index_size(row_counts, &[38, 35]);
    let cat = coded_index_size(row_counts, &[6, 10]);
    let res = coded_index_size(row_counts, &[38, 35, 26]);
    let tos = coded_index_size(row_counts, &[2, 6]);

    sz[0x00] = Some(2 + s + g + g + g);
    sz[0x01] = Some(res + s + s);
    sz[0x02] = Some(4 + s + s + tdor + simple(row_counts[4]) + simple(row_counts[6]));
    sz[0x03] = Some(simple(row_counts[4]));
    sz[0x04] = Some(2 + s + b);
    sz[0x05] = Some(simple(row_counts[6]));
    sz[0x06] = Some(4 + 2 + 2 + s + b + simple(row_counts[8]));
    sz[0x07] = Some(simple(row_counts[8]));
    sz[0x08] = Some(2 + 2 + s);
    sz[0x09] = Some(simple(row_counts[2]) + tdor);
    sz[0x0A] = Some(mfp + s + b);
    sz[0x0B] = Some(2 + hcm + b);
    sz[0x0C] = Some(hca + cat + b);
    sz[0x0D] = Some(hfm + b);
    sz[0x0E] = Some(2 + hds + b);
    sz[0x0F] = Some(2 + 4 + simple(row_counts[2]));
    sz[0x10] = Some(4 + simple(row_counts[4]));
    sz[0x11] = Some(b);
    sz[0x12] = Some(simple(row_counts[2]) + simple(row_counts[20]));
    sz[0x13] = Some(simple(row_counts[0x14]));
    sz[0x14] = Some(2 + s + tdor);
    sz[0x15] = Some(simple(row_counts[2]) + simple(row_counts[23]));
    sz[0x16] = Some(simple(row_counts[0x17]));
    sz[0x17] = Some(2 + s + b);
    sz[0x18] = Some(2 + simple(row_counts[6]) + hs);
    sz[0x19] = Some(simple(row_counts[2]) + mdor + mdor);
    sz[0x1A] = Some(s);
    sz[0x1B] = Some(b);
    sz[0x1C] = Some(2 + mfo + s + simple(row_counts[26]));
    sz[0x1D] = Some(4 + simple(row_counts[4]));
    sz[0x1E] = Some(4 + 4);
    sz[0x1F] = Some(4);
    sz[0x20] = Some(4 + 4 + 4 + 4 + b + s + s);
    sz[0x21] = Some(4);
    sz[0x22] = Some(4 + 4 + 4);
    sz[0x23] = Some(8 + 4 + b + s + s + b);
    sz[0x24] = Some(4 + simple(row_counts[35]));
    sz[0x25] = Some(4 + 4 + 4 + simple(row_counts[35]));
    sz[0x26] = Some(4 + s + b);
    sz[0x27] = Some(4 + 4 + s + s + ic);
    sz[0x28] = Some(4 + 4 + s + ic);
    sz[0x29] = Some(simple(row_counts[2]) + simple(row_counts[2]));
    sz[0x2A] = Some(2 + 2 + s + tos);
    sz[0x2B] = Some(mdor + b);
    sz[0x2C] = Some(simple(row_counts[42]) + tdor);
    sz
}
