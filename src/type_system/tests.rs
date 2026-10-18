use super::*;

#[test]
fn struct_roundtrip() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("Foo").unwrap();
    m.add_field(s, "a", ID_INT, Some(0), "").unwrap();
    m.add_field(s, "b", ID_CHAR, Some(4), "").unwrap();
    assert_eq!(m.size_of(s), Some(8));
    let p = m.create_pointer(s).unwrap();
    assert_eq!(m.size_of(p), Some(8));
    let json = m.to_json();
    let mut m2 = DataTypeManager::new();
    m2.from_json(&json).unwrap();
    let s2 = m2.find_by_name("Foo").unwrap();
    assert_eq!(m2.size_of(s2), Some(8));
    let p2 = m2.find_by_name("Foo*").unwrap();
    assert_eq!(m2.size_of(p2), Some(8));
}

#[test]
fn typedef_survives_id_gap_roundtrip() {
    let mut m = DataTypeManager::new();
    let _a = m.create_struct("A").unwrap();
    let b = m.create_struct("B").unwrap();
    m.add_field(b, "x", ID_INT, Some(0), "").unwrap();
    let t = m.create_typedef("T", b).unwrap();
    assert_eq!(m.size_of(t), Some(4));
    let _e = m.create_enum("E", ID_UINT).unwrap();
    let _json = {
        m.delete(_a).unwrap();
        m.to_json()
    };
    let mut m2 = DataTypeManager::new();
    m2.from_json(&m.to_json()).unwrap();
    let t2 = m2.find_by_name("T").expect("typedef imported");
    assert_eq!(
        m2.get(t2).and_then(|dt| match dt {
            DataType::Typedef { target, .. } => Some(*target),
            _ => None,
        }),
        m2.find_by_name("B"),
        "typedef must point at the remapped B, not at itself"
    );
    assert_eq!(m2.size_of(t2), Some(4));
    let e2 = m2.find_by_name("E").expect("enum imported");
    assert_eq!(
        m2.size_of(e2),
        Some(4),
        "enum underlying must be remapped too"
    );
}

#[test]
fn union_fields_share_offset_zero() {
    let mut m = DataTypeManager::new();
    let u = m.create_union("U").unwrap();
    let f1 = m.add_field(u, "a", ID_INT, None, "").unwrap();
    let f2 = m.add_field(u, "b", ID_CHAR, None, "").unwrap();
    assert_eq!((f1.offset, f2.offset), (0, 0), "union members start at 0");
    assert_eq!(m.size_of(u), Some(4));
}

#[test]
fn name_collisions_rejected() {
    let mut m = DataTypeManager::new();
    assert!(m.create_struct("Foo").is_ok());
    assert!(m.create_struct("Foo").is_err());
}

#[test]
fn enum_works() {
    let mut m = DataTypeManager::new();
    let e = m.create_enum("State", ID_INT).unwrap();
    m.add_enum_variant(e, "A", 0).unwrap();
    m.add_enum_variant(e, "B", 1).unwrap();
    assert!(m.add_enum_variant(e, "A", 2).is_err());
    assert!(m.to_c_decl(e, 0).contains("A = 0"));
}

#[test]
fn union_size_rounds_up_to_alignment() {
    let mut m = DataTypeManager::new();
    let u = m.create_union("U").unwrap();
    let bytes = m.create_array(ID_CHAR, 5).unwrap();
    m.add_field(u, "bytes", bytes, None, "").unwrap();
    m.add_field(u, "word", ID_INT, None, "").unwrap();
    assert_eq!(m.size_of(u), Some(8));
    assert_eq!(m.align_of(u), 4);
}

#[test]
fn packed_struct_has_no_padding_and_roundtrips() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("P").unwrap();
    m.add_field(s, "a", ID_INT, Some(0), "").unwrap();
    m.add_field(s, "b", ID_CHAR, Some(4), "").unwrap();
    assert_eq!(m.size_of(s), Some(8));
    m.set_packed(s, true).unwrap();
    assert_eq!(m.size_of(s), Some(5));
    assert_eq!(m.align_of(s), 1);
    assert!(m.to_c_decl(s, 0).contains("__attribute__((packed))"));

    let mut m2 = DataTypeManager::new();
    m2.from_json(&m.to_json()).unwrap();
    let s2 = m2.find_by_name("P").unwrap();
    assert_eq!(
        m2.size_of(s2),
        Some(5),
        "packed flag must survive the roundtrip"
    );
    assert!(m.set_packed(ID_INT, true).is_err());
}

#[test]
fn struct_fields_stay_sorted_by_offset() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("S").unwrap();
    m.add_field(s, "c", ID_INT, Some(8), "").unwrap();
    m.add_field(s, "a", ID_INT, Some(0), "").unwrap();
    m.add_field(s, "b", ID_INT, Some(4), "").unwrap();
    let d = m.add_field(s, "d", ID_INT, None, "").unwrap();
    assert_eq!(d.offset, 12);
    let names: Vec<String> = match m.get(s) {
        Some(DataType::Struct { fields, .. }) => fields.iter().map(|f| f.name.clone()).collect(),
        _ => panic!("expected struct"),
    };
    assert_eq!(names, ["a", "b", "c", "d"]);
}

#[test]
fn default_manager_is_fully_seeded() {
    let m = DataTypeManager::default();
    assert_eq!(m.size_of(ID_INT), Some(4));
    assert_eq!(m.size_of(ID_POINTER), Some(8));
}

#[test]
fn self_referential_struct_is_deletable_but_not_embeddable() {
    let mut m = DataTypeManager::new();
    let node = m.create_struct("Node").unwrap();
    let ptr = m.create_pointer(node).unwrap();
    m.add_field(node, "next", ptr, Some(0), "").unwrap();
    assert!(
        m.add_field(node, "me", node, Some(8), "").is_err(),
        "by-value self containment must be rejected"
    );
    assert_eq!(m.size_of(node), Some(8));
    m.delete(node).unwrap();
    assert!(m.find_by_name("Node").is_none());
    assert!(
        m.find_by_name("Node*").is_none(),
        "derived pointer goes away with its base"
    );
}

#[test]
fn mutual_and_array_embedding_rejected() {
    let mut m = DataTypeManager::new();
    let a = m.create_struct("A").unwrap();
    let b = m.create_struct("B").unwrap();
    m.add_field(a, "b", b, Some(0), "").unwrap();
    assert!(m.add_field(b, "a", a, Some(0), "").is_err());
    let arr = m.create_array(a, 2).unwrap();
    assert!(m.add_field(a, "arr", arr, Some(8), "").is_err());
}

#[test]
fn delete_is_blocked_by_real_references_only() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("S").unwrap();
    let h = m.create_struct("H").unwrap();
    m.add_field(h, "s", s, Some(0), "").unwrap();
    assert!(m.delete(s).is_err(), "H still embeds S");
    assert!(m.delete(ID_INT).is_err(), "built-ins are protected");
    m.delete(h).unwrap();
    m.delete(s).unwrap();
    assert!(m.delete(s).is_err(), "already gone");
}

#[test]
fn is_used_at_covers_derived_types() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("S").unwrap();
    let p = m.create_pointer(s).unwrap();
    let mut used = std::collections::HashMap::new();
    used.insert(0x1000u64, p);
    assert!(m.is_used_at(s, &used), "S* applied at an address pins S");
    assert!(m.delete_with_usages(s, &used).is_err());
}

#[test]
fn rename_rekeys_derived_types() {
    let mut m = DataTypeManager::new();
    let a = m.create_struct("A").unwrap();
    let pa = m.create_pointer(a).unwrap();
    m.rename(a, "B").unwrap();
    assert_eq!(m.type_name(pa), "B*");
    assert_eq!(m.find_by_name("B*"), Some(pa));
    assert!(m.find_by_name("A*").is_none());
    let a2 = m.create_struct("A").unwrap();
    let pa2 = m.create_pointer(a2).unwrap();
    assert_ne!(pa2, pa);
    assert_eq!(m.resolve_type_name("A*").unwrap(), pa2);
    assert!(m.rename(ID_INT, "integer").is_err());
}

#[test]
fn invalid_names_and_dangling_targets_rejected() {
    let mut m = DataTypeManager::new();
    assert!(m.create_struct("").is_err());
    assert!(m.create_struct("   ").is_err());
    assert!(m.create_struct("Foo*").is_err());
    assert!(m.create_pointer(9999).is_err());
    assert!(m.create_array(9999, 4).is_err());
    assert!(m.create_typedef("T", 9999).is_err());
    assert!(m.create_enum("E", 9999).is_err());
}

#[test]
fn resolve_type_name_forms() {
    let mut m = DataTypeManager::new();
    assert_eq!(m.resolve_type_name(" INT ").unwrap(), ID_INT);
    assert_eq!(m.resolve_type_name("unsigned   int").unwrap(), ID_UINT);
    assert_eq!(m.resolve_type_name("uint32_t").unwrap(), ID_UINT);

    let cp = m.resolve_type_name("const char *").unwrap();
    assert_eq!(m.type_name(cp), "char*");

    let pp = m.resolve_type_name("int * *").unwrap();
    assert_eq!(m.type_name(pp), "int**");

    let grid = m.resolve_type_name("int[2][3]").unwrap();
    assert_eq!(m.size_of(grid), Some(24));

    assert!(m.resolve_type_name("nope").is_err());
    assert!(m.resolve_type_name("").is_err());
    assert!(m.resolve_type_name("*").is_err());
}

#[test]
fn ilp32_arch_adjusts_pointer_long_and_aliases() {
    let mut m = DataTypeManager::new();
    m.set_arch("x86");
    assert_eq!(m.size_of(ID_POINTER), Some(4));
    assert_eq!(m.size_of(ID_LONG), Some(4));
    let p = m.create_pointer(ID_INT).unwrap();
    assert_eq!(m.size_of(p), Some(4));
    assert_eq!(m.resolve_type_name("size_t").unwrap(), ID_UINT);

    m.set_arch("x86_64");
    assert_eq!(m.size_of(ID_POINTER), Some(8));
    assert_eq!(m.resolve_type_name("size_t").unwrap(), ID_ULONGLONG);
    assert!(m.set_pointer_size(2).is_err());
}

#[test]
fn c_decl_uses_valid_array_declarators() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("S").unwrap();
    let buf = m.create_array(ID_CHAR, 16).unwrap();
    m.add_field(s, "buf", buf, Some(0), "").unwrap();
    assert!(m.to_c_decl(s, 4).contains("char buf[16];"));
    let t = m.create_typedef("Buf", buf).unwrap();
    assert_eq!(m.to_c_decl(t, 0), "typedef char Buf[16];");
}

#[test]
fn import_into_populated_manager_renames_duplicates() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("Foo").unwrap();
    m.add_field(s, "a", ID_INT, Some(0), "").unwrap();
    let json = m.to_json();
    m.from_json(&json).unwrap();
    let copy = m
        .find_by_name("Foo_1")
        .expect("duplicate must be imported as Foo_1");
    assert_eq!(m.size_of(copy), Some(4));
}

#[test]
fn import_function_sig_remaps_ret_without_params() {
    let doc = serde_json::json!({
        "types": [
            { "id": 500, "kind": "struct", "name": "S", "fields": [] },
            { "id": 501, "kind": "function", "name": "f", "ret": 500,
              "calling_convention": "__stdcall", "varargs": false }
        ]
    });
    let mut m = DataTypeManager::new();
    m.from_json(&doc).unwrap();
    let f = m.find_by_name("f").expect("function imported");
    match m.get(f) {
        Some(DataType::FunctionSig {
            ret,
            calling_convention,
            ..
        }) => {
            assert_eq!(Some(*ret), m.find_by_name("S"));
            assert_eq!(calling_convention.as_str(), "stdcall");
        }
        other => panic!("expected function signature, got {:?}", other),
    }
}

#[test]
fn import_pointer_chain_is_order_independent() {
    let doc = serde_json::json!({
        "types": [
            { "id": 502, "kind": "pointer", "name": "S**", "target": 501 },
            { "id": 501, "kind": "pointer", "name": "S*", "target": 500 },
            { "id": 500, "kind": "struct", "name": "S", "fields": [] }
        ]
    });
    let mut m = DataTypeManager::new();
    m.from_json(&doc).unwrap();
    assert!(m.find_by_name("S*").is_some());
    assert!(m.find_by_name("S**").is_some());
}

#[test]
fn import_cyclic_typedefs_does_not_hang() {
    let doc = serde_json::json!({
        "types": [
            { "id": 200, "kind": "typedef", "name": "A", "target": 201 },
            { "id": 201, "kind": "typedef", "name": "B", "target": 200 }
        ]
    });
    let mut m = DataTypeManager::new();
    m.from_json(&doc).unwrap();
    let a = m.find_by_name("A").unwrap();
    assert_eq!(m.size_of(a), Some(0));
}

fn field_offset(m: &DataTypeManager, ty: &str, field: &str) -> Option<usize> {
    match m.get(m.find_by_name(ty)?) {
        Some(DataType::Struct { fields, .. }) => {
            fields.iter().find(|f| f.name == field).map(|f| f.offset)
        }
        _ => None,
    }
}

#[test]
fn win32_archive_is_idempotent_and_arch_aware() {
    let mut m64 = DataTypeManager::new();
    assert!(m64.seed_archive("win32").unwrap() > 0);
    assert_eq!(
        m64.seed_archive("WIN32").unwrap(),
        0,
        "second seed adds nothing"
    );
    assert_eq!(
        field_offset(&m64, "TEB", "ProcessEnvironmentBlock"),
        Some(96)
    );
    assert_eq!(
        m64.size_of(m64.find_by_name("UNICODE_STRING").unwrap()),
        Some(16)
    );
    assert_eq!(
        m64.size_of(m64.find_by_name("LONG").unwrap()),
        Some(4),
        "Windows LONG is 32-bit"
    );

    let mut m32 = DataTypeManager::new();
    m32.set_arch("x86");
    m32.seed_archive("win32").unwrap();
    assert_eq!(
        field_offset(&m32, "TEB", "ProcessEnvironmentBlock"),
        Some(48)
    );
    assert_eq!(
        m32.size_of(m32.find_by_name("UNICODE_STRING").unwrap()),
        Some(8)
    );
    assert_eq!(
        m32.size_of(m32.find_by_name("LIST_ENTRY").unwrap()),
        Some(8)
    );
    assert_eq!(m32.size_of(m32.find_by_name("SIZE_T").unwrap()), Some(4));
}

#[test]
fn crt_archive_follows_long_size() {
    let mut m = DataTypeManager::new();
    m.seed_archive("crt").unwrap();
    assert_eq!(field_offset(&m, "timeval", "tv_usec"), Some(8));
    let mut m32 = DataTypeManager::new();
    m32.set_arch("arm");
    m32.seed_archive("crt").unwrap();
    assert_eq!(field_offset(&m32, "timeval", "tv_usec"), Some(4));
    assert_eq!(m32.size_of(m32.find_by_name("timeval").unwrap()), Some(8));
}

#[test]
fn seed_all_covers_every_archive() {
    let mut m = DataTypeManager::new();
    assert!(m.seed_archive("all").unwrap() > 0);
    let storage = m
        .find_by_name("sockaddr_storage")
        .expect("sockaddr_storage seeded");
    assert_eq!(m.size_of(storage), Some(128));
    assert!(m.find_by_name("GUID").is_some());
    assert!(m.find_by_name("FILE").is_some());
    assert!(m.seed_archive("bogus").is_err());
}
