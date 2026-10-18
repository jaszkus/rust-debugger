use super::manager::DataTypeManager;
use super::types::{DataType, StructField, TypeId, FIRST_USER_TYPE_ID, ID_INT, ID_VOID};
use serde_json::{json, Value};
use std::collections::HashMap;

fn kind_of(e: &Value) -> &str {
    e.get("kind").and_then(Value::as_str).unwrap_or("")
}

fn json_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

fn json_id(v: &Value, key: &str) -> Option<TypeId> {
    json_u64(v, key)
        .filter(|&n| n <= TypeId::MAX as u64)
        .map(|n| n as TypeId)
}

fn json_u8(v: &Value, key: &str) -> Option<u8> {
    json_u64(v, key)
        .filter(|&n| n <= u8::MAX as u64)
        .map(|n| n as u8)
}

fn entry_id(idx: usize, e: &Value) -> TypeId {
    json_id(e, "id").unwrap_or_else(|| TypeId::MAX.wrapping_sub(idx as TypeId))
}

fn import_name(raw: &str) -> String {
    if raw.trim().is_empty() {
        return "unnamed".to_string();
    }
    let mut name = raw.to_string();
    while name.ends_with('*') || name.ends_with(']') {
        name.pop();
        name.push('_');
    }
    name
}

fn fields_to_json(fields: &[StructField]) -> Vec<Value> {
    fields
        .iter()
        .map(|f| {
            json!({
                "name": f.name, "offset": f.offset, "type_id": f.type_id, "comment": f.comment,
                "bit_offset": f.bit_offset, "bit_width": f.bit_width,
            })
        })
        .collect()
}

impl DataTypeManager {
    pub fn to_json(&self) -> Value {
        let types: Vec<Value> = self
            .all()
            .into_iter()
            .map(|(id, dt)| {
                let mut v = json!({ "id": id, "name": self.type_name(id) });
                match dt {
                    DataType::Primitive { size, .. } => {
                        v["kind"] = json!("primitive");
                        v["size"] = json!(size);
                    }
                    DataType::Pointer { target } => {
                        v["kind"] = json!("pointer");
                        v["target"] = json!(target);
                    }
                    DataType::Array { element, count } => {
                        v["kind"] = json!("array");
                        v["element"] = json!(element);
                        v["count"] = json!(count);
                    }
                    DataType::Struct { fields, packed, .. } => {
                        v["kind"] = json!("struct");
                        v["packed"] = json!(packed);
                        v["fields"] = Value::Array(fields_to_json(fields));
                    }
                    DataType::Union { fields, .. } => {
                        v["kind"] = json!("union");
                        v["fields"] = Value::Array(fields_to_json(fields));
                    }
                    DataType::Enum {
                        underlying,
                        variants,
                        ..
                    } => {
                        v["kind"] = json!("enum");
                        v["underlying"] = json!(underlying);
                        v["variants"] = json!(variants
                            .iter()
                            .map(|(n, val)| json!({ "name": n, "value": val }))
                            .collect::<Vec<_>>());
                    }
                    DataType::Typedef { target, .. } => {
                        v["kind"] = json!("typedef");
                        v["target"] = json!(target);
                    }
                    DataType::FunctionSig {
                        ret,
                        params,
                        calling_convention,
                        varargs,
                        ..
                    } => {
                        v["kind"] = json!("function");
                        v["ret"] = json!(ret);
                        v["calling_convention"] = json!(calling_convention);
                        v["varargs"] = json!(varargs);
                        v["params"] = json!(params
                            .iter()
                            .map(|(t, n)| json!({ "type_id": t, "name": n }))
                            .collect::<Vec<_>>());
                    }
                    DataType::String => {
                        v["kind"] = json!("string");
                    }
                }
                v
            })
            .collect();
        json!({ "types": types, "pointer_size": self.pointer_size })
    }

    fn remap_ref(&self, id_map: &HashMap<TypeId, TypeId>, old: TypeId) -> Option<TypeId> {
        if let Some(&new) = id_map.get(&old) {
            return Some(new);
        }
        if old < FIRST_USER_TYPE_ID && self.types.contains_key(&old) {
            Some(old)
        } else {
            None
        }
    }

    fn import_field(&mut self, id_map: &HashMap<TypeId, TypeId>, owner: TypeId, f: &Value) {
        let fname = f.get("name").and_then(Value::as_str).unwrap_or("field");
        let ft_old = json_id(f, "type_id").unwrap_or(ID_INT);
        let ft = match self.remap_ref(id_map, ft_old) {
            Some(t) => t,
            None => return,
        };
        let off = json_u64(f, "offset").map(|v| v as usize);
        let comment = f.get("comment").and_then(Value::as_str).unwrap_or("");
        match (json_u8(f, "bit_width"), off) {
            (Some(w), Some(o)) => {
                let bit_offset = json_u8(f, "bit_offset").unwrap_or(0);
                let _ = self.add_bitfield(owner, fname, ft, o, bit_offset, w);
            }
            _ => {
                let _ = self.add_field(owner, fname, ft, off, comment);
            }
        }
    }

    pub fn from_json(&mut self, doc: &Value) -> Result<(), String> {
        if let Some(ps) = json_u64(doc, "pointer_size") {
            let _ = self.set_pointer_size(ps as usize);
        }
        let arr = doc
            .get("types")
            .and_then(|v| v.as_array())
            .ok_or("missing 'types' array")?;
        let mut id_map: HashMap<TypeId, TypeId> = HashMap::with_capacity(arr.len());

        for (idx, e) in arr.iter().enumerate() {
            let kind = kind_of(e);
            if !matches!(kind, "struct" | "union" | "enum" | "typedef" | "function") {
                continue;
            }
            let old_id = entry_id(idx, e);
            let name = import_name(e.get("name").and_then(Value::as_str).unwrap_or(""));
            let unique = self.unique_name(&name);
            let created: Option<TypeId> = match kind {
                "struct" => {
                    let id = self.create_struct(&unique).ok();
                    if let Some(id) = id
                        && e.get("packed").and_then(Value::as_bool) == Some(true) {
                            let _ = self.set_packed(id, true);
                        }
                    id
                }
                "union" => self.create_union(&unique).ok(),
                "enum" => self.create_enum(&unique, ID_INT).ok(),
                "typedef" => self.create_typedef(&unique, ID_VOID).ok(),
                _ => {
                    let cc = e
                        .get("calling_convention")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let varargs = e.get("varargs").and_then(Value::as_bool).unwrap_or(false);
                    self.create_function_sig(&unique, ID_VOID, Vec::new(), cc, varargs)
                        .ok()
                }
            };
            if let Some(id) = created {
                id_map.insert(old_id, id);
            }
        }

        let mut pending: Vec<(TypeId, &Value)> = arr
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(kind_of(e), "pointer" | "array"))
            .map(|(i, e)| (entry_id(i, e), e))
            .collect();
        while !pending.is_empty() {
            let before = pending.len();
            let mut unresolved: Vec<(TypeId, &Value)> = Vec::new();
            for (old_id, e) in pending {
                let attempt = if kind_of(e) == "pointer" {
                    let target = json_id(e, "target").unwrap_or(ID_VOID);
                    self.remap_ref(&id_map, target)
                        .map(|t| self.create_pointer(t))
                } else {
                    let element = json_id(e, "element").unwrap_or(ID_INT);
                    let count = json_u64(e, "count").map(|c| c as usize).unwrap_or(1);
                    self.remap_ref(&id_map, element)
                        .map(|t| self.create_array(t, count))
                };
                match attempt {
                    Some(Ok(id)) => {
                        id_map.insert(old_id, id);
                    }
                    Some(Err(_)) => {}
                    None => unresolved.push((old_id, e)),
                }
            }
            if unresolved.len() == before {
                break;
            }
            pending = unresolved;
        }

        for (idx, e) in arr.iter().enumerate() {
            let new_id = match id_map.get(&entry_id(idx, e)) {
                Some(&n) => n,
                None => continue,
            };
            match kind_of(e) {
                "struct" | "union" => {
                    if let Some(fields) = e.get("fields").and_then(Value::as_array) {
                        for f in fields {
                            self.import_field(&id_map, new_id, f);
                        }
                    }
                }
                "typedef" => {
                    if let Some(t) = json_id(e, "target").and_then(|t| self.remap_ref(&id_map, t))
                        && !self.embeds(t, new_id)
                            && let Some(DataType::Typedef { target, .. }) =
                                self.types.get_mut(&new_id)
                            {
                                *target = t;
                            }
                }
                "enum" => {
                    if let Some(u) =
                        json_id(e, "underlying").and_then(|u| self.remap_ref(&id_map, u))
                        && !self.embeds(u, new_id)
                            && let Some(DataType::Enum { underlying, .. }) =
                                self.types.get_mut(&new_id)
                            {
                                *underlying = u;
                            }
                    if let Some(variants) = e.get("variants").and_then(Value::as_array) {
                        for v in variants {
                            let vname = v.get("name").and_then(Value::as_str).unwrap_or("");
                            let val = v.get("value").and_then(Value::as_i64).unwrap_or(0);
                            let _ = self.add_enum_variant(new_id, vname, val);
                        }
                    }
                }
                "function" => {
                    let ret = json_id(e, "ret")
                        .and_then(|r| self.remap_ref(&id_map, r))
                        .unwrap_or(ID_VOID);
                    let mut list: Vec<(TypeId, String)> = Vec::new();
                    if let Some(params) = e.get("params").and_then(Value::as_array) {
                        for p in params {
                            let pt = json_id(p, "type_id")
                                .and_then(|t| self.remap_ref(&id_map, t))
                                .unwrap_or(ID_VOID);
                            let pn = p
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            list.push((pt, pn));
                        }
                    }
                    if let Some(DataType::FunctionSig {
                        ret: r, params: p, ..
                    }) = self.types.get_mut(&new_id)
                    {
                        *r = ret;
                        *p = list;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
