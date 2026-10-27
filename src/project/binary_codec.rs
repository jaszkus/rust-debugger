pub(crate) struct W {
    pub(crate) buf: Vec<u8>,
}

impl W {
    pub(crate) fn new() -> Self {
        W {
            buf: Vec::with_capacity(4 << 20),
        }
    }
    #[inline]
    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    #[inline]
    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    #[inline]
    pub(crate) fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    #[inline]
    pub(crate) fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    #[inline]
    pub(crate) fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    #[inline]
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }
    #[inline]
    pub(crate) fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    #[inline]
    pub(crate) fn opt_u64(&mut self, v: Option<u64>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u64(x);
            }
            None => self.u8(0),
        }
    }
    #[inline]
    pub(crate) fn vec_u64(&mut self, v: &[u64]) {
        self.u32(v.len() as u32);
        for x in v {
            self.u64(*x);
        }
    }
    #[inline]
    pub(crate) fn hashmap_u64_str<S: std::hash::BuildHasher>(
        &mut self,
        m: &std::collections::HashMap<u64, String, S>,
    ) {
        self.u32(m.len() as u32);
        let mut keys: Vec<u64> = m.keys().copied().collect();
        keys.sort_unstable();
        for k in keys {
            self.u64(k);
            self.str(&m[&k]);
        }
    }
}

pub(crate) struct R<'a> {
    pub(crate) buf: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> R<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        R { buf, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err(format!(
                "corrupt project DB (truncated: need {} bytes at {}, have {})",
                n,
                self.pos,
                self.buf.len()
            ));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| "corrupt project DB (truncated: u32)".to_string(),
        )?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(
            |_| "corrupt project DB (truncated: u64)".to_string(),
        )?))
    }
    pub(crate) fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().map_err(
            |_| "corrupt project DB (truncated: i32)".to_string(),
        )?))
    }
    pub(crate) fn i64(&mut self) -> Result<i64, String> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().map_err(
            |_| "corrupt project DB (truncated: i64)".to_string(),
        )?))
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let n = self.u32()? as usize;
        if n > (64 << 20) {
            return Err(format!(
                "corrupt project DB (blob {} bytes exceeds 64MiB limit)",
                n
            ));
        }
        Ok(self.take(n)?.to_vec())
    }
    pub(crate) fn str(&mut self) -> Result<String, String> {
        let b = self.bytes()?;
        String::from_utf8(b).map_err(|_| "corrupt project DB (bad utf8)".to_string())
    }
    pub(crate) fn opt_u64(&mut self) -> Result<Option<u64>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err("corrupt project DB (opt flag)".to_string()),
        }
    }
    pub(crate) fn vec_u64(&mut self) -> Result<Vec<u64>, String> {
        let n = self.u32()? as usize;
        let mut v = Vec::with_capacity(n.min(1 << 23));
        for _ in 0..n {
            v.push(self.u64()?);
        }
        Ok(v)
    }
    pub(crate) fn hashmap_u64_str(&mut self) -> Result<rustc_hash::FxHashMap<u64, String>, String> {
        let n = self.u32()? as usize;
        let mut m = rustc_hash::FxHashMap::with_capacity_and_hasher(
            n.min(1 << 22),
            rustc_hash::FxBuildHasher,
        );
        for _ in 0..n {
            let k = self.u64()?;
            let v = self.str()?;
            m.insert(k, v);
        }
        Ok(m)
    }
}

pub(crate) const T_FUNC_ENTRY: u8 = 0;
pub(crate) const T_FUNC_SYMBOL: u8 = 1;
pub(crate) const T_FUNC_CALL: u8 = 2;
pub(crate) const T_FUNC_PROLOGUE: u8 = 3;
pub(crate) const T_FUNC_AFTER_RET: u8 = 4;
pub(crate) const T_FUNC_UNWIND: u8 = 5;
pub(crate) const T_FUNC_USER: u8 = 6;
pub(crate) const T_FUNC_DATA_PTR: u8 = 7;
pub(crate) const T_FUNC_ADDRESS: u8 = 8;

pub(crate) const T_XREF_CALL: u8 = 0;
pub(crate) const T_XREF_JUMP: u8 = 1;
pub(crate) const T_XREF_READ: u8 = 2;
pub(crate) const T_XREF_WRITE: u8 = 3;
pub(crate) const T_XREF_ADDR: u8 = 4;
pub(crate) const T_XREF_STRING: u8 = 5;
pub(crate) const T_XREF_CALLIND: u8 = 6;
pub(crate) const T_XREF_JMPIND: u8 = 7;
pub(crate) const T_XREF_TAIL: u8 = 8;
pub(crate) const T_XREF_THUNK: u8 = 9;

pub(crate) const T_EDGE_FT: u8 = 0;
pub(crate) const T_EDGE_JMP: u8 = 1;
pub(crate) const T_EDGE_T: u8 = 2;
pub(crate) const T_EDGE_F: u8 = 3;

pub(crate) const T_VAR_LOCAL: u8 = 0;
pub(crate) const T_VAR_PARAM: u8 = 1;
pub(crate) const T_VAR_SAVED: u8 = 2;
pub(crate) const T_VAR_UNKNOWN: u8 = 3;

pub(crate) const T_LINE_SIG: u8 = 0;
pub(crate) const T_LINE_DECL: u8 = 1;
pub(crate) const T_LINE_ASSIGN: u8 = 2;
pub(crate) const T_LINE_CALL: u8 = 3;
pub(crate) const T_LINE_RET: u8 = 4;
pub(crate) const T_LINE_BRANCH: u8 = 5;
pub(crate) const T_LINE_LABEL: u8 = 6;
pub(crate) const T_LINE_COMMENT: u8 = 7;
pub(crate) const T_LINE_OPEN: u8 = 8;
pub(crate) const T_LINE_CLOSE: u8 = 9;

pub(crate) const T_STUB_IMPORT: u8 = 0;
pub(crate) const T_STUB_TAIL: u8 = 1;

pub(crate) const T_RT_PRIM: u8 = 0;
pub(crate) const T_RT_STRUCT: u8 = 1;
pub(crate) const T_RT_ARRAY: u8 = 2;
pub(crate) const T_RT_POINTER: u8 = 3;
pub(crate) const T_RT_ENUM: u8 = 4;

pub(crate) const T_PRIM_BOOL: u8 = 0;
pub(crate) const T_PRIM_CHAR: u8 = 1;
pub(crate) const T_PRIM_UCHAR: u8 = 2;
pub(crate) const T_PRIM_SHORT: u8 = 3;
pub(crate) const T_PRIM_USHORT: u8 = 4;
pub(crate) const T_PRIM_INT: u8 = 5;
pub(crate) const T_PRIM_UINT: u8 = 6;
pub(crate) const T_PRIM_LONG: u8 = 7;
pub(crate) const T_PRIM_ULONG: u8 = 8;
pub(crate) const T_PRIM_LLONG: u8 = 9;
pub(crate) const T_PRIM_ULLONG: u8 = 10;
pub(crate) const T_PRIM_FLOAT: u8 = 11;
pub(crate) const T_PRIM_DOUBLE: u8 = 12;
pub(crate) const T_PRIM_VOID: u8 = 13;
