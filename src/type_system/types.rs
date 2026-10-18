pub type TypeId = u32;

pub const FIRST_USER_TYPE_ID: TypeId = 100;

pub const ID_VOID: TypeId = 0;
pub const ID_BOOL: TypeId = 1;
pub const ID_CHAR: TypeId = 2;
pub const ID_UCHAR: TypeId = 3;
pub const ID_SHORT: TypeId = 4;
pub const ID_USHORT: TypeId = 5;
pub const ID_INT: TypeId = 6;
pub const ID_UINT: TypeId = 7;
pub const ID_LONG: TypeId = 8;
pub const ID_ULONG: TypeId = 9;
pub const ID_LONGLONG: TypeId = 10;
pub const ID_ULONGLONG: TypeId = 11;
pub const ID_FLOAT: TypeId = 12;
pub const ID_DOUBLE: TypeId = 13;
pub const ID_POINTER: TypeId = 14;
pub const ID_STRING: TypeId = 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructField {
    pub name: String,
    pub offset: usize,
    pub type_id: TypeId,
    pub comment: String,
    pub bit_offset: Option<u8>,
    pub bit_width: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
    SystemV,
    Win64,
    Unknown,
}

impl CallingConvention {
    pub fn normalize(s: &str) -> Self {
        match s
            .trim()
            .trim_start_matches('_')
            .to_ascii_lowercase()
            .as_str()
        {
            "cdecl" | "c" | "c-cdecl" => CallingConvention::Cdecl,
            "stdcall" | "winapi" | "api" => CallingConvention::Stdcall,
            "fastcall" => CallingConvention::Fastcall,
            "thiscall" => CallingConvention::Thiscall,
            "vectorcall" => CallingConvention::Vectorcall,
            "systemv" | "sysv" | "system-v" | "sysv-amd64" => CallingConvention::SystemV,
            "win64" | "ms" | "microsoft" | "ms-x64" | "msvc" => CallingConvention::Win64,
            _ => CallingConvention::Unknown,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            CallingConvention::Cdecl => "cdecl",
            CallingConvention::Stdcall => "stdcall",
            CallingConvention::Fastcall => "fastcall",
            CallingConvention::Thiscall => "thiscall",
            CallingConvention::Vectorcall => "vectorcall",
            CallingConvention::SystemV => "sysv",
            CallingConvention::Win64 => "win64",
            CallingConvention::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataType {
    Primitive {
        name: String,
        size: usize,
    },
    Pointer {
        target: TypeId,
    },
    Array {
        element: TypeId,
        count: usize,
    },
    Struct {
        name: String,
        fields: Vec<StructField>,
        packed: bool,
    },
    Union {
        name: String,
        fields: Vec<StructField>,
    },
    Enum {
        name: String,
        underlying: TypeId,
        variants: Vec<(String, i64)>,
    },
    Typedef {
        name: String,
        target: TypeId,
    },
    FunctionSig {
        name: String,
        ret: TypeId,
        params: Vec<(TypeId, String)>,
        calling_convention: String,
        varargs: bool,
    },
    String,
}

impl DataType {
    pub fn own_name(&self) -> Option<&str> {
        match self {
            DataType::Primitive { name, .. }
            | DataType::Struct { name, .. }
            | DataType::Union { name, .. }
            | DataType::Enum { name, .. }
            | DataType::Typedef { name, .. }
            | DataType::FunctionSig { name, .. } => Some(name.as_str()),
            DataType::String => Some("string"),
            DataType::Pointer { .. } | DataType::Array { .. } => None,
        }
    }

    pub fn name_mut(&mut self) -> Option<&mut String> {
        match self {
            DataType::Struct { name, .. }
            | DataType::Union { name, .. }
            | DataType::Enum { name, .. }
            | DataType::Typedef { name, .. }
            | DataType::FunctionSig { name, .. } => Some(name),
            _ => None,
        }
    }

    pub fn is_derived(&self) -> bool {
        matches!(self, DataType::Pointer { .. } | DataType::Array { .. })
    }

    pub fn any_ref(&self, mut pred: impl FnMut(TypeId) -> bool) -> bool {
        match self {
            DataType::Pointer { target } | DataType::Typedef { target, .. } => pred(*target),
            DataType::Array { element, .. } => pred(*element),
            DataType::Struct { fields, .. } | DataType::Union { fields, .. } => {
                fields.iter().any(|f| pred(f.type_id))
            }
            DataType::Enum { underlying, .. } => pred(*underlying),
            DataType::FunctionSig { ret, params, .. } => {
                pred(*ret) || params.iter().any(|(t, _)| pred(*t))
            }
            DataType::Primitive { .. } | DataType::String => false,
        }
    }
}
