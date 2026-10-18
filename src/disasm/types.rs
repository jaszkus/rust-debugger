use super::operand_enum;
use std::ops::Deref;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsnBytes([u8; 15], u8);

impl InsnBytes {
    #[inline]
    pub fn from_slice(b: &[u8]) -> Self {
        let mut arr = [0u8; 15];
        let n = b.len().min(15);
        arr[..n].copy_from_slice(&b[..n]);
        InsnBytes(arr, n as u8)
    }
}

impl Deref for InsnBytes {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        &self.0[..self.1 as usize]
    }
}

impl std::fmt::Display for InsnBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.deref() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DisasmInstruction {
    pub address: u64,
    pub bytes: InsnBytes,
    pub mnemonic: &'static str,
    pub operands: operand_enum::OperandList,
}

impl DisasmInstruction {
    #[inline]
    pub fn mnem(&self) -> &str {
        self.mnemonic
    }

    #[inline]
    pub fn ops(&self) -> std::borrow::Cow<'_, str> {
        self.operands.text()
    }

    #[inline]
    pub fn bytes_slice(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone)]
pub struct DisasmResult {
    pub instructions: Arc<Vec<DisasmInstruction>>,
    pub arch: String,
}
