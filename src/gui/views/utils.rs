use crate::gui::state::{BookmarkKind, CommentKind};

#[derive(Debug, Clone, Copy)]
pub enum CtxAction {
    Select,
    ToggleBp,
    Comment,
    Bookmark,
    Rename,
    Goto,
}
pub const COMMENT_KINDS: &[CommentKind] = &[
    CommentKind::Eol,
    CommentKind::Pre,
    CommentKind::Post,
    CommentKind::Plate,
    CommentKind::Repeatable,
];
pub const BOOKMARK_KINDS: &[BookmarkKind] = &[
    BookmarkKind::Note,
    BookmarkKind::Info,
    BookmarkKind::Error,
    BookmarkKind::Analysis,
];
pub fn comment_kind_idx(i: usize) -> CommentKind {
    COMMENT_KINDS[i.min(COMMENT_KINDS.len() - 1)]
}
pub fn bookmark_kind_idx(i: usize) -> BookmarkKind {
    BOOKMARK_KINDS[i.min(BOOKMARK_KINDS.len() - 1)]
}
pub fn parse_addr_str(s: &str) -> Option<u64> {
    let s = s.trim();
    u64::from_str_radix(
        s.strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s),
        16,
    )
    .ok()
}
pub fn first_addr_in_operands(ops: &str) -> Option<u64> {
    let bytes = ops.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        if bytes[i] == b'0' && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            let start = i + 2;
            let mut j = start;
            while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                j += 1;
            }
            if j > start {
                if let Ok(v) = u64::from_str_radix(&ops[start..j], 16) {
                    return Some(v);
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
    parse_addr_str(ops)
}
pub fn escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
pub fn contains_ci(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    n.is_empty()
        || (h.len() >= n.len()
            && h.windows(n.len())
                .any(|w| w.iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b)))
}
