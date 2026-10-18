use super::manager::DataTypeManager;
use super::types::{
    TypeId, ID_CHAR, ID_INT, ID_LONG, ID_LONGLONG, ID_POINTER, ID_SHORT, ID_UCHAR, ID_UINT,
    ID_ULONGLONG, ID_USHORT,
};

type FieldSpec<'a> = (&'a str, TypeId, usize);

impl DataTypeManager {
    pub const ARCHIVES: &'static [&'static str] = &["win32", "crt", "libc"];

    #[allow(dead_code)]
    pub fn list_archives() -> &'static [&'static str] {
        Self::ARCHIVES
    }

    pub fn seed_archive(&mut self, archive: &str) -> Result<usize, String> {
        match archive.trim().to_ascii_lowercase().as_str() {
            "win32" => self.seed_win32(),
            "crt" => self.seed_crt(),
            "libc" => self.seed_libc(),
            "all" => Ok(self.seed_win32()? + self.seed_crt()? + self.seed_libc()?),
            other => Err(format!(
                "Unknown archive '{}' (want one of: win32, crt, libc, all)",
                other
            )),
        }
    }

    fn ensure_typedefs(&mut self, defs: &[(&str, TypeId)]) -> usize {
        let mut added = 0usize;
        for &(name, target) in defs {
            if self.find_by_name(name).is_none() && self.create_typedef(name, target).is_ok() {
                added += 1;
            }
        }
        added
    }

    fn ensure_aggregate(
        &mut self,
        name: &str,
        is_union: bool,
        fields: &[FieldSpec],
    ) -> Result<usize, String> {
        if self.find_by_name(name).is_some() {
            return Ok(0);
        }
        let created = if is_union {
            self.create_union(name)
        } else {
            self.create_struct(name)
        };
        let id = created?;
        for &(fname, ftype, off) in fields {
            if let Err(e) = self.add_field(id, fname, ftype, Some(off), "") {
                let _ = self.delete(id);
                return Err(format!("Failed to seed {}.{}: {}", name, fname, e));
            }
        }
        Ok(1)
    }

    fn seed_win32(&mut self) -> Result<usize, String> {
        let ps = self.pointer_size;
        let (uptr, iptr) = if ps == 4 {
            (ID_UINT, ID_INT)
        } else {
            (ID_ULONGLONG, ID_LONGLONG)
        };
        let char_ptr = self.create_pointer(ID_CHAR)?;
        let wchar_ptr = self.create_pointer(ID_USHORT)?;
        let u8x8 = self.create_array(ID_UCHAR, 8)?;

        let mut added = self.ensure_typedefs(&[
            ("BYTE", ID_UCHAR),
            ("UCHAR", ID_UCHAR),
            ("CHAR", ID_CHAR),
            ("WORD", ID_USHORT),
            ("USHORT", ID_USHORT),
            ("ATOM", ID_USHORT),
            ("WCHAR", ID_USHORT),
            ("SHORT", ID_SHORT),
            ("DWORD", ID_UINT),
            ("UINT", ID_UINT),
            ("UINT32", ID_UINT),
            ("ULONG", ID_UINT),
            ("BOOL", ID_INT),
            ("LONG", ID_INT),
            ("INT32", ID_INT),
            ("HRESULT", ID_INT),
            ("NTSTATUS", ID_INT),
            ("QWORD", ID_ULONGLONG),
            ("UINT64", ID_ULONGLONG),
            ("ULONGLONG", ID_ULONGLONG),
            ("DWORD64", ID_ULONGLONG),
            ("INT64", ID_LONGLONG),
            ("LONGLONG", ID_LONGLONG),
            ("HANDLE", ID_POINTER),
            ("HWND", ID_POINTER),
            ("HMODULE", ID_POINTER),
            ("HINSTANCE", ID_POINTER),
            ("LPVOID", ID_POINTER),
            ("LPCVOID", ID_POINTER),
            ("PVOID", ID_POINTER),
            ("SIZE_T", uptr),
            ("DWORD_PTR", uptr),
            ("ULONG_PTR", uptr),
            ("UINT_PTR", uptr),
            ("WPARAM", uptr),
            ("SSIZE_T", iptr),
            ("LONG_PTR", iptr),
            ("INT_PTR", iptr),
            ("LPARAM", iptr),
            ("LRESULT", iptr),
        ]);
        added += self.ensure_typedefs(&[
            ("LPSTR", char_ptr),
            ("LPCSTR", char_ptr),
            ("PSTR", char_ptr),
            ("PCSTR", char_ptr),
            ("LPWSTR", wchar_ptr),
            ("LPCWSTR", wchar_ptr),
            ("PWSTR", wchar_ptr),
            ("PCWSTR", wchar_ptr),
        ]);
        added += self.ensure_aggregate(
            "GUID",
            false,
            &[
                ("Data1", ID_UINT, 0),
                ("Data2", ID_USHORT, 4),
                ("Data3", ID_USHORT, 6),
                ("Data4", u8x8, 8),
            ],
        )?;
        added += self.ensure_aggregate(
            "FILETIME",
            false,
            &[
                ("dwLowDateTime", ID_UINT, 0),
                ("dwHighDateTime", ID_UINT, 4),
            ],
        )?;
        added += self.ensure_aggregate(
            "SYSTEMTIME",
            false,
            &[
                ("wYear", ID_USHORT, 0),
                ("wMonth", ID_USHORT, 2),
                ("wDayOfWeek", ID_USHORT, 4),
                ("wDay", ID_USHORT, 6),
                ("wHour", ID_USHORT, 8),
                ("wMinute", ID_USHORT, 10),
                ("wSecond", ID_USHORT, 12),
                ("wMilliseconds", ID_USHORT, 14),
            ],
        )?;
        added += self.ensure_aggregate("POINT", false, &[("x", ID_INT, 0), ("y", ID_INT, 4)])?;
        added += self.ensure_aggregate(
            "RECT",
            false,
            &[
                ("left", ID_INT, 0),
                ("top", ID_INT, 4),
                ("right", ID_INT, 8),
                ("bottom", ID_INT, 12),
            ],
        )?;
        added +=
            self.ensure_aggregate("COORD", false, &[("X", ID_SHORT, 0), ("Y", ID_SHORT, 2)])?;
        added += self.ensure_aggregate(
            "SMALL_RECT",
            false,
            &[
                ("Left", ID_SHORT, 0),
                ("Top", ID_SHORT, 2),
                ("Right", ID_SHORT, 4),
                ("Bottom", ID_SHORT, 6),
            ],
        )?;
        added += self.ensure_aggregate(
            "LARGE_INTEGER",
            true,
            &[
                ("QuadPart", ID_LONGLONG, 0),
                ("LowPart", ID_UINT, 0),
                ("HighPart", ID_INT, 4),
            ],
        )?;
        added += self.ensure_aggregate(
            "UNICODE_STRING",
            false,
            &[
                ("Length", ID_USHORT, 0),
                ("MaximumLength", ID_USHORT, 2),
                ("Buffer", wchar_ptr, ps),
            ],
        )?;
        added += self.ensure_aggregate(
            "LIST_ENTRY",
            false,
            &[("Flink", ID_POINTER, 0), ("Blink", ID_POINTER, ps)],
        )?;
        added += self.ensure_aggregate(
            "PEB",
            false,
            &[
                ("InheritedAddressSpace", ID_UCHAR, 0),
                ("BeingDebugged", ID_UCHAR, 2),
                ("Mutant", ID_POINTER, ps),
                ("ImageBaseAddress", ID_POINTER, ps * 2),
                ("Ldr", ID_POINTER, ps * 3),
            ],
        )?;
        added += self.ensure_aggregate(
            "TEB",
            false,
            &[
                ("NtTib_ExceptionList", ID_POINTER, 0),
                ("NtTib_StackBase", ID_POINTER, ps),
                ("ProcessEnvironmentBlock", ID_POINTER, ps * 12),
            ],
        )?;
        Ok(added)
    }

    fn seed_crt(&mut self) -> Result<usize, String> {
        let ps = self.pointer_size;
        let (uptr, iptr) = if ps == 4 {
            (ID_UINT, ID_INT)
        } else {
            (ID_ULONGLONG, ID_LONGLONG)
        };
        let mut added = self.ensure_typedefs(&[
            ("time_t", ID_LONGLONG),
            ("clock_t", ID_LONGLONG),
            ("size_t", uptr),
            ("ptrdiff_t", iptr),
            ("intptr_t", iptr),
            ("uintptr_t", uptr),
        ]);
        let long_sz = self.size_of(ID_LONG).unwrap_or(8);
        added +=
            self.ensure_aggregate("div_t", false, &[("quot", ID_INT, 0), ("rem", ID_INT, 4)])?;
        added += self.ensure_aggregate(
            "ldiv_t",
            false,
            &[("quot", ID_LONG, 0), ("rem", ID_LONG, long_sz)],
        )?;
        added += self.ensure_aggregate(
            "tm",
            false,
            &[
                ("tm_sec", ID_INT, 0),
                ("tm_min", ID_INT, 4),
                ("tm_hour", ID_INT, 8),
                ("tm_mday", ID_INT, 12),
                ("tm_mon", ID_INT, 16),
                ("tm_year", ID_INT, 20),
                ("tm_wday", ID_INT, 24),
                ("tm_yday", ID_INT, 28),
                ("tm_isdst", ID_INT, 32),
            ],
        )?;
        added += self.ensure_aggregate(
            "timeval",
            false,
            &[("tv_sec", ID_LONG, 0), ("tv_usec", ID_LONG, long_sz)],
        )?;
        added += self.ensure_aggregate(
            "timespec",
            false,
            &[("tv_sec", ID_LONG, 0), ("tv_nsec", ID_LONG, long_sz)],
        )?;
        added += self.ensure_aggregate("FILE", false, &[])?;
        Ok(added)
    }

    fn seed_libc(&mut self) -> Result<usize, String> {
        let mut added = self.ensure_typedefs(&[
            ("pid_t", ID_INT),
            ("uid_t", ID_UINT),
            ("gid_t", ID_UINT),
            ("off_t", ID_LONGLONG),
            ("mode_t", ID_UINT),
            ("socklen_t", ID_UINT),
            ("in_addr_t", ID_UINT),
            ("in_port_t", ID_USHORT),
            ("sa_family_t", ID_USHORT),
        ]);
        let u8x8 = self.create_array(ID_UCHAR, 8)?;
        let u8x16 = self.create_array(ID_UCHAR, 16)?;
        let u8x118 = self.create_array(ID_UCHAR, 118)?;
        let long_sz = self.size_of(ID_LONG).unwrap_or(8);

        added += self.ensure_aggregate("in_addr", false, &[("s_addr", ID_UINT, 0)])?;
        added += self.ensure_aggregate(
            "sockaddr_in",
            false,
            &[
                ("sin_family", ID_USHORT, 0),
                ("sin_port", ID_USHORT, 2),
                ("sin_addr", ID_UINT, 4),
                ("sin_zero", u8x8, 8),
            ],
        )?;
        added += self.ensure_aggregate(
            "pollfd",
            false,
            &[
                ("fd", ID_INT, 0),
                ("events", ID_SHORT, 4),
                ("revents", ID_SHORT, 6),
            ],
        )?;
        added += self.ensure_aggregate(
            "stat_timespec",
            false,
            &[("tv_sec", ID_LONG, 0), ("tv_nsec", ID_LONG, long_sz)],
        )?;
        added += self.ensure_aggregate("in6_addr", false, &[("s6_addr", u8x16, 0)])?;
        if self.find_by_name("sockaddr_in6").is_none() {
            let in6 = self
                .find_by_name("in6_addr")
                .ok_or("missing in6_addr".to_string())?;
            added += self.ensure_aggregate(
                "sockaddr_in6",
                false,
                &[
                    ("sin6_family", ID_USHORT, 0),
                    ("sin6_port", ID_USHORT, 2),
                    ("sin6_flowinfo", ID_UINT, 4),
                    ("sin6_addr", in6, 8),
                ],
            )?;
        }
        added += self.ensure_aggregate(
            "sockaddr_storage",
            false,
            &[
                ("ss_family", ID_USHORT, 0),
                ("__ss_padding", u8x118, 2),
                ("__ss_align", ID_ULONGLONG, 120),
            ],
        )?;
        added += self.ensure_aggregate(
            "stat",
            false,
            &[
                ("st_dev", ID_ULONGLONG, 0),
                ("st_ino", ID_ULONGLONG, 8),
                ("st_mode", ID_UINT, 24),
                ("st_size", ID_LONGLONG, 48),
            ],
        )?;
        Ok(added)
    }
}
