# data/types — bundled type archives

Versioned, hand-curated C type and function-signature archives for the
decompiler and the analysis pipeline. Both are compiled into the binary with
`include_str!` (see `src/type_system/archive.rs`), so a release never depends
on files in the working directory.

## Layout

```
data/types/win32/typedefs.json   Win32 typedefs (HANDLE, DWORD, LPCWSTR, ...)
data/types/win32/structs.json    Win32 structs and unions (PEB, TEB, UNICODE_STRING, ...)
data/types/win32/enums.json      Win32 flag/value enums
data/types/win32/api-*.json      Win32 import signatures, one file per module
data/types/crt/                  C runtime typedefs, structs and UCRT signatures
data/types/libc/                 POSIX-style typedefs and structs
```

Every file uses the same top-level schema, and the loader merges all files of
one archive:

```json
{
  "schema": 1,
  "archive": "win32",
  "version": "10.0.26100-public",
  "module": "kernel32",
  "typedefs": { "HANDLE": "void *" },
  "structs": { "UNICODE_STRING": { "fields": [
      { "name": "Length", "type": "unsigned short" },
      { "name": "MaximumLength", "type": "unsigned short" },
      { "name": "Buffer", "type": "wchar_t *" } ] } },
  "unions": { "LARGE_INTEGER": { "fields": [
      { "name": "QuadPart", "type": "long long" },
      { "name": "LowPart", "type": "unsigned int", "offset": 0 } ] } },
  "enums": { "FILE_ACCESS_RIGHTS": {
      "underlying": "unsigned int",
      "variants": { "GENERIC_READ": "0x80000000" } } },
  "functions": { "CreateFileW": {
      "ret": "HANDLE",
      "cc": "stdcall",
      "params": [
        { "name": "lpFileName", "type": "LPCWSTR" },
        { "name": "dwDesiredAccess", "type": "DWORD" } ] } }
}
```

Type entries may also be written as `{"to": "..."}` instead of a bare string.

* `offset` is optional. When omitted, layout is computed with the Windows
  default pack (8) and natural alignment for the requested architecture.
* `size` pins an aggregate size (used for opaque/ABI-sized types).
* `pack` caps member alignment.
* `variants.x86` / `variants.x64` override `fields` and `size` per
  architecture; the loader drops the variant that does not match the
  requested architecture.
* `bit_offset` / `bit_width` mark bitfields; `offset` is the storage unit.
* `varargs: true` marks a variadic function.

The loader rejects unknown schema versions, by-value type cycles, overlapping
members, out-of-bounds members, duplicate member names and bitfields that do
not fit their storage unit. Unknown type *references* are tolerated (the name
is kept and reported by `TypeArchive::unknown_types`), and a unit test asserts
that the shipped archives have none.

## Windows data model

All Win32 and CRT data is expressed in the Windows **LLP64** model regardless
of the host: `int` = `long` = 4 bytes, `wchar_t` = 2 bytes, pointers are 4
bytes on x86 and 8 bytes on x64, `long long` = 8 bytes. The archives never
rely on the host `usize`, `long` or `wchar_t`, and the `x86` variants are
layout-checked in unit tests.

## Provenance and licensing

The data is **original to this project** and released under Apache-2.0 with
the rest of the crate. It was written by hand from public, human-readable API
documentation:

* Microsoft Win32 / Windows API reference on `learn.microsoft.com`
  (function prototypes, parameter types, documented structure members).
* The documented `PEB` / `TEB` / `PEB_LDR_DATA` / `LDR_DATA_TABLE_ENTRY` /
  `RTL_USER_PROCESS_PARAMETERS` member lists, re-expressed in this archive's
  own schema.
* The public C standard library and POSIX specifications for the CRT and
  libc archives.

No Microsoft Windows SDK header text is copied or redistributed. No data was
extracted from Ghidra `.gdt` archives, MinGW-w64, Wine or ReactOS, and none of
those projects' files are redistributed here. Ghidra is only used as an
external reference for local parity measurements.

If a third-party type source is ever added, it must be recorded here **and**
in `NOTICE` and `THIRD_PARTY_LICENSES.md`, with its upstream version and
license.
