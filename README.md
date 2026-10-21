<div align="center">

<!--
  Logo: uncomment once the icon is final.
  <img src="assets/icon.png" alt="Rust Debugger logo" width="120" />
-->

# Rust Debugger

### Binary analysis and reverse engineering, written in Rust

Static analysis, pcode decompilation, live debugging and an x86-64 emulator<br/>
in one fast, self-contained workbench, with a GPU-accelerated GUI<br/>
and an MCP server for AI agents.


<br/>

[![License](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2024%20edition-orange?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-informational?style=flat-square)](#requirements)
[![MCP](https://img.shields.io/badge/MCP-200%2B%20tools-8A2BE2?style=flat-square)](#mcp-server)
![Version](https://img.shields.io/badge/version-0.8.0-yellow?style=flat-square)

[![Stars](https://img.shields.io/github/stars/jaszkus/rust-debugger?style=flat-square&logo=github)](https://github.com/jaszkus/rust-debugger/stargazers)
[![Issues](https://img.shields.io/github/issues/jaszkus/rust-debugger?style=flat-square)](https://github.com/jaszkus/rust-debugger/issues)
[![Last commit](https://img.shields.io/github/last-commit/jaszkus/rust-debugger?style=flat-square)](https://github.com/jaszkus/rust-debugger/commits)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](#contributing)

<br/>

[**Overview**](#overview) &nbsp;·&nbsp;
[**Features**](#features) &nbsp;·&nbsp;
[**Quick start**](#quick-start) &nbsp;·&nbsp;
[**Command line**](#command-line) &nbsp;·&nbsp;
[**MCP server**](#mcp-server) &nbsp;·&nbsp;
[**Architecture**](#architecture) &nbsp;·&nbsp;
[**Contributing**](#contributing)

</div>

<br/>

> [!WARNING]
> **Under active development (`0.8.0`).** Features, APIs and project-file formats may change between releases.
> **I'm actively looking for contributors.** See [Contributing](#contributing).

<!--
  Add a screenshot or GIF here. It is the single biggest boost for a README.

  <p align="center">
    <img src="docs/screenshots/main.png" alt="Rust Debugger GUI" width="900" />
  </p>
-->

## Overview

Rust Debugger brings the core of a classic reverse engineering suite into a single native binary: loader,
disassembler, analyzer, decompiler, emulator and debugger. Use it from the GPU-accelerated GUI, from the
command line, or remotely from AI agents over MCP.

<img width="1920" height="1005" alt="image" src="https://github.com/user-attachments/assets/912448e6-61ed-47f0-9deb-3db68ccb8056" />
<img width="1920" height="1005" alt="image" src="https://github.com/user-attachments/assets/20064bb2-0a13-4edd-8cdc-94a64bb22f35" />
<img width="1920" height="1005" alt="image" src="https://github.com/user-attachments/assets/51c79841-e68a-485a-bfe6-d22db69b46c6" />


| Highlight | Details |
| --- | --- |
| **All-in-one** | Loader, disassembler, analyzer, decompiler, emulator and debugger in a single native binary. |
| **Fast and headless-friendly** | Batch `--analyze` and `--serve` modes need no GPU. Analysis results are cached in compressed project files. |
| **Modern GUI** | GPU-accelerated front-end built on `iced` / `wgpu` (Vulkan, DX12 or Metal). |
| **Static and dynamic** | Move from disassembly to decompiled C-like code, then step through it live or dry-run it in the emulator. |

### At a glance

| Formats | Architectures | Debugging | Platforms | MCP tools |
| :---: | :---: | :---: | :---: | :---: |
| PE, ELF, Mach-O, .NET, minidump, map | x86, x86-64, ARM64 | Win32 Debug API, `ptrace` | Windows, Linux | **200+** |

## Features

### Parsing and loading

- **PE, ELF and Mach-O** executables, **.NET** assemblies (CLR metadata), **minidumps** and linker **map files**
- **DWARF** (via `gimli`) and **PDB** debug information
- C++ and Rust symbol **demangling**
- RTTI scan, resources, imports, exports and sections

### Disassembly

- **x86 / x86-64** via [`iced-x86`](https://github.com/icedland/iced)
- **ARM64** via [`yaxpeax-arm`](https://github.com/iximeow/yaxpeax-arm)
- Built-in **x86 assembler / encoder** used for patching

### Analysis pipeline

- Function detection (entry points, thunks, call and jump targets) and **FID signatures**
- **CFG** construction, constant propagation, noreturn inference, stack / unwind analysis and variable recovery
- Cross-references, import xrefs and **string extraction** with an n-gram classification model
- Detection passes for **packers, anti-debug, obfuscation and crypto**, plus .NET, Go and Objective-C

### Decompiler

- x86-64 to **pcode** lifting
- Mini-**SSA** expression trees
- **C-like** output with recovered variables
- Real **PDB / DWARF** signatures, local variables, call arguments and struct member names
- **SSE / xmm** arguments, enums, bitfields, stack-canary cleanup and terminal CFG region cloning

### Emulation and live debugging

- **x86-64 emulator** (ALU, flags, memory) for deobfuscation and dry-running functions
- Live debugging through the **Windows Debug API** and Linux **`ptrace`**
- Breakpoints, stepping, registers and memory, threads, stack traces and **recorded traces**

### Patching and projects

- Byte and **branch patching** with history and rebuild-after-patch
- **RDDB v9** project files: zstd-compressed analysis cache plus annotations

### GUI

The GUI ships with 15 views: Listing, Hex, Decompiler, Pcode, CFG, Xrefs, Strings, Symbols, Stack, Sections,
Imports, Resources, Patches, Debug and Live.

## Requirements

- **Rust** stable toolchain (edition 2024, rustc 1.88 or newer)
- **Windows 10+** or **Linux** (Wayland or X11)
- A GPU with **Vulkan, DX12 or Metal** support, for the GUI only

> [!TIP]
> Headless `--serve` and `--analyze` runs need **no GPU**, which makes them a good fit for servers, CI and containers.

## Quick start

```sh
git clone https://github.com/jaszkus/rust-debugger.git
cd rust-debugger
cargo build --release
```

The binary is placed in `target/release/rust-debugger` (`rust-debugger.exe` on Windows).

```sh
rust-debugger                        # open an empty workbench
rust-debugger sample.exe             # open a binary straight away
rust-debugger --analyze sample.exe   # headless batch analysis, prints a JSON summary
rust-debugger --serve 7777           # headless MCP server for AI agents
```

## Command line

| Command | Description |
| --- | --- |
| `rust-debugger [file]` | Launch the GUI, optionally preloading a file. |
| `rust-debugger --serve [port] [file]` | Start the headless MCP server (alias `--headless`). The default port is `7777`; `0` picks a free port. |
| `rust-debugger --analyze <file> [--fresh]` | Parse, disassemble and analyze in batch mode, then print a JSON summary. Results are cached in RDDB; `--fresh` ignores the cache. |
| `rust-debugger --bench <file> [--parse-only]` | Time the parse, disassembly and analysis phases. |
| `rust-debugger --version`, `--help` | Print the version or the usage text. |

<details>
<summary><b>Environment variables and exit codes</b></summary>

<br/>

| Variable | Purpose |
| --- | --- |
| `RD_MAX_DECOMP` | `--analyze` sets it to `0` unless it is already set. |
| `RUST_DEBUGGER_TOKEN` | Enables bearer-token authentication for the MCP server. |

| Exit code | Meaning |
| :---: | --- |
| `0` | Success |
| `1` | Runtime failure |
| `2` | Usage error |

</details>

## MCP server

Rust Debugger speaks **JSON-RPC over HTTP** on `127.0.0.1` and exposes **200+ MCP tool names**.

```sh
rust-debugger --serve 7777                         # endpoint: http://127.0.0.1:7777/mcp
RUST_DEBUGGER_TOKEN=secret rust-debugger --serve   # require a bearer token
```

> [!NOTE]
> The server listens on **localhost only**. Set `RUST_DEBUGGER_TOKEN` if other users or processes share the machine.

### Client configuration

Example for `opencode.json`, or any MCP client that supports remote servers:

```json
{
  "mcp": {
    "rust-debugger": {
      "type": "remote",
      "url": "http://127.0.0.1:7777/mcp",
      "headers": {
        "Authorization": "Bearer ${RUST_DEBUGGER_TOKEN}"
      }
    }
  }
}
```

### Full tool reference

The server exposes **237 tools** in 15 groups. Clients can discover them at runtime with `search_tools` (search by keyword or category; an empty query lists the categories) and run long scans in the background with `run_async` and `poll_job`.

| Group | Tools | Covers |
| --- | :---: | --- |
| **Programs and analysis** | 18 | Loading and saving binaries, multi-program sessions, running and monitoring auto-analysis. |
| **Functions** | 22 | Lookup, search, summaries, hashing, similarity, renaming, thunks and FunctionID signatures. |
| **Disassembly and decompilation** | 11 | Listings, pseudocode, pcode and instruction pattern search. |
| **Cross-references and control flow** | 23 | Xrefs, call graph and call trees, basic blocks, import usage and user-defined references. |
| **Symbols and structure** | 13 | Imports, exports, symbols, sections, relocations, globals, C++ namespaces, classes and RTTI. |
| **Memory, strings and data** | 17 | Raw reads, strings, byte search, data items, memory dumps and code gaps. |
| **Data types** | 25 | Structs, unions, enums, typedefs, type archives and DWARF / PDB import. |
| **Annotations and tagging** | 18 | Comments, bookmarks, labels, function tags, undo / redo and the agent plan. |
| **Protection and malware triage** | 10 | Packer, anti-debug, anti-VM, obfuscation and crypto detection, entropy and XOR loops. |
| **PE and .NET** | 8 | PE header details, CLR metadata, types, methods and metadata tokens. |
| **Patching and assembler** | 31 | Byte, instruction and branch patches, patch history and export, built-in assembler. |
| **Debugger control** | 20 | Start, attach, step, breakpoints, hardware breakpoints and exception policy. |
| **Process memory** | 8 | Read, write, search and dump live memory; modules, threads and memory regions. |
| **Tracing and emulation** | 6 | Single-step trace recording and replay, plus p-code emulation of functions. |
| **Server and utilities** | 7 | Tool discovery, health checks, integer conversion and background jobs. |

Expand a group for the full list of tools and their descriptions.

<details>
<summary><b>Programs and analysis</b> (18 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `get_metadata` | Get binary metadata: format, arch, entry point, file path |
| `get_current_program_info` | Get current program info: name, path, language, image base, entry point, counts |
| `get_binary_overview` | One-shot binary overview: format, arch, entry, sections, import summary, exports, function count, protection report counts. Replaces 5+ separate calls. |
| `get_entry_points` | List binary entry point addresses |
| `get_function_count` | Return total number of detected functions |
| `run_analysis` | Run auto-analysis and WAIT for the fresh result (blocking; timeout_ms default 600000, 5000..3600000). Use reanalyze for the old fire-and-forget queue. |
| `reanalyze` | Trigger full auto-analysis (alias of run_analysis) |
| `get_analysis_status` | Get current analysis progress / status |
| `cancel_analysis` | Cancel a stuck analysis run and free the progress slot. The background thread silently discards its result. |
| `load_binary` | Parse and load a PE/ELF/Mach-O file from disk as the current binary |
| `import_file` | Import a binary file from disk and load it (alias of load_binary) |
| `load_memory_dump` | Load a raw memory dump file as a new binary (replaces current) |
| `load_map_file` | Import symbols from an MSVC .map file into the loaded binary (args: path, optional base_offset hex added to every address) |
| `save_program` | Write the (possibly patched) binary to a file |
| `open_program` | Open a binary from disk as a new program (saves the current one as a slot) |
| `close_program` | Close an open program by name (switches away if it's the current one) |
| `list_open_programs` | List all open programs (multi-program model) |
| `switch_program` | Switch the current program to an already-open one (by name) |

</details>

<details>
<summary><b>Functions</b> (22 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `list_functions` | List functions paginated with optional filter (name or hex address, '0x' optional). limit 1..1000: above is clamped (see 'warnings'), below is rejected |
| `lookup_function` | Lookup a function by address (hex) or name |
| `get_function_at` | Find function containing the given address |
| `search_functions` | Search functions by name substring or hex address |
| `search_functions_enhanced` | Advanced function search: name + size range + caller/callee counts |
| `get_function_summary` | Comprehensive one-shot summary of a function: signature, callers/callees, used imports, used strings, preview |
| `get_function_signature` | Get first N bytes of a function as a signature + FNV-1a hash |
| `get_function_hash` | Get dual FNV-1a hashes (full masked + value-sensitive specific) of a function body |
| `find_similar_functions` | Find groups of functions with identical masked code shape |
| `diff_functions` | Diff two functions by normalized mnemonic sequence |
| `rename_function` | Rename a detected function |
| `create_function` | Define a function at an address (Ghidra createFunction; UserDefined source, persists in .rdb v4) |
| `delete_function` | Delete the function starting at an address |
| `resolve_thunk` | Walk a thunk chain to its ultimate destination (Ghidra getThunkedFunction; import thunks show DLL!Name) |
| `list_stubs` | List detected import thunks / stub functions |
| `list_switch_tables` | List detected switch/jump tables |
| `get_stack_frame` | Get stack frame variables (locals/params) for a function |
| `get_call_context` | One-shot call context for an address: containing function + decompilation + callers + callees + imports called + strings referenced. |
| `fid_ingest_library` | Ingest named functions of the current analysis as a FunctionID library (persists in session, merges into analysis) |
| `fid_export_db` | Export the session FunctionID library to a .fidb JSON file |
| `fid_import_db` | Import a .fidb JSON library file into the session FunctionID DB |
| `fid_list` | List session FunctionID signatures (filter by name/library substring) |

</details>

<details>
<summary><b>Disassembly and decompilation</b> (11 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `decompile_function` | Get pseudocode for a function at the given address |
| `force_decompile` | Force fresh decompilation of a function |
| `get_function_pcode` | Get PCode IR for a function |
| `disassemble_function` | Get full disassembly listing for a function |
| `disassemble_range` | Disassemble N instructions starting at an address (or up to end_address). No analysis required. |
| `disassemble_bytes` | Disassemble a hex byte string at an arbitrary base address. No binary required. |
| `get_annotated_disasm` | Disassembly of a function with inline annotations: comments, call targets, string refs, xrefs |
| `get_assembly_context` | Disassemble N instructions before/after an address |
| `search_in_decompiled` | Search regex/substring across all decompiled pseudocode |
| `search_instructions` | Search instructions by mnemonic and/or operand substring |
| `search_instruction_pattern` | Find sequences of instructions matching a pattern of mnemonics (e.g. 'push;mov;call'). Paged: has_more / next_offset |

</details>

<details>
<summary><b>Cross-references and control flow</b> (23 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `get_xrefs_to` | Get cross-references targeting an address |
| `get_xrefs_from` | Get cross-references originating from an address |
| `get_function_xrefs` | All xrefs into and out of a function |
| `get_bulk_xrefs` | Get xrefs to a list of addresses in one call |
| `get_function_callers` | Get functions that call the given address |
| `get_function_callees` | Get functions called by the given address |
| `get_call_tree` | Get call tree (BFS through callees) from a function up to max_depth |
| `find_callers_chain` | Get layered list of callers up to max_depth |
| `find_recursive_functions` | List functions that call themselves |
| `find_leaf_functions` | List functions that don't call any other function |
| `find_root_functions` | List functions that are never called by any other function |
| `analyze_call_graph` | Call graph statistics: roots, leaves, indegree/outdegree distribution |
| `analyze_control_flow` | CFG statistics for a function: blocks, edges, branch points |
| `get_basic_block_at` | Find the basic block containing the given address |
| `list_basic_blocks` | List all basic blocks of a function with successors/predecessors |
| `find_immediate_refs` | Scan sections for raw immediate references (32-bit and 64-bit LE) to an address. Useful when xref analysis hasn't run. |
| `find_imports_called_by` | List Win32/POSIX imports called by a function (direct or via stub) |
| `find_strings_referenced_by` | List strings referenced by a function |
| `find_users_of_import` | List functions that use a given import (by name, e.g. 'CreateFileW' or 'KERNEL32.dll!CreateFileW') |
| `find_callsites_to_import` | Ghidra-style: scan the binary for every direct call/jump to an imported function (by name like 'MessageBoxW' or 'USER32.dll!MessageBoxW') and every call to its import thunk |
| `add_memory_reference` | Create a user-defined memory reference (in-memory only) |
| `remove_reference` | Remove a user-defined memory reference |
| `list_memory_references` | List user-defined memory references |

</details>

<details>
<summary><b>Symbols and structure</b> (13 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `list_imports` | List imported symbols (paginated) |
| `list_exports` | List exported symbols (paginated) |
| `list_exports_full` | List exports with ordinal, RVA, address, and forwarder string (paginated, filter, only_forwarders) |
| `lookup_export` | Lookup an export by name OR ordinal |
| `list_imported_libraries` | Group imports by DLL (kernel32.dll, ntdll.dll, etc.) |
| `list_symbols` | List all symbols (paginated) |
| `list_sections` | List binary sections |
| `get_section_at` | Find section containing the given address |
| `list_relocations` | List base/dynamic relocations (PE BaseReloc, ELF rela, PLT artificial) |
| `list_globals` | List global symbols with section + type info (paginated) |
| `list_namespaces` | List C++ namespaces derived from demangled function names |
| `list_classes` | List C++ classes derived from demangled function names |
| `scan_rtti` | C++ RTTI scanner (MSVC + Itanium fallback): TypeDescriptors/COLs/vftables/first vfunc per class. |

</details>

<details>
<summary><b>Memory, strings and data</b> (17 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `get_bytes` | Read raw bytes from a virtual address (hex string output). size 1..4096 per call; larger requests are clamped and flagged with truncated/warnings/next_address |
| `get_string` | Read a null-terminated string from a virtual address |
| `get_int` | Read an integer (u8/u16/u32/u64/i*) at a virtual address |
| `read_memory` | Read raw memory at an address (alias of get_bytes) |
| `inspect_memory_content` | Read memory with heuristic type guessing (string/pointer/data) |
| `list_strings` | List extracted strings (paginated, filter, encoding). limit 1..5000 and a response-size budget per page: follow next_offset while has_more is true |
| `search_strings` | Search strings by substring |
| `search_bytes` | Search for a hex byte pattern ('??' = any byte) in binary data. Paged: has_more / next_offset tell whether the list is complete; pass offset to continue |
| `search_byte_patterns` | Search for byte patterns (alias of search_bytes) |
| `find_format_strings` | List strings containing C printf-style format specifiers (%s, %d, etc.) |
| `list_data_items` | List defined data: strings in non-executable sections (paginated, filter) |
| `address_info` | All info about an address: section, function, basic block, instruction, string, symbol, xrefs, comment |
| `find_code_gaps` | Find gaps of undefined bytes between functions in executable sections |
| `find_next_undefined_function` | Find the first undefined byte region after an address |
| `dump_section` | Dump a section to a file by name |
| `dump_range` | Dump a virtual address range to a file |
| `dump_full_binary` | Dump entire current (possibly patched) binary data to a file |

</details>

<details>
<summary><b>Data types</b> (25 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `list_data_types` | List all data types in the type manager (id, name, size, C decl) |
| `get_data_type` | Get one data type by name (id, size, C declaration) |
| `create_struct` | Create a struct type |
| `create_union` | Create a union type |
| `create_enum` | Create an enum type (optional underlying type) |
| `create_typedef` | Create a typedef of an existing type |
| `create_pointer_type` | Create a pointer-to-type (deduped by target) |
| `create_array_type` | Create an array type [count] of an element type |
| `create_function_signature` | Create a function signature type: return_type, params [{name,type}], calling_convention, varargs |
| `add_struct_field` | Add a field to a struct/union (auto-offset after the last field, or explicit offset) |
| `remove_struct_field` | Remove a field from a struct/union by name |
| `add_enum_variant` | Add a named value to an enum |
| `rename_data_type` | Rename a data type |
| `delete_data_type` | Delete a user data type (fails if referenced) |
| `apply_data_type` | Ghidra setDataType: define data of a type at an address |
| `get_data_type_at` | Get the data type applied at an address |
| `list_applied_types` | List all address->type definitions |
| `export_types` | Export the type manager as JSON (reimportable) |
| `import_types` | Import types from a JSON doc (inline 'types' array) or a file path |
| `import_dwarf_types` | Import DWARF types from the loaded ELF's .debug_info into the DataTypeManager (structs/unions/enums/typedefs with members and layouts) |
| `import_pdb` | Import types from a PDB file (MSVC): path, or default `<binary>.pdb` next to the loaded PE. Classes/unions/enums with fields, enum values |
| `list_type_archives` | List built-in type archives (win32/crt/libc — Ghidra .gdt equivalent) |
| `load_type_archive` | Seed well-known OS/CRT types from a built-in archive (idempotent) |
| `list_valid_data_types` | List built-in data types |
| `list_calling_conventions` | List known calling conventions |

</details>

<details>
<summary><b>Annotations and tagging</b> (18 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `set_comment` | Set / update a user comment at an address (kind: eol\|pre\|post\|plate\|repeatable) |
| `delete_comment` | Delete the user comment at an address (optional kind) |
| `list_comments` | List all user comments (all kinds) |
| `batch_set_comments` | Set multiple comments atomically: [{address, kind, text}] |
| `set_bookmark` | Add a bookmark at an address (kind: note\|info\|error\|analysis) |
| `list_bookmarks` | List all bookmarks |
| `delete_bookmark` | Delete bookmark at an address |
| `create_label` | Create an in-memory user label at an address |
| `delete_label` | Delete a user label at an address |
| `list_labels` | List all user-defined labels (with source: user\|analysis) |
| `get_function_labels` | List labels (user + symbol) inside a function |
| `label_strings` | Apply default s_xxx labels to all strings missing a user label |
| `tag_function` | Tag a function for triage (e.g. crypto, network, reviewed) |
| `untag_function` | Remove a tag from a function |
| `list_function_tags` | List function tags (all, or for one address) |
| `undo_annotation` | Undo the last annotation edit (comment/bookmark/label/rename/tag) |
| `redo_annotation` | Redo the last undone annotation edit |
| `set_plan` | Publish the agent plan shown in the AI Live card (steps + in-progress index) |

</details>

<details>
<summary><b>Protection and malware triage</b> (10 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `detect_protections` | Run all detectors at once and return a structured protection report (anti-debug, anti-VM, packers, obfuscation, .NET, crypto) |
| `detect_anti_debug` | Anti-debug imports, strings, INT 2D / RDTSC / SIDT, PEB reads via fs:[30]/gs:[60] |
| `detect_anti_vm` | Anti-VM strings (VBox/VMware/QEMU), CPUID, VMware backdoor port 0x5658 |
| `detect_packers` | Known packer section names (UPX/ASPack/VMProtect/Themida/...), entropy, tiny IAT |
| `detect_obfuscation` | Indirect jumps/calls, jmp $+2 junk, prefix soup, opaque predicates |
| `detect_crypto` | Common crypto init constants (MD5/SHA1/SHA256/AES Rcon) |
| `section_entropy` | Per-section entropy with verdict (packed_or_encrypted / compressed / code / structured / padding) |
| `find_pe_headers` | Scan whole binary for embedded PE headers (MZ + PE\\0\\0). Reveals nested loaders / overlays |
| `find_xor_loops` | Heuristic scan for XOR-based decryption stubs: `xor mem, ...` followed by `inc idx; backward branch` |
| `find_aes_rcon_table` | Locate the canonical AES Rcon table (01 02 04 08 10 20 40 80 1B 36) — marks AES key expansion |

</details>

<details>
<summary><b>PE and .NET</b> (8 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `get_pe_info` | PE/DLL header info: image_base, is_dll, COFF + DLL characteristics with decoded flag names (CFG, DEP, ASLR, ...) |
| `dll_export_summary` | Counts of named/ordinal-only/forwarder exports — useful for stub-DLL fingerprinting |
| `is_dotnet_assembly` | Quick yes/no — is the loaded PE a managed .NET assembly? |
| `dotnet_info` | CLR runtime version, COR20 flags, entry-point token, stream layout, table/type/method counts |
| `list_dotnet_types` | List TypeDef rows (paginated, optional name filter) |
| `list_dotnet_methods` | List MethodDef rows with owner type (paginated, optional name filter) |
| `list_dotnet_member_refs` | List MemberRef rows (external calls like System.Console::WriteLine) with parent scope |
| `resolve_dotnet_token` | Resolve a metadata token (e.g. 0x0A000003) to Parent::Name |

</details>

<details>
<summary><b>Patching and assembler</b> (31 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `patch_bytes` | Patch raw bytes at a virtual address (hex string; 'bytes' or alias 'hex'). Records the patch for undo/list. Drops the analysis by default (analysis_invalidated in the response; invalidate_analysis=false keeps it) |
| `nop_range` | Replace a byte range with x86 NOPs (0x90) |
| `fill_bytes` | Fill a virtual address range with a single byte value (e.g. 0xCC for INT3) |
| `fill_pattern` | Fill a virtual address range with a repeating hex pattern |
| `patch_string` | Write an ASCII/UTF-8 string at a virtual address (optionally null-terminated) |
| `patch_wide_string` | Write a UTF-16LE string at a virtual address (optionally null-terminated) |
| `patch_int` | Write an integer (u8/u16/u32/u64/i*) at a virtual address (LE/BE) |
| `copy_bytes` | Copy `size` bytes from src_address to dst_address within the binary |
| `search_and_replace_bytes` | Find a hex pattern across (optionally a single section) and replace each match with a same-length pattern |
| `patch_nop_instruction` | Replace one or more whole instructions starting at address with NOPs (uses disassembly to size them) |
| `patch_call_to_nop` | Replace the call instruction at address with NOPs (auto-sized) |
| `patch_jcc_to_nop` | Replace the conditional jump at address with NOPs (auto-sized) |
| `patch_jcc_invert` | Invert the condition of a Jcc at address (je↔jne, jl↔jge, etc.) — short or near |
| `patch_jcc_to_jmp` | Convert the conditional jump at address into an unconditional jump (preserves target) |
| `patch_jmp_to_address` | Write `jmp rel32` at address jumping to target (5 bytes; rel must fit in 32 bits) |
| `patch_function_to_ret` | Replace function entry with a single 0xC3 (`ret`) so the function does nothing |
| `patch_return_value` | Rewrite function entry as `xor eax,eax;ret` (value=0) or `mov eax,imm32;ret` (i32 fits) |
| `list_patches` | List every patch recorded in this session (offset, vaddr, original, new, description) |
| `get_patch_diff` | Get all patches as an offset-sorted before/after diff |
| `undo_last_patch` | Undo (revert) the most recently applied patch |
| `undo_patch_at` | Undo the most recent patch covering a given virtual address |
| `revert_all_patches` | Revert all patches and clear the history |
| `clear_patch_history` | Clear the patch history without reverting (keeps current binary state) |
| `export_patches` | Export the patch list to a JSON file (replayable via import_patches) |
| `import_patches` | Apply patches from a JSON file produced by export_patches |
| `diff_with_file` | Byte-by-byte compare current binary data with a file on disk |
| `save_patched_binary` | Write the (possibly patched) binary data to a new file |
| `patch_asm` | Assemble an instruction at an address and patch it into the binary (records patch, invalidates analysis) |
| `assemble` | Assemble a single instruction to bytes (mov/call/jmp/jcc/push/pop/xor/add/sub/cmp/test/lea/nop/ret/int3/...) |
| `assemble_snippet` | Assemble multiple lines (one instruction per line) at an address |
| `list_asm_mnemonics` | List mnemonics supported by the built-in assembler |

</details>

<details>
<summary><b>Debugger control</b> (20 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `get_debugger_status` | Get current debugger status, registers, breakpoint count, recent events |
| `debugger_start` | Start debugging the currently loaded binary (queues request) |
| `debugger_attach` | Attach the debugger to an already-running process by PID. Non-destructive on detach. |
| `debugger_detach` | Detach from the target without killing it. |
| `debugger_step_into` | Single-step into (queues request) |
| `debugger_step_over` | Step over (queues request) |
| `debugger_continue` | Continue execution (queues request) |
| `debugger_pause` | Suspend a running target for inspection (SIGSTOP/DebugBreakProcess); resume with debugger_continue |
| `debugger_stop` | Terminate debug session (queues request) |
| `debugger_stack_trace` | Walk the EBP frame chain of the attached process and resolve return addresses |
| `add_breakpoint` | Add a breakpoint at an address |
| `remove_breakpoint` | Remove a breakpoint at an address |
| `list_breakpoints` | List all breakpoints |
| `list_watchpoints` | List hardware watchpoints (read/write/access + hw exec) |
| `set_hardware_breakpoint` | Arm a DR0..DR3 hardware breakpoint (kind: execute\|write\|rw). Per-thread. |
| `clear_hardware_breakpoint` | Clear a DR0..DR3 hardware breakpoint slot. |
| `arm_software_breakpoint` | Write 0xCC at the given address in the live process and remember the original byte. |
| `run_until_address` | Arm an INT3 at address, continue, and poll until the BP is hit. Returns registers at hit. |
| `set_debug_options` | Toggle forward_exceptions (DBG_EXCEPTION_NOT_HANDLED for SEH/VEH) and auto_continue_after_bp. |
| `set_exception_policy` | Per-exception-code policy override: forward/swallow/pause/clear. Wins over the global forward_exceptions flag. |

</details>

<details>
<summary><b>Process memory</b> (8 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `read_process_memory` | Read live process memory (debugger must be attached). Returns hex+ASCII of the requested range. |
| `write_process_memory` | Write live process memory (debugger must be attached). Hex bytes payload. |
| `list_memory_regions` | Walk every committed region in the live process (VirtualQueryEx). Optional only_executable / only_writable filters. |
| `list_modules` | List every loaded module in the target process (DLLs + EXE) with runtime base + size. |
| `list_threads` | List thread IDs in the target process. |
| `disassemble_process_memory` | Read N instructions from the live process at a runtime address. Use this to see *decrypted* code on the fly. |
| `search_process_memory` | Scan the live process memory for a pattern. Hex bytes (default) or ASCII string with `s:` prefix. |
| `dump_process_region` | Dump [address, address+size] of live process memory to a file. |

</details>

<details>
<summary><b>Tracing and emulation</b> (6 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `start_trace` | Start single-step trace recording. Subsequent BP/SS hits append to a ring buffer of size `max`. |
| `stop_trace` | Stop trace recording. |
| `read_trace` | Read the recorded trace (rip/rax/rcx/rdx/rsp/t per entry). |
| `save_trace` | Save the recorded trace to a JSON file (Ghidra SaveTraceTask equivalent) |
| `load_trace` | Load a saved trace file back into the buffer (time-ordered) |
| `emu_run_function` | Concretely execute a function on the p-code emulator (no live process): pass integer args (rdi,rsi,...), get rax, end reason, steps and memory writes |

</details>

<details>
<summary><b>Server and utilities</b> (7 tools)</summary>

<br/>

| Tool | Description |
| --- | --- |
| `search_tools` | Find tools by keywords/category (e.g. 'entropy', 'xor decrypt', category=patching). Empty query lists categories. Returns names, params, required args, async eligibility; include_schema=true attaches full inputSchema. |
| `check_connection` | Health check: is the MCP server connected and which program is loaded |
| `health` | Server health: binary/analysis/debugger state |
| `get_version` | Get server version and feature list |
| `int_convert` | Convert integer between formats (dec/hex/bin/bytes/ascii) |
| `run_async` | Run an allowlisted long scan in a background thread (max 4 concurrent, timeout_ms default 120s) and return a job_id. Poll with poll_job. Eligible: detect_*, search_*, find_*, list_strings, section_entropy, get_binary_overview, get_call_context, analyze_call_graph, scan_rtti and more - search_tools marks every eligible tool with async_eligible=true. |
| `poll_job` | Poll a background job (timeout_ms enforced). Returns the tool result when done; consumes the job slot. |

</details>


## Use as a library

The crate is also a library (`rust_debugger::...`):

```toml
# Cargo.toml
[dependencies]
rust-debugger = { git = "https://github.com/jaszkus/rust-debugger" }
```

```rust
use rust_debugger::{disasm, parser};

let bin = parser::parse_file(std::path::Path::new("sample.exe"))?;
let listing = disasm::disassemble_binary(&bin)?;
```

## Architecture

Three front-ends (GUI, MCP server and CLI) share the same two engines: a **static engine**
(parser, disassembler, analysis and decompiler, backed by the RDDB project cache) and a **dynamic engine**
(x86-64 emulator and live debugger). The dynamic engine feeds traces and values back into the static analysis.

```mermaid
flowchart TB
    subgraph FE["Front-ends"]
        GUI["GUI<br/>iced / wgpu"]
        MCP["MCP server<br/>200+ tools"]
        CLI["CLI<br/>--analyze · --bench"]
    end

    subgraph CORE["Static engine"]
        direction LR
        P["parser"] --> D["disasm"] --> A["analysis"] --> DC["decompiler"]
        A <--> DB[("RDDB project")]
    end

    subgraph DYN["Dynamic engine"]
        direction LR
        EMU["emu<br/>x86-64"]
        DBG["debugger<br/>Win API / ptrace"]
    end

    FE --> CORE
    FE --> DYN
    DYN -. "traces & values" .-> CORE
```

### Project layout

```text
rust-debugger/
├── src/
│   ├── analysis/      protections, decompiler (pcode / printing / structure), flow, symbols, xrefs, pipeline
│   ├── asm/           x86 assembler / encoder
│   ├── debugger/      live debugging (Windows / Linux)
│   ├── disasm/        x86-64 and ARM64 disassembly
│   ├── emu/           x86-64 emulator (alu / config / exec / mem / regs)
│   ├── gui/           iced GUI (app, state, theme, views, widgets)
│   ├── mcp/           MCP server, protocol and tool registry
│   ├── parser/        binary formats (pe / elf / macho / dotnet / minidump / mapfile), strings, model
│   ├── project/       RDDB project files (snapshot, codecs)
│   ├── type_system/   data-type archives (win32 / crt / libc) and codecs
│   ├── tests/         unit / full / parity / fuzz / mcp suites
│   └── util/          shared helpers
├── data/              string classification model (see data/README.md)
└── assets/            GUI fonts and icon
```

## Development

```sh
cargo test                           # unit and integration suites
cargo check --all-targets            # quick compile check
cargo run --release -- sample.exe    # run from source
```

## Contributing

The project is in active development and **contributors are very welcome**. This is a great moment to get
involved, whatever your experience level.

| Way to help | How |
| --- | --- |
| **Report bugs and ideas** | Open an [issue](https://github.com/jaszkus/rust-debugger/issues). |
| **Send pull requests** | Fixes, new analysis passes, format parsers, MCP tools, GUI polish and docs. |
| **Test on real binaries** | Run it on your own PE / ELF / Mach-O / .NET files and report what breaks. |
| **Improve the docs** | Anything unclear in the README or the code is worth a fix. |

> [!NOTE]
> **Not sure where to start?** Open an issue and I'll help you get oriented.

Details on the dev setup, code layout and the PR process are in [**CONTRIBUTING.md**](CONTRIBUTING.md).
Security reports go through [**SECURITY.md**](SECURITY.md).

<div align="center">

<a href="https://github.com/jaszkus/rust-debugger/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=jaszkus/rust-debugger" alt="Contributors" />
</a>

</div>

## Acknowledgements

| Project | Used for |
| --- | --- |
| [`iced`](https://github.com/iced-rs/iced) / [`wgpu`](https://wgpu.rs/) | GUI and GPU rendering |
| [`iced-x86`](https://github.com/icedland/iced) | x86 / x86-64 disassembly |
| [`yaxpeax-arm`](https://github.com/iximeow/yaxpeax-arm) | ARM64 disassembly |
| [`gimli`](https://github.com/gimli-rs/gimli) | DWARF parsing |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | String model and inspiration for the MCP tool naming |

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

- `data/StringModel.sng` is an unmodified copy of Ghidra's string n-gram model
  (`Ghidra/Features/Base/data/stringngrams/StringModel.sng`, © National Security Agency, Apache-2.0).
  `data/StringModelLLR.bin` is a precomputed table derived from it.
  See [NOTICE](NOTICE) and [data/README.md](data/README.md).
- Third-party Rust crates and their license expressions are listed in
  [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
- Bundled fonts and their full licenses are listed in
  [assets/README.md](assets/README.md).

> [!IMPORTANT]
> Rust Debugger is intended for **security research, malware analysis, interoperability and education**.
> Use it only on software you are authorized to analyze.

---

<div align="center">

**If you find Rust Debugger useful, consider giving it a star. It really helps the project grow.**

[![Star History Chart](https://api.star-history.com/svg?repos=jaszkus/rust-debugger&type=Date)](https://star-history.com/#jaszkus/rust-debugger&Date)

</div>
