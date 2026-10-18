# rust-debugger

**Ghidra/IDA-style binary analysis, decompilation and live debugging — in Rust.**

A self-contained reverse-engineering workbench: static analysis (disassembly, pcode-based
decompilation, data-flow recovery), live debugging (Windows Debug API / Linux `ptrace`)
and a built-in x86-64 emulator, wrapped in a GPU-accelerated GUI (iced/wgpu) and exposed
to AI agents through a Ghidra-compatible MCP server.

![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-informational)

> **Status:** 🚧 under active development (`0.1.0`) — features, APIs and project-file
> formats may change. I'm actively looking for contributors — see [Contributing](#contributing).

## Features

**Parsing & loading**
- PE, ELF, Mach-O, .NET (CLR metadata), minidump and linker map files
- DWARF (via `gimli`) and PDB debug info, C++/Rust symbol demangling
- RTTI scan, resources, imports/exports, sections

**Disassembly**
- x86 / x86-64 (via `iced-x86`) and ARM64 (via `yaxpeax-arm`)
- x86 assembler/encoder used for patching

**Analysis pipeline**
- Function detection (entries, thunks, call/jump targets), function-ID (FID) signatures
- CFG, constant propagation, noreturn inference, stack/unwind recovery, variable recovery
- Cross-references, import xrefs, string extraction with an n-gram classification model
- Protection/detection passes: packers, anti-debug, obfuscation, crypto, .NET, Go, ObjC

**Decompiler**
- x86-64 → pcode lifting, mini-SSA expression trees, C-like printing with recovered variables

**Emulation & live debugging**
- x86-64 emulator (ALU, flags, memory) for deobfuscation and dry-running functions
- Live debugging via Windows Debug API / Linux `ptrace`: breakpoints, stepping, register and
  memory access, threads, stack traces, recorded traces

**Patching & projects**
- Byte and branch patching with history and rebuild-after-patch
- RDDB v4/v5 project files (zstd-compressed analysis cache + annotations)

**GUI**
- iced/wgpu front-end: listing, hex, decompiler, pcode, CFG, xrefs, strings, symbols, stack,
  sections, imports, resources, patches, debug and live panels

**MCP server (for AI agents)**
- JSON-RPC over HTTP on `127.0.0.1`, **200+ Ghidra-compatible tool names** so existing
  Ghidra-MCP clients and prompts work out of the box
- Optional bearer-token auth via `RUST_DEBUGGER_TOKEN`

## Requirements

- Rust stable toolchain (edition 2021)
- Windows 10+ or Linux (Wayland/X11)
- A GPU with Vulkan, DX12 or Metal support for the GUI (headless `--serve`/`--analyze` runs need no GPU)

## Build

```sh
cargo build --release
# binary: target/release/rust-debugger
```

## Usage

### GUI

```sh
rust-debugger                 # open an empty workbench
rust-debugger sample.exe      # open a binary
```

### CLI

| Command | Description |
| --- | --- |
| `rust-debugger [file]` | Launch the GUI, optionally preloading a file |
| `rust-debugger --serve [port] [file]` | Headless MCP server (alias `--headless`); default port `7777`, `0` picks a free one |
| `rust-debugger --analyze <file> [--fresh]` | Batch parse + disasm + analyze, print a JSON summary (RDDB-cached; `--fresh` ignores the cache) |
| `rust-debugger --bench <file> [--parse-only]` | Time the parse / disasm / analysis phases |
| `rust-debugger --version`, `--help` | Version / usage |

Environment: `RD_MAX_DECOMP` — `--analyze` sets it to `0` unless it is already set.

Exit codes: `0` ok, `1` runtime failure, `2` usage error.

### MCP server

```sh
rust-debugger --serve 7777                    # http://127.0.0.1:7777/mcp
RUST_DEBUGGER_TOKEN=secret rust-debugger --serve   # require bearer token
```

Example MCP client configuration (opencode.json / any MCP client):

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

### Library

The crate is also a library (`rust_debugger::…`):

```rust
use rust_debugger::{disasm, parser};

let bin = parser::parse_file(std::path::Path::new("sample.exe"))?;
let listing = disasm::disassemble_binary(&bin)?;
```

## Project layout

```
src/
  analysis/    protections, decompiler (pcode/printing/structure), flow, symbols, xrefs, pipeline
  asm/         x86 assembler/encoder
  debugger/    live debugging (windows / linux)
  disasm/      x86-64 + ARM64 disassembly
  emu/         x86-64 emulator (alu / config / exec / mem / regs)
  gui/         iced GUI (app, state, theme, views, widgets)
  mcp/         MCP server, protocol and tool registry
  parser/      binary formats (pe/elf/macho/dotnet/minidump/mapfile), strings, model
  project/     RDDB project files (snapshot, codecs)
  type_system/ data-type archives (win32/crt/libc) and codecs
  tests/       unit / full / parity / fuzz / mcp suites
  util/        shared helpers
data/          string classification model (see data/README.md)
assets/        GUI fonts and icon
```

## Development

```sh
cargo test                     # unit + integration suites
cargo check --all-targets      # quick compile check
```

## Contributing

The project is in active development and **I'm looking for contributors** — this is a
great moment to get involved, whatever your experience level:

- 🐛 **Bugs & feature ideas** — open an [issue](https://github.com/jaszkus/rust-debugger/issues)
- 🔧 **Pull requests** — fixes, new analysis passes, format parsers, MCP tools, GUI polish, docs
- 🧪 **Testing** — run it on your own binaries (PE/ELF/Mach-O/.NET) and report what breaks
- 📖 **Docs** — anything unclear in the README or the code is worth a fix

Not sure where to start? Open an issue and I'll help you get oriented.

## License

Licensed under the **Apache License 2.0** — see [LICENSE](LICENSE).

- `data/StringModel.sng` is an unmodified copy of Ghidra's string n-gram model
  (`Ghidra/Features/Base/data/stringngrams/StringModel.sng`, © National Security Agency,
  Apache-2.0). `data/StringModelLLR.bin` is a precomputed table derived from it.
  See [NOTICE](NOTICE) and [data/README.md](data/README.md).
- Third-party Rust crates keep their own licenses.
