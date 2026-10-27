# Changelog

## 1.1.0 - 2026-10-27

### Type archive (new)

- Added a versioned Win32, CRT and libc type archive under `data/types`, embedded
  with `include_str!`, so a release never depends on files in the working
  directory.
- Added a loader, typedef resolver and LLP64 layout engine with validation of
  cycles, overlaps, out-of-bounds members and bitfield widths, plus `x86`/`x64`
  layout variants (`src/type_system/archive.rs`).
- `DataTypeManager` archives are now materialised from that data instead of
  hard-coded Rust tables.
- Added an immutable archive index (`src/analysis/symbols/type_archive.rs`) with
  function signatures, aggregate shapes and `PEB`/`TEB` layouts.
- Exported and imported functions get archive signatures, parameter names and
  typedefs when no debug info exists; user and PDB/DWARF types still win.
- Import call sites type their arguments through the IAT, so locals and
  parameters become `UNICODE_STRING`, `RECT`, `LONG` and friends, and struct
  members render as `base->field` when the access width matches a known field.
- `gs:[0x60]` now types as `PEB *`, so `*(T *)(ProcessEnvironmentBlock + off)`
  renders as a named field.

### Analysis

- Discover address-taken functions from data-section pointers and `lea`/`mov`
  targets, with an instruction-boundary and block-shape gate.
- Stop function extents at `int3`/zero padding, at `ud2`/`hlt`, and at jumps into
  a distinct known entry; reject prologue-looking starts after a conditional
  branch.
- Type parameters proven to be memory bases as pointers and fold bitfield stores
  to their debug field.
- Keep by-value debug parameters named across stack spills and resolve debug
  stack locals in comparisons and operands.
- Parse only address-forming instructions in the code-address scan.

### Decompiler

- Added an SSA view over p-code, forwarding SSA stack values and dispatch state.
- Recover compare-chain equality dispatchers as `switch`, structure loop
  state-machine transitions as `continue`, and prefer the lower-`goto` rendering
  when switches are present.
- Duplicate small goto regions and loop transitions to remove flat cleanup
  `goto`s while keeping the conservative rollback.
- Fold subtraction conditions into direct comparisons.
- Infer a `void` return when no value is returned, capture call results that are
  used, and never drop a call line when its return register is overwritten.
- Read absolute memory in comparisons, keep shifted constants numeric, and
  expand debug-info arrays element-wise.
- Name temporaries, hide ABI bookkeeping, render typed stack slots without
  pointer casts, and keep `utf8` identifiers intact in generated code.

### Tests

- Added type-system tests for the archive: embedded data resolves every
  reference, typedef chains, 32/64-bit layouts, function lookup with decoration
  and `api-ms-win-*` fallback, malformed archives, unions, bitfields, arrays and
  materialisation into `DataTypeManager`.

## 1.0.0 - 2026-10-26

### Analysis

- Merge chained PE unwind fragments into their owning functions and use the merged `.pdata` range as the function extent.
- Recover MSVC RVA switches whose bound check is far above the dispatch.
- Keep blocks reachable only through switch cases when pruning the CFG.
- Harden ELF `.eh_frame` and Mach-O load-command parsing against truncated records.
- Clear constant-propagation facts at branches so indirect-call targets are not invented across paths.

### Decompiler

- Render Ghidra-style types (`longlong`, `ulonglong`, `int`, `uint`, `short`, `ushort`, `byte`, `char`) and size-aware unsigned casts.
- Name remaining registers `uVarN`/`fVarN`/`in_REG`, declare temporaries, and use `FUN_` for unnamed functions.
- Render synthetic structure accesses as typed pointer arithmetic and resolve `gs:[0x60]` to `ProcessEnvironmentBlock`.
- Render stack addresses as `&local_X`, fold small absolute values as immediates, and spell data labels with lowercase hex.
- Inline single-use generated temporaries and remove stack-frame and callee-saved bookkeeping.

### MCP

- Fix a race that lost results from very fast asynchronous jobs.
- Gate `search_process_memory` under `allow_execution` and file dumps under `allow_changes`.
- Reject sections whose file offset is past EOF.
- Guarantee progress on short process-memory reads.
- Fold the full token-length difference into the constant-time comparison and join the server thread on stop.

### Project

- Drop the unused inner checksum and bump the analysis cache stamp.

## 0.9.1 - 2026-10-22

### Configuration

- Added tests for the config path, full settings roundtrip, disk write/read and invalid JSON handling.
- Extracted reusable config read/write helpers.

### UI

- Clipped long function signatures and detail values in the Func sidebar.

### Release

- The release workflow now attaches LICENSE, NOTICE, third-party licenses, font licenses and CHANGELOG.md automatically.
- Added this repository changelog.

## 0.9.0 - 2026-10-21

### Decompiler

- Recover compare-chain equality dispatchers as `switch` statements.
- Structure loop state-machine transitions as `continue`.
- Order indirect switch groups by unconditional fallthrough.
- Keep the conservative rollback when a switch would introduce `goto`, `LAB_` or a warning.
- Bump `ANALYSIS_STAMP` to `analysis-2026-10-compare-chain`.

### Tests

- Add compare-chain, loop state-machine and switch fallthrough coverage.

## 0.8.1 - 2026-10-21

### Configuration

- Persist UI settings in `%USERPROFILE%\.rust-debugger\config.json` (`~/.rust-debugger/config.json` on Linux/macOS).
- Migrate the legacy `ui-settings.json`.
- Persist MCP state, MCP port and hex bytes per row; sync MCP permissions.
- Remove the unused Recover strings, Max function size and Confirm before closing settings.

### UI

- Clip long call names in the Func sidebar.

## 0.8.0 - 2026-10-21

### UI

- Fixed filter spacing and search-field styling across list tabs.
- Fixed the missing arrow glyph in function names.
- Moved the context menu to a dedicated overlay canvas with rounded styling and animation.
- Fixed listing annotation overlap and AI Logs column overlap.

### Documentation

- Added the README screenshot gallery and feature highlights.

## 0.7.1 - 2026-10-21

### Release

- Added the full OFL license text, font notices, third-party license inventory and license assets.
