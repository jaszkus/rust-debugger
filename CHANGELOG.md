# Changelog

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
