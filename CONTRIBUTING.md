# Contributing

Thanks for wanting to help! This project is in active development and any
contribution is welcome — code, tests, docs, bug reports, or just trying it on
your own binaries and telling us what broke.

## Getting started

```sh
git clone https://github.com/jaszkus/rust-debugger
cd rust-debugger
cargo build            # debug build of the GUI + CLI
cargo test             # ~500 unit/integration tests
cargo check --all-targets
```

- Rust stable toolchain (edition 2024, rustc ≥ 1.85). Windows 10+ or Linux.
- The GUI needs a GPU (Vulkan/DX12/Metal); headless modes (`--serve`,
  `--analyze`) do not.
- GUI regression tests create a real wgpu device. On headless machines install
  software Vulkan (`mesa-vulkan-drivers` on Debian/Ubuntu) — that is also what
  CI does.
- The optional PDB/DWARF fixture tests read sample binaries from `tests/`
  (not part of the repo); they skip automatically when the fixtures are absent.

## What to work on

- Issues labeled `good first issue` / `help wanted`.
- Small, focused PRs merge fastest — one logical change per PR.

## Code layout

See the *Project layout* section in the [README](README.md). Common entry
points:

- binary format parsing — `src/parser/formats/`
- disassembly — `src/disasm/` (x86 via `iced-x86`, ARM64 via `yaxpeax-arm`)
- analysis pipeline — `src/analysis/` (flow, decompiler, symbols, xrefs)
- MCP tools — `src/mcp/tools/`; registering a tool means touching
  `src/mcp/protocol/registry.rs`, `dispatch.rs` and the schema in
  `src/mcp/tools/schemas/` (registry/dispatch drift tests enforce consistency)
- GUI — `src/gui/` (iced; views live in `src/gui/views/`)

## Style

- Match the style of the surrounding code.
- `rustfmt` is not enforced yet (CI shows an advisory diff), and please avoid
  reformatting unrelated code in a PR.
- Leave clippy at least as clean as you found it (`cargo clippy --all-targets`).
- Add a focused regression test for bug fixes where practical.

## Commits & PRs

- Imperative commit subjects; explain the *why* in the body when it is not
  obvious.
- CI must be green: tests on Linux + Windows, `cargo-deny`, lint jobs.
- Changing workflows/versioning? Ping @jaszkus in the PR.

## Questions

Open an issue — happy to help newcomers get oriented.
