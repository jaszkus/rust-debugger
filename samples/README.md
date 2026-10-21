# Test samples

This directory contains **source-only** fixtures that are safe to publish. The
compiled fixtures are intentionally ignored: debug and PDB files can embed
machine-specific paths and must be built locally.

## PDB fixtures

The C sources are self-contained MSVC samples. Build them with debug
information, for example:

```bat
cl /Zi /Od /Fe:pdb_sample.exe pdb_sample.c /link /DEBUG
cl /Zi /Od /Fe:pdb_enum_sample.exe pdb_enum_sample.c /link /DEBUG
cl /Zi /Od /Fe:pdb_float_sample.exe pdb_float_sample.c /link /DEBUG
cl /Zi /Od /Fe:pdb_locals_sample.exe pdb_locals_sample.c /link /DEBUG
```

Put the resulting `.exe`/`.pdb` pairs in this directory or in `tests/`. The test
suite looks in `samples/` first, then `tests/`, and skips a test when the
fixture is absent.

## Windows binaries

`kernel32.dll`, `notepad.exe` and similar Microsoft binaries are **not**
redistributed here. Provide your own authorized copies locally if you want to
run the corresponding system-binary tests; they are ignored by Git.
