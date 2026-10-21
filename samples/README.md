# Test samples

`samples/src/` contains the source for the self-built PDB and DWARF fixtures.
The matching `.exe`/`.pdb`/`.elf` files are checked in so the parser, debug-type
and decompiler tests work out of the box.

The PDB files use a neutral build path (`C:\build\sample`) and contain no local
user paths. The DWARF ELF was built from the checked-in source and has a neutral
source path.

## PDB fixtures

Rebuild them with debug information, for example:

```bat
cl /Zi /Od /Fe:pdb_sample.exe src\pdb_sample.c /link /DEBUG
cl /Zi /Od /Fe:pdb_enum_sample.exe src\pdb_enum_sample.c /link /DEBUG
cl /Zi /Od /Fe:pdb_float_sample.exe src\pdb_float_sample.c /link /DEBUG
cl /Zi /Od /Fe:pdb_locals_sample.exe src\pdb_locals_sample.c /link /DEBUG
```

`pdb_o2_sample.c` is the same sample built with optimization for the `/O2` test.
Build outputs belong in this directory.

## Windows binaries

`kernel32.dll`, `notepad.exe` and `samples/x` are **not** redistributed here.
Provide your own authorized copies locally; they are ignored by Git and the
corresponding tests skip when they are absent.
