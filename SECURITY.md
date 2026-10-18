# Security policy

## Supported versions

The project is pre-1.0: fixes land on `master` and in the next release.

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Contact the
maintainer (`@jaszkus`) directly on GitHub and give us a chance to fix the
issue before any disclosure. A good report includes:

- the affected version or commit,
- what you were doing and how to reproduce it,
- the impact you believe it has (crash, data corruption, code execution, …).

This tool parses untrusted input (PE, ELF, Mach-O, .NET/CLR metadata, PDB,
DWARF, minidump, raw bytes) and the live debugger can spawn and attach to
processes, so parser crashes, out-of-bounds reads, and anything that lets a
malformed binary influence the host are all in scope.

We aim to acknowledge reports within a few days.
