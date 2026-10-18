# data/

Bundled analysis data. Both files are compiled into the binary
(`include_str!` / `include_bytes!` in `src/parser/strings/string_model.rs`),
so they must stay in the repository for the crate to build.

## StringModel.sng

Character n-gram language model used to classify extracted strings as
human-readable text (English) vs. binary noise.

Provenance: an **unmodified copy of Ghidra's** string model,
`Ghidra/Features/Base/data/stringngrams/StringModel.sng`
(https://github.com/NationalSecurityAgency/ghidra), © National Security
Agency, licensed under Apache-2.0. The local copy is byte-identical to the
upstream repo file (git blob c91e9aac, unchanged upstream since 2023-11-30);
a Windows checkout of Ghidra may show CRLF line endings, the repo copy is LF.

## StringModelLLR.bin

Precomputed log-likelihood-ratio table derived from `StringModel.sng`
(quantized, step 0.05): 2^21 trigram bytes followed by 2^14 bigram bytes.
Generated offline so the classifier does not have to rebuild the model at
startup. See `src/parser/strings/string_model.rs` for the exact layout and
consumption logic.
