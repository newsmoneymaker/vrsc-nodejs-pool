# hashtool

Diagnostic-only ground-truth helper, built 2026-10-23 while investigating a suspected
VerusHash/PBaaS hash mismatch (see `critical-vrsc-hash-pbaas-mismatch.md` in project memory).

Links directly against the real VerusCoin node's own compiled `CBlockHeader::GetHash()`
(same build artifacts as `mmrtool/`, same reason: guaranteed byte-identical to the real
network, no risk of a subtle hand-port bug). Given a 140-byte header + solution buffer on
stdin (`H <id> <hex>`), prints the real node's own hash for it.

**Not part of the live pool pipeline.** The investigation concluded the pool's original
`hasher/verushash` binary was already correct the whole time (a real mismatch only showed
up when comparing against a block mined via VerusCoin's OTHER, equally-valid method, which
this pool never uses) -- swapping the live hasher to this tool was tried once, broke 100%
of real share acceptance within seconds, and was reverted immediately. Kept here purely as
a reusable ground-truth checker for any future hash-related investigation, the same way
`mmrtool/` is kept for MMR-root verification. Do NOT wire `lib/hasher.js`'s default path to
this tool.

Build notes: same toolchain/link pattern as `mmrtool/` (see that directory's own README for
the exact commands and gotchas -- `CVerusHash(V2)::init()` must be called once or AES-NI
function pointers are null, `ld --start-group`/`--end-group` needed). Runtime needs
`libgcc_s.so.1`/`libstdc++.so.6` alongside it (non-universal toolchain libs, same as
`mmrtool/`) -- run with `LD_LIBRARY_PATH=$(dirname $0)`.
