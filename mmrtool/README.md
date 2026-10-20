# mmrtool

Computes the real Merkle Mountain Range (MMR) root VerusCoin's post-PBaaS consensus rules require in
every block's solution (`hashBlockMMRRoot`) -- see `lib/mmrFixup.js`'s own module comment and
`lib/blockBuilder.js`'s module comment for the full story of why this exists: `getblocktemplate` does
NOT hand back a solution with this field already correct, confirmed by a live `submitblock` round trip
against the fully-synced mainnet node (2026-10-21) that failed with "CheckBlock Merkle Mountain Range
(MMR) root mismatch" even when resubmitting the template's own solution completely unmodified.

## Why a compiled binary, not a JS port

The real algorithm (`mmr.h` in the VerusCoin node source, ~1500 lines: a templated, chunked Merkle
Mountain Range combined with a per-transaction sub-MMR and a BLAKE2b hash personalized
`"VerusDefaultHash"`) is a real, deep subsystem. Hand-porting it to JavaScript carries a real risk of a
subtle bug that's only detectable via slow, rare `submitblock` round trips (no other way to verify
correctness short-of also having a real node). This tool instead links DIRECTLY against the real node's
own compiled types (`CBlock`, `CTransaction`, `mmr.h`'s templates, etc.) -- guaranteed byte-identical by
construction, not a reimplementation.

## What it does

`mmrtool <blockhex>` takes a full serialized block (the exact shape `submitblock` takes: 140 byte
header + varint-prefixed 1344 byte solution + varint tx count + tx data -- see
`blockBuilder.js::serializeBlock()`), deserializes it as a real `CBlock`, replicates
`CBlock::BuildBlockMMRTree()` (the exact function `CheckBlock()` itself calls), and prints 4
space-separated fields on stdout:

```
<stored MMR root hex> <freshly computed MMR root hex> <0 or 1, were they already equal> <patched solution hex>
```

The patched solution is byte-identical to the input except for the `hashBlockMMRRoot` sub-field (32
bytes at offset 40 of the 1344 byte solution) -- swap it into the job before hashing/submitting.

## How it was built (2026-10-20/21, on srv2's already-working VerusCoin build)

This is NOT a portable `make`-able target on its own -- it depends on the full VerusCoin node source
tree already being configured and built (the same tree `verusd` itself was built from, with the
gcc12/g++12 micromamba toolchain -- see the fleet's own `modern-toolchain-conda` notes), because it
links against that build's own compiled static libraries directly.

1. Copy `mmrtool.cpp` into that source tree's `src/` directory (next to `primitives/block.h` etc. --
   it needs those headers' relative includes to resolve).
2. Compile (same flags the project's own Makefile uses for its other small CLI tools, extracted via
   `make V=1 verus-tx`, plus `-maes -mpclmul -msse4.2 -mssse3` for the VerusHash init call this tool
   also needs -- see below):
   ```
   <toolchain>/bin/x86_64-conda-linux-gnu-c++ -std=c++17 -DHAVE_CONFIG_H -I. -I../src/config -I. -I./obj \
     -pthread -I<depends>/include -I./leveldb/include -I./leveldb/helpers/memenv -I./secp256k1/include \
     -I./cryptoconditions/include -I./cryptoconditions/src/include/falcon -I./cryptoconditions/src \
     -I./cryptoconditions/src/asn -I./univalue/include -isystem <depends>/include/ -DHAVE_BUILD_INFO \
     -D__STDC_FORMAT_MACROS -g -pipe -O2 -fwrapv -pthread -fno-strict-aliasing -maes -mpclmul -msse4.2 \
     -mssse3 -Wno-builtin-declaration-mismatch -c -o mmrtool.o mmrtool.cpp
   ```
3. Link against the SAME libraries `verusd` itself links against (extracted the real link line via
   `make V=1 verusd`, swapping `verusd-bitcoind.o` for `mmrtool.o`), wrapped in `--start-group`/
   `--end-group` because this tool's object file introduces symbol references in a different order than
   `verusd`'s own entry point does (without the group wrapper, `ld`'s single-pass archive scanning
   leaves a few symbols -- e.g. `curl_url` -- unresolved even though the exact same library is on the
   command line):
   ```
   <toolchain>/bin/x86_64-conda-linux-gnu-c++ -std=c++17 -g -pipe -O2 -fwrapv -pthread -fno-strict-aliasing \
     -Wl,-z,relro -Wl,-z,now -pie -o mmrtool mmrtool.o -L<depends>/lib \
     -Wl,--start-group libbitcoin_server.a <depends>/lib/libcurl.a <depends>/lib/libarchive.a -lz \
     libbitcoin_common.a univalue/.libs/libunivalue.a libbitcoin_util.a libbitcoin_zmq.a libzcash.a \
     libtls.a ./leveldb/libleveldb.a ./leveldb/libmemenv.a secp256k1/.libs/libsecp256k1.a \
     cryptoconditions/.libs/libcryptoconditions_core.a libbitcoin_wallet.a -lboost_filesystem \
     -lboost_program_options -lboost_thread -lboost_chrono -ldb_cxx-6.2 -lssl \
     <depends>/lib/libevent_pthreads.a <depends>/lib/libevent.a <depends>/lib/libzmq.a -lstdc++ -lrt \
     crypto/libbitcoin_crypto.a crypto/libverus_crypto.a crypto/libverus_portable_crypto.a -lboost_system \
     -lcrypto <depends>/lib/libsodium.a -lrustzcash -ldl -lanl -Wl,--end-group -lpthread
   ```
4. `strip mmrtool` (82MB -> ~7MB; it's still linked against the project's own compiled static libraries,
   just without debug symbols).
5. Copy the two toolchain runtime libs it needs that AREN'T on a normal Debian 10 host (everything else
   resolves against plain system libc/libpthread/librt/libdl/libanl/libm, universally present): `ldd
   mmrtool` to find `libstdc++.so.6`/`libgcc_s.so.1` under the toolchain's own `env/lib/`, copy both
   next to the binary. `lib/mmrFixup.js` sets `LD_LIBRARY_PATH` to this directory when invoking it, so it
   runs standalone on the MAIN pool server with no SSH/network dependency on srv2 at all.

Real bug hit building this (left documented in `mmrtool.cpp`'s own comments, don't "clean it up" without
re-reading why): `CVerusHash::init()`/`CVerusHashV2::init()` must be called once before ANY VerusHash-
family code path runs, even one this tool doesn't actually need the RESULT of
(`CPOSNonce::IsPOSNonce()`, reached from an unrelated `IsVerusPOSBlock()` check deep inside the real
`GetVerusEntropyHashComponent()` the MMR code calls) -- omitting it segfaults on a null AES-NI/PCLMUL
function pointer, the same bug class already found once in poolpayminer's `CpuWorker.cpp`.
