# vrsc-nodejs-pool

Mining pool software for **VerusCoin (VRSC)** written in Node.js: a stratum server for VerusHash2.2
using VerusCoin's real "Equihash-compatible" stratum wire protocol (the same shape real Zcash-family
pools use, NOT the standard Bitcoin Stratum protocol most other pools in this fleet use), block
accounting through the pool wallet, and batch payouts. It is a fork of
[cryptonote-nodejs-pool](https://github.com/dvandal/cryptonote-nodejs-pool) by Dvandal (GNU GPL v2),
adapted for VerusCoin's real node (a Komodo/PBaaS-based fork with Zcash Sapling transactions). Live
example: <https://vrsc.pool-pay.com>.

## What it does

* **Stratum server** (plain TCP and TLS ports). Unlike the Bitcoin-stratum coins in this fleet, VRSC's
  wire protocol has NO `coinb1`/`coinb2`/merkle branches sent to miners: the pool receives a COMPLETE
  candidate block from the node's own `getblocktemplate` (header, coinbase, merkle root, and the
  VerusHash2.2 "solution" bytes, which also carry this chain's PBaaS/Merkle-Mountain-Range
  commitments) and only ever varies the header's 32 byte nonce field before hashing and submitting.
  `mining.notify` carries 9 fields (`job_id, version, prevhash, merkleroot, finalSaplingRoot, ntime,
  nbits, clean_jobs, solution`); `mining.set_target` (a raw 256 bit target) replaces
  `mining.set_difficulty`; `mining.submit` is `[worker, job_id, ntime, nonce, solution]` with no
  separate extranonce2 -- the "nonce" IS the client's whole remaining nonce-field content. See
  `lib/pool.js` and `lib/blockBuilder.js`'s own module comments for the full byte-level detail and the
  real mistakes found and fixed getting here.
* **IMPORTANT operational requirement, unique to this chain**: the node itself (not this pool) builds
  the real coinbase transaction via `CreateNewBlock()`, paid to whatever `-mineraddress=<address>` names
  in the node's own `VRSC.conf` (or the wallet's default reserve key if that's unset). This pool takes
  that coinbase VERBATIM -- it does NOT build its own coinbase the way every other coin here does,
  because the solution's own PBaaS/MMR commitments are computed over the node's exact transaction set
  INCLUDING the coinbase, and substituting a different one invalidates them (`submitblock` then fails
  with "CheckBlock Merkle Mountain Range (MMR) root mismatch", not a PoW-only rejection). **Before
  running this pool, set `mineraddress=<the pool's own VRSC address>` in `VRSC.conf` and restart the
  node**, or every block this pool finds will pay the node's own wallet instead of the pool.
* **VerusHash2.2 proof of work** over a 140 byte Zcash-style header (version, hashPrevBlock,
  hashMerkleRoot, hashFinalSaplingRoot, nTime, nBits, a 32 byte nonce -- NOT Bitcoin's 4 byte nonce)
  followed by a 1344 byte "solution" the node provides (VerusHash is a plain single hash, not an
  Equihash puzzle to solve -- the solution is fixed metadata, passed through unchanged except its
  nonce). Checked with a small C++ helper (`hasher/verushash`), vendored and byte-verified from the
  real node's own VerusHash2.2 source.
* **Hybrid PoW/PoS chain**: VerusCoin has both a PoW chain (VerusHash2.2, what this pool mines) and a
  separate PoS staking mechanism (its own `chainstake`/block-staking rules). This pool only ever builds
  and submits PoW blocks via `getblocktemplate`/`submitblock` -- it has no PoS/staking logic at all.
* **Accounts** are VerusCoin addresses (base58 `R...` P2PKH, or `b...` P2SH -- VRSC does NOT use
  bech32), optionally `.worker` or `+worker`, with a reward mode prefix `prop:` (shared, default) or
  `solo:`.
* **Reward**: no mandatory developer/community coinbase output on VRSC (unlike several other coins in
  this fleet) -- the whole `coinbasevalue` goes to the pool's own address. Subsidy follows VerusCoin's
  real multi-era table (`src/pbaas/crosschainrpc.cpp`'s hardcoded mainnet eras), NOT a simple Bitcoin
  halving -- see `lib/reward.js`'s own header comment for the exact era table and the live
  cross-check performed against a real `getblocktemplate`.
* **Payments and unlocker** as in Bitcoin-based pools (`sendmany`/wallet RPC, `gettransaction`, real
  coinbase maturity 100 blocks -- `blockUnlocker.depth` kept safely above that).

## Node

Real upstream [VerusCoin/VerusCoin](https://github.com/VerusCoin/VerusCoin). Needs a gcc12+ toolchain
(see this fleet's own notes on building it with an isolated micromamba toolchain on an older host).
`VRSC.conf` needs `rpcuser`/`rpcpassword`/`rpcport` as usual, PLUS `mineraddress=<pool address>` (see
above -- this is not optional for a pool, unlike every Bitcoin-stratum coin here).

## Status

Built, node fully synced, live submitblock round-trip verified against the real mainnet node
(2026-10-20/21). Payments stay in `dryRun` until a real block matures and pays out correctly.
