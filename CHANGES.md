# Changes

## 1.0.0

* First release: VerusCoin (VRSC, VerusHash2.2) pool, derived from the lcn-nodejs-pool template and
  rewritten for VRSC's real "Equihash-compatible" stratum wire protocol (NOT standard Bitcoin stratum --
  see `lib/pool.js`/`lib/blockBuilder.js` module comments for the full story, including a real mistake
  caught and corrected before this release).
* `lib/blockBuilder.js`: builds the 140 byte Zcash-style header + VerusHash2.2 solution, and the
  serialized block for `submitblock`. Originally built its OWN coinbase (modeled on every Bitcoin-
  stratum coin here); this was found WRONG via a real live `submitblock` round-trip test against the
  fully-synced mainnet node (2026-10-20) -- VRSC's `getblocktemplate` builds the COMPLETE block
  server-side, including PBaaS/Merkle-Mountain-Range commitments over every transaction (coinbase
  included), so substituting a different coinbase invalidates those commitments. Fixed by taking the
  node's own `coinbasetxn` verbatim and requiring `mineraddress=<pool address>` in the node's own
  `VRSC.conf`. Two other real bugs were found and fixed along the way while still on the old
  hand-built-coinbase code path (an off-by-one scriptSig length that corrupted every byte after it, and
  a missing empty `vJoinSplit` vector that Zcash Sapling transactions always serialize when
  `nVersion >= 2`) -- both are now moot since the coinbase is no longer hand-built, but the bugs (and
  the byte-level diffing against a real matured block that found them) are documented in git history
  and in the vrsc-project memory file.
* `lib/pool.js`: real `mining.notify`/`mining.set_target`/`mining.submit` shapes for VRSC's actual
  wire protocol (9-field notify, raw-target difficulty, no extranonce2). `setKeepAlive` on every
  stratum socket. Login log line carries `agent=%s`/`type=%s` for the fleet's own monitoring scripts.
* `lib/blockUnlocker.js`: double-credit dedupe guard on `blocks:candidates` (same class of bug found on
  QWC); `depth` kept at 110, safely above VRSC's real 100-block coinbase maturity (an earlier config
  value of 70 would have credited/matured blocks before they were reorg-safe -- fixed before launch).
* `lib/reward.js`: rewritten from a leftover Lyncoin-specific halving formula to VRSC's real multi-era
  subsidy table (`src/pbaas/crosschainrpc.cpp`'s hardcoded mainnet eras) -- cross-checked against a
  real live `getblocktemplate` at height 4288108 (`coinbasevalue` 300000000 atomic = 3 VRSC, matching
  era 2's 3rd halving exactly).
* `lib/api.js`: fixed a leftover `lcnReward.minerReward()` call (the API's `/get_last_block_data`
  `reward` field was using Lyncoin's halving formula on VRSC heights -- would have shown a nonsensical
  number) to use the new `reward.js`.
* Dedicated Redis instance (port 6402) -- an earlier config pointed at port 6401 with the wrong auth,
  which is actually `xcb-pool-redis.service`'s own instance; fixed before this pool was ever started
  for real, so no data was ever at risk.
* Real live submitblock round-trip test performed against the fully-synced mainnet node (2026-10-20/21):
  confirmed the live chain's solution version (8, SOLUTION_VERUSV8) still maps to the VerusHash2.2 hash
  function (the dispatch in `verus_clhash.h` is `solutionVersion >= SOLUTION_VERUSHHASH_V2_2(4)`, so
  every solution version from 4 through 8 uses the same VerusHash2.2 code path -- no further hash
  change has happened since height 1053660), and that the chain's hybrid PoW/PoS design never affects
  this pool (`getblocktemplate`/`submitblock` are PoW-only RPCs; a real matured block was independently
  confirmed `"validationtype":"work"`).
* Not yet checked on a block found on mainnet: the real payout with the wallet (`sendmany`); payments
  stay `dryRun: true`.
