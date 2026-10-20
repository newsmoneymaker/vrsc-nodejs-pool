/**
 * VerusCoin (VRSC) Pool (based on cryptonote-nodejs-pool, GPL-2.0)
 *
 * Builds VRSC blocks from a getblocktemplate answer: the coinbase transaction (a Zcash Sapling v4
 * transaction, NOT Bitcoin's simple format -- see buildCoinbase() below), the merkle root, the 140
 * byte header of a share, and the serialized block for submitblock.
 *
 * Header (little endian, confirmed from the real node source, src/primitives/block.h's
 * CBlockHeader::SerializationOp): version 4 | hashPrevBlock 32 | hashMerkleRoot 32 |
 * hashFinalSaplingRoot 32 | nTime 4 | nBits 4 | nNonce 32 (Zcash-shaped, NOT Bitcoin's 4 byte nonce).
 * The node's own "solution" bytes (1344 for VerusHash2.2, from getblocktemplate, passed through
 * UNCHANGED -- VerusHash is a plain single-hash PoW, not an Equihash puzzle to solve) are appended
 * after the header with their own compactsize length prefix for hashing/submitblock, confirmed from
 * src/hash.h's SerializeVerusHashV2b()/CBlockHeader::Serialize().
 *
 * CRITICAL, found the hard way (see vrsc-project.md): VRSC's real stratum wire protocol is NOT
 * standard Bitcoin-stratum shape -- it's the "Equihash-compatible" protocol real Zcash-family pools
 * use (confirmed from the open source monkins1010/ccminer reference miner's equi/equi-stratum.cpp,
 * the code path actually used for VerusHash, dispatched via `mining.set_target`). Under that protocol
 * the POOL computes the ENTIRE merkle root SERVER-SIDE from ONE fixed coinbase per job -- there is no
 * coinb1/coinb2/branches sent to miners, and no per-miner/per-share coinbase rebuilding from a
 * submitted extranonce. Extranonce1/extranonce2 ONLY ever end up inside the header's own 32 byte
 * nonce field (see pool.js's module comment for the exact submit shape) and have NO relationship to
 * the coinbase or merkle root at all -- a sharp contrast with classic Bitcoin stratum, where varying
 * the coinbase's extranonce is HOW you get a different merkle root to search against.
 *
 * SECOND CRITICAL finding, from the real live submitblock round-trip test (2026-10-20, once the node
 * finished IBD): this chain's getblocktemplate does NOT work like Bitcoin's at all. `CreateNewBlock()`
 * (src/miner.cpp) builds the COMPLETE candidate block server-side -- coinbase (paid to whatever address
 * `-mineraddress` names in the node's own conf, or the wallet's default reserve key if unset), merkle
 * root, AND the solution's PBaaS/Merkle-Mountain-Range commitments (`hashBlockMMRRoot`, which hashes
 * EVERY transaction including the coinbase, confirmed from CBlock::BuildBlockMMRTree() iterating
 * `vtx`) -- getblocktemplate just hands this whole thing to the miner/pool, which may only vary the
 * NONCE field before hashing+submitting. A pool that builds its OWN coinbase (what this file used to
 * do, modeled on every other Bitcoin-stratum coin here) invalidates the template's hashBlockMMRRoot the
 * instant it swaps in a different coinbase -- confirmed live: submitblock accepted the FORMAT (after
 * the two bugs below were fixed) but rejected with "CheckBlock Merkle Mountain Range (MMR) root
 * mismatch" (-25), not a PoW-only rejection, because our custom coinbase no longer matched the
 * template's own MMR commitment. Implementing a from-scratch, byte-correct BLAKE2b Merkle Mountain
 * Range matching this node's exact tree algorithm is a real, deep subsystem -- NOT attempted. Instead,
 * the node's own `VRSC.conf` now has `mineraddress=<pool address>` (set 2026-10-20, node restarted),
 * so getblocktemplate's own internally-built coinbase already pays the pool directly, and this pool
 * takes that coinbase VERBATIM (see buildCoinbase() below) -- it only ever varies the header's nonce
 * field, exactly like every field in `template.solution` already assumes. This does not change the
 * pool's own economics at all: one address still receives the whole block reward, blockUnlocker.js
 * still splits it across miners by their round shares exactly as before.
 **/
let crypto = require('crypto');

const HEADER_SIZE = 140;
const NONCE_SIZE = 32;

function sha256d (buf) {
	return crypto.createHash('sha256').update(crypto.createHash('sha256').update(buf).digest()).digest();
}
exports.sha256d = sha256d;

function reverse (buf) {
	return Buffer.from(buf).reverse();
}
exports.reverse = reverse;

function varint (n) {
	if (n < 0xfd) return Buffer.from([n]);
	if (n <= 0xffff) { let b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b; }
	if (n <= 0xffffffff) { let b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b; }
	let b = Buffer.alloc(9); b[0] = 0xff; b.writeBigUInt64LE(BigInt(n), 1); return b;
}
exports.varint = varint;

/**
 * The ONE coinbase transaction for this job -- taken VERBATIM from getblocktemplate's own
 * `coinbasetxn`, never rebuilt (see the module comment above: this chain's node, not the pool, builds
 * the real coinbase, paid to whatever `-mineraddress` names in VRSC.conf). Returns
 * {tx: Buffer, txid, poolValue}.
 *
 * History: this used to construct the coinbase itself (height push + pool nonce + coinbaseTag in the
 * scriptSig, one P2PKH output to the pool's own address) the same way every Bitcoin-stratum coin here
 * does. That was WRONG for this chain and was replaced 2026-10-20 after the live submitblock round-trip
 * test showed it invalidates the template's own `hashBlockMMRRoot` (see module comment) -- two real
 * bugs were found and fixed in the OLD code along the way (an off-by-one scriptSig length, and a
 * missing empty `vJoinSplit` vector) before that deeper architectural issue was found; both fixes are
 * now moot since this function no longer builds a scriptSig/transaction by hand at all, but the lesson
 * (always byte-diff against a real matured block, never assume) is why they were caught.
 **/
exports.buildCoinbase = function (template, poolScriptHex) {
	if (!template.coinbasetxn || typeof template.coinbasetxn.data !== 'string') {
		throw new Error('getblocktemplate missing coinbasetxn.data (is -mineraddress set in VRSC.conf?)');
	}
	let poolValue = template.coinbasetxn.coinbasevalue;
	if (!(poolValue > 0)) throw new Error('bad coinbasevalue ' + poolValue);

	let tx = Buffer.from(template.coinbasetxn.data, 'hex');

	// Sanity check, not a protocol requirement: confirm the node's own coinbase actually pays the
	// configured pool address (via -mineraddress) rather than some other address (e.g. the wallet's
	// own default reserve key, which is what this fork silently falls back to if -mineraddress is ever
	// unset or wrong after a node restart/reinstall -- this would otherwise mine real blocks that pay
	// nobody this pool can sweep, a silent and expensive failure mode).
	if (poolScriptHex && tx.indexOf(Buffer.from(poolScriptHex, 'hex')) === -1) {
		throw new Error('getblocktemplate coinbase does not pay the configured pool address -- check -mineraddress in VRSC.conf');
	}

	// The node already computed the real txid (its own hash algorithm, no need to assume sha256d) --
	// `hash`/`txid` on every getblocktemplate transaction entry is display byte order, reverse once
	// for internal order (same convention as template.transactions[i].txid/hash below).
	let txid = reverse(Buffer.from(template.coinbasetxn.hash || template.coinbasetxn.txid, 'hex'));
	return {tx: tx, txid: txid, poolValue: poolValue};
};

/** the sibling hashes of the coinbase (index 0) up the merkle tree of the block, given the ids of the other transactions (internal byte order) */
exports.merkleBranches = function (txids) {
	let level = [null].concat(txids);
	let steps = [];
	while (level.length > 1) {
		steps.push(level[1]);
		if (level.length % 2) level.push(level[level.length - 1]);
		let next = [null];
		for (let i = 2; i < level.length; i += 2) next.push(sha256d(Buffer.concat([level[i], level[i + 1]])));
		level = next;
	}
	return steps;
};

/** merkle root (internal byte order) from the coinbase id and the branch */
exports.merkleRootFromBranches = function (coinbaseTxid, branches) {
	let root = coinbaseTxid;
	for (let b of branches) root = sha256d(Buffer.concat([root, b]));
	return root;
};

/** compact bits to the 256 bit target */
exports.compactToTarget = function (bits) {
	let exponent = bits >>> 24;
	let mantissa = BigInt(bits & 0x007fffff);
	if (bits & 0x00800000) return 0n;
	return exponent <= 3 ? mantissa >> BigInt(8 * (3 - exponent)) : mantissa << BigInt(8 * (exponent - 3));
};

/**
 * VRSC's own compact-bits-to-difficulty formula (ccminer's equi/equi-stratum.cpp, target_to_diff_verus()
 * -- confirmed DIFFERENT from the generic Equihash one in the same file, target_to_diff_equi(): VRSC
 * scales from 0x0f0f0f instead of the generic 0xffff0000/Bitcoin-style 0x00ffff reference point).
 * `bits` is the compact nBits uint32 (template.bits, parsed), NOT a full 256 bit target. Display/stats
 * only -- share accept/reject and varDiff in this pool work off the real BigInt target directly (see
 * pool.js), not this float approximation.
 **/
exports.compactBitsToVerusDiff = function (bits) {
	let exponentDiff = 8 * (0x20 - ((bits >>> 24) & 0xff));
	let significand = bits & 0xffffff;
	if (!significand) return 0;
	return (0x0f0f0f / significand) * Math.pow(2, exponentDiff);
};

/** every 4 byte word reversed: the way Bitcoin/Zcash-family stratum sends hash fields (the miner reverses the words back) */
function swapWords (buf) {
	let out = Buffer.from(buf);
	for (let i = 0; i < out.length; i += 4) out.slice(i, i + 4).reverse();
	return out;
}
exports.swapWords = swapWords;

/**
 * The job for miners out of a template: the node's own coinbase (see buildCoinbase() above) + merkle
 * root computed here, server-side, once per template refresh (see the module comment above -- this is
 * NOT rebuilt per miner/per-share). `tag` is accepted but unused (kept so pool.js's call site doesn't
 * need to change) -- there is no pool-controlled coinbaseTag to inject any more, see buildCoinbase().
 *   {height, version, bits, time, target (BigInt), prevInternal, finalSaplingRoot, solution,
 *    merkleRoot, transactions (hex list for submitblock), coinbaseTx (Buffer), poolValue}
 **/
exports.buildJob = function (template, poolScriptHex, tag) {
	let coinbase = exports.buildCoinbase(template, poolScriptHex);
	let txs = template.transactions || [];
	let txids = txs.map(function (t) { return reverse(Buffer.from(t.txid || t.hash, 'hex')); });
	let branches = exports.merkleBranches(txids);
	let merkleRoot = exports.merkleRootFromBranches(coinbase.txid, branches);
	let bits = parseInt(template.bits, 16);
	let versionHex = (template.version >>> 0).toString(16).padStart(8, '0');
	if (!template.finalsaplingroothash) throw new Error('getblocktemplate missing finalsaplingroothash');
	if (!template.solution) throw new Error('getblocktemplate missing solution (pre-VerusHash2.1 chain? see vrsc-project.md)');
	return {
		height: template.height,
		version: template.version,
		versionHex: versionHex,
		bits: bits,
		bitsHex: template.bits,
		time: template.curtime,
		mintime: template.mintime,
		target: BigInt('0x' + template.target),
		prevHash: template.previousblockhash,
		prevInternal: reverse(Buffer.from(template.previousblockhash, 'hex')),
		finalSaplingRoot: reverse(Buffer.from(template.finalsaplingroothash, 'hex')),
		solution: Buffer.from(template.solution, 'hex'),
		merkleRoot: merkleRoot,
		coinbaseTx: coinbase.tx,
		transactions: txs.map(function (t) { return t.data; }),
		poolValue: coinbase.poolValue,
		payments: 0
	};
};

/** what mining.notify carries: VerusCoin's real "Equihash-compatible" shape (confirmed from
 *  monkins1010/ccminer's equi_stratum_notify()) -- NOT standard Bitcoin-stratum. 9 fields, no
 *  coinb1/coinb2/branches: the pool already computed the whole merkle root server-side (see buildJob()
 *  above). Byte orders follow this project's existing convention for every other coin (big endian hex
 *  text for version/time/bits, every 4 byte word reversed for the three hash fields, solution passed
 *  through as plain hex with no reordering) -- this pool controls both ends of the wire (pool.js and
 *  poolpayminer's future stratum client), so there's no need to replicate ccminer's own internal byte
 *  juggling exactly, only to agree with the miner on ONE convention that reconstructs the real header
 *  correctly (see buildHeader() below, which undoes exactly this). */
exports.notifyParams = function (job, jobId, clean) {
	return [
		jobId,
		job.versionHex,
		swapWords(job.prevInternal).toString('hex'),
		swapWords(job.merkleRoot).toString('hex'),
		swapWords(job.finalSaplingRoot).toString('hex'),
		job.time.toString(16).padStart(8, '0'),
		job.bitsHex,
		!!clean,
		job.solution.toString('hex')
	];
};

/** the 140 byte header of a share: version | hashPrevBlock | hashMerkleRoot | hashFinalSaplingRoot |
 *  nTime | nBits | nNonce (32 bytes) -- confirmed from src/primitives/block.h's CBlockHeader. The
 *  caller is responsible for placing extranonce1/extranonce2 inside `nonce32` before calling this
 *  (see NONCE_SIZE above and pool.js's module comment for the real submit shape). */
exports.buildHeader = function (job, ntime, nonce32) {
	if (nonce32.length !== NONCE_SIZE) throw new Error('nonce must be ' + NONCE_SIZE + ' bytes');
	let header = Buffer.alloc(HEADER_SIZE);
	header.writeInt32LE(job.version, 0);
	job.prevInternal.copy(header, 4);
	job.merkleRoot.copy(header, 36);
	job.finalSaplingRoot.copy(header, 68);
	header.writeUInt32LE(ntime >>> 0, 100);
	header.writeUInt32LE(job.bits >>> 0, 104);
	nonce32.copy(header, 108);
	return header;
};

/** the exact bytes VerusHash2.2 hashes for this header+solution: the 140 byte header followed by the
 *  compactsize-prefixed solution -- matches src/hash.h's SerializeVerusHashV2b() (which just serializes
 *  the whole CBlockHeader, header fields then nSolution as a normal serialized vector<unsigned char>).
 *  This is what hasher.js's helper process is fed for share-difficulty checks. */
exports.hashableBuffer = function (header, solution) {
	return Buffer.concat([header, varint(solution.length), solution]);
};

/** the serialized block for submitblock: header, solution, the number of transactions, the coinbase, the template's transactions */
exports.serializeBlock = function (job, header) {
	let count = 1 + job.transactions.length;
	return header.toString('hex') + varint(job.solution.length).toString('hex') + job.solution.toString('hex') +
		varint(count).toString('hex') + job.coinbaseTx.toString('hex') + job.transactions.join('');
};

exports.HEADER_SIZE = HEADER_SIZE;
exports.NONCE_SIZE = NONCE_SIZE;
