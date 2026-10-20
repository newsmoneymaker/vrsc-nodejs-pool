/**
 * VerusCoin (VRSC) Pool (based on cryptonote-nodejs-pool, GPL-2.0)
 *
 * The REAL, hard-won fix for the pool's single biggest VRSC-specific gap, found via a live
 * submitblock round-trip test against the fully-synced mainnet node (2026-10-21): getblocktemplate's
 * own "solution" field does NOT carry a submission-ready `hashBlockMMRRoot` (the embedded Merkle
 * Mountain Range commitment this chain's post-PBaaS consensus rules check on every block -- see
 * blockBuilder.js's own module comment for the full story of how this was found). Confirmed
 * empirically: resubmitting the template's OWN solution completely unmodified, with the template's
 * own nonce completely unmodified, STILL fails with "CheckBlock Merkle Mountain Range (MMR) root
 * mismatch" (-25) -- the pool must compute the real value itself before submitblock, for whatever
 * the FINAL header (particularly nNonce) ends up being.
 *
 * This only matters for a share that beats the REAL NETWORK difficulty (a found block) -- ordinary
 * share accept/reject against the pool's own (much lower) assigned difficulty is COMPLETELY
 * unaffected: VerusHash's cost per attempt is identical whether or not the solution bytes are
 * "valid" by this chain's own PBaaS rules, so hashrate/share accounting (shares.js, blockUnlocker.js)
 * needs no change at all. Only the rare "we might have found a real block" path needs this.
 *
 * Implementation: rather than hand-port the BLAKE2b-personalized hash + the templated Merkle Mountain
 * Range combination algorithm (mmr.h, ~1500 lines in the real node source, real risk of a subtle
 * reimplementation bug with no way to verify except slow, rare submitblock round trips), this calls a
 * small helper binary (mmrtool/, see its own build notes) that LINKS DIRECTLY against the real node's
 * own compiled types -- guaranteed byte-identical by construction, verified against a live node
 * 2026-10-21 (stored-vs-fresh MMR root really do differ on every real template; a submission built
 * with the fixed-up root gets a clean "Insufficient hash result in PoW block" rejection for a
 * deliberately-wrong nonce -- a pure PoW rejection, not a shape/consensus-commitment error).
 *
 * fixup(blockHex, callback): callback(err, {matched, patchedSolutionHex}). `blockHex` is the FULL
 * serialized block (see blockBuilder.js's serializeBlock()) built with whatever solution the job
 * currently carries -- mmrtool only needs this to read the real transaction content and header
 * fields; the OLD solution's own version/descriptor bytes it carries in are fine as input (unchanged
 * by this whole operation, only the hashBlockMMRRoot sub-field is corrected in the OUTPUT).
 **/
let execFile = require('child_process').execFile;
let path = require('path');

let mmrToolConfig = config.mmrTool || {};
let log_ = function (level, text, args) { log(level, 'mmrFixup', text, args || []); };

let BIN = mmrToolConfig.path || path.join(__dirname, '..', 'mmrtool', 'mmrtool');
let LIB_DIR = mmrToolConfig.libDir || path.join(__dirname, '..', 'mmrtool');

exports.fixup = function (blockHex, callback) {
	execFile(BIN, [blockHex], {
		env: Object.assign({}, process.env, {LD_LIBRARY_PATH: LIB_DIR}),
		timeout: 10000,
		maxBuffer: 1024 * 1024
	}, function (err, stdout, stderr) {
		if (err) {
			log_('error', 'mmrtool failed: %s %s', [err.message, stderr || '']);
			return callback(err);
		}
		let parts = stdout.trim().split(' ');
		if (parts.length !== 4) {
			log_('error', 'mmrtool unexpected output: %s', [stdout]);
			return callback(new Error('mmrtool unexpected output'));
		}
		let storedRoot = parts[0], freshRoot = parts[1], matched = parts[2] === '1', patchedSolutionHex = parts[3];
		if (!matched) {
			log_('warn', 'getblocktemplate solution had a stale/placeholder MMR root (stored %s, real %s) -- corrected before submission, as expected on this chain', [storedRoot, freshRoot]);
		}
		callback(null, {matched: matched, patchedSolutionHex: patchedSolutionHex});
	});
};
