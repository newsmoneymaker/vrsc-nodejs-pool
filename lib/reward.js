/**
 * Block subsidy of VerusCoin (VRSC) mainnet.
 *
 * VRSC's real GetBlockSubsidy (src/main.cpp -> komodo_ac_block_subsidy() in src/komodo_utils.h) is a
 * generic Komodo-style multi-era table, NOT a simple Bitcoin halving. The real era table for VRSC
 * mainnet (confirmed from src/pbaas/crosschainrpc.cpp, CCurrencyDefinition::CCurrencyDefinition("VRSC",
 * testMode=false)):
 *
 *   era 0: reward=0,             decay=100000000, halving=1,       eraend=10080     (bootstrap era)
 *   era 1: reward=38400000000,   decay=0,         halving=43200,   eraend=226080    (384 VRSC/block)
 *   era 2: reward=2400000000,    decay=0,         halving=1051920, eraend=0         (24 VRSC/block,
 *          halves every 1,051,920 blocks forever after -- this is the era the live chain is in now,
 *          height ~4.29M, 3 halvings in: 2400000000 >> 3 = 300000000 = 3 VRSC, cross-checked 2026-10-20
 *          against a real getblocktemplate at height 4288108 with coinbasevalue=300000000)
 *
 * Unlike KCN/LCN there is NO mandatory separate developer-reward coinbase output on VRSC (checked
 * ConnectBlock/CreateNewBlock in the real node source -- no devreward-style script enforcement found);
 * the ENTIRE subsidy+fees goes to whoever the node's getblocktemplate names as the coinbase recipient
 * (the pool, here), so unlike reward.js's old LCN-derived minerReward() there is no 10%/90% split to
 * net out. This function returns the GROSS subsidy (what blockBuilder.js's own `coinbasevalue` passthrough
 * already uses for a real block) -- it exists only for display (API `/get_last_block_data`'s `reward`
 * field), the real per-block payout always comes from blockUnlocker.js reading the wallet's own
 * gettransaction, never from this estimate. Amounts in atomic units (1 VRSC = 1e8, config.coinUnits).
 **/
const ERAS = [
	{reward: 0, decay: 100000000, halving: 1, eraend: 10080},
	{reward: 38400000000, decay: 0, halving: 43200, eraend: 226080},
	{reward: 2400000000, decay: 0, halving: 1051920, eraend: 0}
];
const LASTERA = ERAS.length - 1;

exports.blockSubsidy = function (height) {
	if (!(height > 0)) return 0;

	let curEra = 0;
	for (; curEra <= LASTERA; curEra++) {
		if (ERAS[curEra].eraend > height || ERAS[curEra].eraend === 0) break;
	}
	if (curEra > LASTERA) return 0;

	let era = ERAS[curEra];
	let nStart = curEra ? ERAS[curEra - 1].eraend : 0;
	let subsidy = era.reward;

	if (era.halving !== 0) {
		let numHalvings = Math.floor((height - nStart) / era.halving);
		if (numHalvings > 0) {
			if (era.decay === 0) {
				// plain integer halving (real node: subsidy >>= numhalvings, a 64 bit shift -- JS's
				// `>>` is only 32 bit safe, so divide by 2 repeatedly instead for the same floor result)
				for (let i = 0; i < numHalvings && subsidy > 0; i++) subsidy = Math.floor(subsidy / 2);
			} else if (era.decay === 100000000 && era.eraend !== 0) {
				// linear interpolation down to the next era's reward across this era's span (only era 0
				// on VRSC mainnet uses this, long in the past at the live chain's height)
				let nextReward = curEra === LASTERA ? 0 : ERAS[curEra + 1].reward;
				let subsidyDifference = subsidy - nextReward;
				let sign = 1;
				if (subsidyDifference < 0) { sign = -1; subsidyDifference *= -1; }
				let denominator = era.eraend - nStart;
				let numerator = denominator - ((era.eraend - height) + ((height - nStart) % era.halving));
				subsidy = subsidy - sign * Math.floor((subsidyDifference * numerator) / denominator);
			} else {
				// geometric decay per halving step (unused by any VRSC mainnet era today)
				for (let i = 0; i < numHalvings && subsidy !== 0; i++) subsidy = Math.floor((subsidy * era.decay) / 100000000);
			}
		}
	}
	return subsidy;
};
