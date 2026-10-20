/**
 * VerusCoin (VRSC) Pool (based on cryptonote-nodejs-pool, GPL-2.0)
 *
 * Stratum server for VerusHash2.2, using VerusCoin's REAL wire protocol -- NOT standard Bitcoin stratum.
 * Confirmed from the open source monkins1010/ccminer reference miner's equi/equi-stratum.cpp (the code
 * path actually used for VerusHash, dispatched by the CLIENT upon receiving a `mining.set_target`
 * message -- see `sctx->is_equihash` in its util.cpp). An EARLIER pass of this file assumed plain
 * Bitcoin-stratum shape (coinb1/coinb2/branches, mining.set_difficulty, a 5 param submit with a
 * separate extranonce2); that was wrong and has been corrected -- see vrsc-project.md for the full
 * story of the mistake and how it was found.
 *
 *   node getblocktemplate --> block builder: ONE fixed coinbase + merkle root computed server-side
 *   per job (see blockBuilder.js buildJob() -- never rebuilt per miner/per-share) --notify--> miners
 *   --submit--> share check (helper: VerusHash2.2 of the 140 byte header + solution) --> redis
 *   (shares.js). A share that meets the network target is sent to the node as a whole block with
 *   submitblock.
 *
 * mining.notify (9 params, see blockBuilder.js notifyParams()): [job_id, version, prevhash, merkleroot,
 * finalSaplingRoot, ntime, nbits, clean_jobs, solution]. No coinb1/coinb2/branches at all -- the pool
 * already did that work. version/ntime/nbits are big endian hex text (this project's usual convention);
 * prevhash/merkleroot/finalSaplingRoot each have every 4 byte word reversed; solution is plain hex, no
 * reordering (VerusHash is a plain single-hash PoW, not an Equihash puzzle -- no solving involved, the
 * solution is fixed data the node generated, just passed through). This pool controls both ends of the
 * wire (this file and poolpayminer's stratum client), so these exact byte-level conventions don't need
 * to match ccminer's own internal choices -- only the STRUCTURAL shape (which fields exist, what they
 * mean, no coinbase-rebuild-per-share) needed to come from the real reference.
 *
 * Difficulty: `mining.set_target` (a raw 256 bit target, hex, no byte reversal -- it's a number, not a
 * byte buffer) instead of `mining.set_difficulty`. VerusCoin's own compact-bits-to-difficulty formula
 * (ccminer's target_to_diff_verus(), confirmed DIFFERENT from the generic Equihash one in the same file)
 * is in blockBuilder.js's compactBitsToVerusDiff() -- used here only for the displayed network
 * difficulty (publishNetwork()), not for share accept/reject, which works off the real BigInt target
 * directly, same spirit as job.blockHashes already did for every other coin here.
 *
 * mining.submit (5 params, see equi_stratum_submit()): [worker, job_id, ntime, nonce, solution].
 * `nonce` is EN2_SIZE hex bytes = the client's ENTIRE remaining nonce-field content beyond its assigned
 * extranonce1 prefix -- there is NO separate extranonce2 param; what would be called extranonce2 IS this
 * nonce field. `solution` is echoed back by the client but this pool ignores that value and always uses
 * its own authoritative copy from the job (never trust a client-echoed immutable field).
 *
 * Extranonce1/extranonce2 ONLY ever end up inside the header's own 32 byte nonce field (bytes 108-139)
 * and have NO relationship to the coinbase or merkle root (a sharp contrast with classic Bitcoin
 * stratum, where varying the coinbase's extranonce is HOW you get a different merkle root to search
 * against) -- a job's merkleroot+finalSaplingRoot are fixed for its whole lifetime, only the 32 byte
 * nonce field is what miners actually search.
 *
 * NOT yet tested against a live node (still doing initial sync when this was written -- getblocktemplate
 * refuses until a chain is close to caught up). See vrsc-project.md for what's verified vs assumed from
 * source/the ccminer reference alone.
 **/

let net = require('net');
let tls = require('tls');
let fs = require('fs');
let crypto = require('crypto');

let utils = require('./utils.js');
let shares = require('./shares.js');
let rpc = require('./tdcRpc.js');
let hasher = require('./hasher.js');
let builder = require('./blockBuilder.js');
let mmrFixup = require('./mmrFixup.js');

let logSystem = 'pool';
require('./exceptionWriter.js')(logSystem);

let poolConfig = config.poolServer;
let varDiffConfig = Object.assign({startDiff: 4000, minDiff: 200, maxDiff: 50000000, targetTime: 20, retargetTime: 60, variancePercent: 30, maxJump: 100}, poolConfig.varDiff || {});
let JOB_REFRESH = poolConfig.jobRefresh || 1000;
let ALGO_NAME = 'verushash';
let TEMPLATE_REFRESH = (poolConfig.templateRefresh || 30) * 1000;   // a new template of the same tip at most this often (it carries new transactions)
let COINBASE_TAG = poolConfig.coinbaseTag === undefined ? '/vrsc.pool-pay.com/' : poolConfig.coinbaseTag;

let banningEnabled = poolConfig.banning && poolConfig.banning.enabled;
let bannedIPs = {};
let perIPStats = {};

const MAX_CLIENT_LINE = 16 * 1024;
const MAX_WORKERNAME = 32;
// the 32 byte nonce field is extranonce1 + extranonce2 TOGETHER, filling it completely (see the module
// comment above) -- not a separate 4 byte Bitcoin-style nonce plus a short extranonce2 like every other
// coin here. mining.submit's single "nonce" param IS this whole extranonce2 region.
const EN1_SIZE = 4;
const EN2_SIZE = builder.NONCE_SIZE - EN1_SIZE;
const TWO_64_1 = 18446744073709551615n;
const TWO_256 = 1n << 256n;
const MAX_NTIME_AHEAD = 2 * 60 * 60;

/**
 * Split a byte stream into lines
 **/
function lineSplitter (maxLength, onLine, onOverflow) {
	let buffer = '';
	return function (data) {
		buffer += data;
		let idx;
		while ((idx = buffer.indexOf('\n')) !== -1) {
			let line = buffer.slice(0, idx).replace(/\r$/, '');
			buffer = buffer.slice(idx + 1);
			if (line.length) onLine(line);
		}
		if (buffer.length > maxLength) {
			buffer = '';
			onOverflow();
		}
	};
}

/**
 * Parse the stratum login: [prop:|solo:]<address>[.workername | +workername]
 * Returns {address, workerName, rewardType} or {error}
 **/
function parseLogin (login, pass) {
	if (typeof login !== 'string' || !login.length || login.length > 200) return {error: 'Invalid login'};

	let rewardData = utils.determineRewardData(login);
	let rest = rewardData.address;
	let workerName = null;

	let plus = rest.indexOf('+');
	if (plus === -1) plus = rest.indexOf('.');
	if (plus !== -1) {
		workerName = utils.cleanupSpecialChars(rest.substr(plus + 1)).substr(0, MAX_WORKERNAME) || null;
		rest = rest.substr(0, plus);
	}
	if (!workerName && typeof pass === 'string' && pass !== 'x' && pass.length) {
		workerName = utils.cleanupSpecialChars(pass).substr(0, MAX_WORKERNAME) || null;
	}

	let address = utils.canonicalMinerAddress(rest);
	if (!address) return {error: 'Invalid VerusCoin address (expected an ordinary base58 P2PKH address starting with R)'};

	return {address: address, workerName: workerName, rewardType: rewardData.rewardType};
}

/**
 * Banning
 **/
let allowIPs = (poolConfig.allowIPs || []).map(String);

function isAllowedIp (ip) {
	if (!allowIPs.length) return true;
	let plain = ip.replace(/^::ffff:/, '');
	return allowIPs.indexOf(plain) !== -1 || allowIPs.indexOf(ip) !== -1;
}

function IsBannedIp (ip) {
	if (!banningEnabled || !bannedIPs[ip]) return false;
	let timeLeft = poolConfig.banning.time * 1000 - (Date.now() - bannedIPs[ip]);
	if (timeLeft > 0) return true;
	delete bannedIPs[ip];
	log('info', logSystem, 'Ban dropped for %s', [ip]);
	return false;
}

function checkBan (miner, validShare) {
	if (!banningEnabled) return;

	let stats = perIPStats[miner.ip];
	if (!stats) stats = perIPStats[miner.ip] = {validShares: 0, invalidShares: 0};
	if (validShare) stats.validShares++; else stats.invalidShares++;

	let total = stats.validShares + stats.invalidShares;
	if (total >= poolConfig.banning.checkThreshold) {
		let percent = stats.invalidShares / total * 100;
		if (percent >= poolConfig.banning.invalidPercent) {
			log('warn', logSystem, 'Banned %s@%s: %d%% invalid shares', [miner.address, miner.ip, Math.round(percent)]);
			bannedIPs[miner.ip] = Date.now();
			miner.destroy();
		}
		delete perIPStats[miner.ip];
	}
}

setInterval(function () {
	let now = Date.now();
	for (let ip in bannedIPs) {
		if (now - bannedIPs[ip] > poolConfig.banning.time * 1000) delete bannedIPs[ip];
	}
	perIPStats = {};
}, 60 * 1000);

/**
 * Limits against connection floods: per IP (total and not yet logged in), a login deadline, in total.
 * Settings in poolServer: maxConnectionsPerIp, maxUnauthenticatedPerIp, loginTimeout (s), maxConnections.
 **/
let MAX_PER_IP = poolConfig.maxConnectionsPerIp || 100;
let MAX_UNAUTH_PER_IP = poolConfig.maxUnauthenticatedPerIp || 10;
let LOGIN_TIMEOUT = (poolConfig.loginTimeout || 20) * 1000;
let MAX_TOTAL = poolConfig.maxConnections || 3000;
let connectionsByIp = {};
let totalConnections = 0;
let limitLogged = {};

function limitReason (ip) {
	let c = connectionsByIp[ip];
	if (totalConnections >= MAX_TOTAL) return 'the pool is full (' + MAX_TOTAL + ' connections)';
	if (c && c.total >= MAX_PER_IP) return 'more than ' + MAX_PER_IP + ' connections from one address';
	if (c && c.unauth >= MAX_UNAUTH_PER_IP) return 'more than ' + MAX_UNAUTH_PER_IP + ' connections from one address that did not log in';
	return null;
}

/**
 * Difficulty memory: the state of the variable difficulty is kept per address and worker for a while and handed to the next
 * connection of the same worker (a miner whose network drops connections would otherwise start from the start difficulty every time).
 **/
const DIFF_MEMORY_TTL = (poolConfig.diffMemoryMinutes || 15) * 60 * 1000;
let diffMemory = new Map();      // "address~worker" -> {diff, shareTimes, lastRetarget, seen}

setInterval(function () {
	let now = Date.now();
	diffMemory.forEach(function (mem, key) {
		if (now - mem.seen > DIFF_MEMORY_TTL) diffMemory.delete(key);
	});
}, 60 * 1000);

/**
 * Job manager: polls the node for a block template, keeps recent jobs.
 **/
let jobs = new Map();          // job id -> job
let currentJob = null;
let jobCounter = 0;
let miners = new Set();
let refreshing = false;
let lastTemplateError = null;
let lastTemplateErrorTime = 0;
let extraNonceCounter = crypto.randomBytes(2).readUInt16BE(0);

let poolScript = null;         // scriptPubKey of the pool address: what the coinbase pays to
let lastTip = null;
let lastTemplateAt = 0;

function newJobFromTemplate (t) {
	if (!poolScript) {
		poolScript = utils.addressScript(poolConfig.poolAddress);
		if (!poolScript) throw new Error('poolServer.poolAddress is not a valid VerusCoin address');
	}
	// NOTE: this chain's getblocktemplate hardcodes coinbasetxn=true server-side (src/rpc/mining.cpp),
	// so coinbasevalue is ALWAYS nested under t.coinbasetxn.coinbasevalue, never top-level -- checking
	// a top-level t.coinbasevalue here would reject EVERY real template (caught live, 2026-10-20, via
	// the submitblock round-trip test: see blockBuilder.js's buildCoinbase() for the matching fix).
	if (!t || !t.previousblockhash || !t.bits || !t.target || !t.coinbasetxn || typeof t.coinbasetxn.coinbasevalue !== 'number') throw new Error('unexpected block template');
	let built = builder.buildJob(t, poolScript, COINBASE_TAG);
	if (built.target <= 0n) throw new Error('bad target ' + t.target);
	built.id = null;
	built.blockHashes = Number(TWO_256 / (built.target + 1n));
	built.networkDiff = builder.compactBitsToVerusDiff(built.bits);
	built.created = Date.now();
	return built;
}

function refreshTemplate () {
	if (refreshing) return;
	refreshing = true;
	let fail = function (err) {
		refreshing = false;
		// the node is loading or not synchronised: one line per 30 seconds, not one per poll
		let text = err.message || JSON.stringify(err);
		if (text !== lastTemplateError || Date.now() - lastTemplateErrorTime > 30000) {
			lastTemplateError = text;
			lastTemplateErrorTime = Date.now();
			log('error', logSystem, 'getblocktemplate failed: %s', [text]);
		}
	};

	// cheap poll of the tip; a template is asked for when the tip moved (or now and then, to pick up new transactions)
	rpc.call('getbestblockhash', [], function (err, tip) {
		if (err) return fail(err);
		if (tip === lastTip && currentJob && Date.now() - lastTemplateAt < TEMPLATE_REFRESH) {
			refreshing = false;
			return;
		}
		rpc.call('getblocktemplate', [{rules: ['segwit']}], function (err, t) {
			refreshing = false;
			if (err) return fail(err);
			let job;
			try {
				job = newJobFromTemplate(t);
			} catch (e) {
				log('error', logSystem, 'Bad block template: %s', [e.message]);
				return;
			}
			if (t.previousblockhash !== tip) return;      // the tip moved while we asked: the next poll picks it up
			let newBlock = !currentJob || currentJob.height !== job.height || currentJob.prevHash !== job.prevHash;
			lastTip = tip;
			lastTemplateAt = Date.now();

			job.id = String(++jobCounter);
			jobs.set(job.id, job);
			currentJob = job;
			// forget jobs of earlier blocks and old ones of this block
			jobs.forEach(function (j, id) {
				if (j.height < job.height || job.created - j.created > 10 * 60 * 1000 || Number(id) < jobCounter - 20) jobs.delete(id);
			});

			if (newBlock) {
				log('info', logSystem, 'New block to mine: height %d, network difficulty %s hashes', [job.height, Math.round(job.blockHashes)]);
				publishNetwork(job);
			}
			miners.forEach(function (miner) { miner.sendJob(newBlock); });
		});
	});
}

let lastPublished = {height: null, time: 0};

function publishNetwork (job) {
	let now = Date.now();
	if (lastPublished.height === job.height && now - lastPublished.time < 30000) return;
	lastPublished = {height: job.height, time: now};
	redisClient.hmset(config.coin + ':network', {
		height: job.height,
		algorithm: ALGO_NAME,
		difficulties: JSON.stringify({[ALGO_NAME]: job.networkDiff}),
		updated: now
	}, function (err) {
		if (err) log('error', logSystem, 'Failed to publish network data: %j', [err]);
	});
}

/** the share target of a difficulty in hashes: what the miner uses (top 64 bits of the hash below (2^64 - 1) / diff) */
function shareLimit (diff) {
	return TWO_64_1 / BigInt(Math.max(1, Math.round(diff)));
}

/** the real 256 bit target sent via mining.set_target for a given per-miner difficulty (expected hashes,
 *  same unit as shareLimit() above and job.blockHashes) -- diff=1 means "expect one hash per share", so
 *  target = (2^256 - 1) / diff, mirroring job.blockHashes = TWO_256 / (job.target + 1). */
function minerTarget (diff) {
	return (TWO_256 - 1n) / BigInt(Math.max(1, Math.round(diff)));
}

/**
 * One miner connection
 **/
function handleConnection (socket, portData) {
	let ip = socket.remoteAddress;
	if (!ip) return socket.destroy();

	if (!isAllowedIp(ip)) {
		log('info', logSystem, 'Rejected connection from %s: not in poolServer.allowIPs', [ip]);
		return socket.destroy();
	}

	if (IsBannedIp(ip)) {
		log('info', logSystem, 'Rejected connection from banned IP %s', [ip]);
		return socket.destroy();
	}

	let limited = limitReason(ip);
	if (limited) {
		if (!limitLogged[ip] || Date.now() - limitLogged[ip] > 60000) {
			limitLogged[ip] = Date.now();
			log('warn', logSystem, 'Rejected connection from %s: %s', [ip, limited]);
		}
		return socket.destroy();
	}
	let counter = connectionsByIp[ip] || (connectionsByIp[ip] = {total: 0, unauth: 0});
	counter.total++;
	counter.unauth++;
	totalConnections++;
	let authenticated = false;

	socket.setEncoding('utf8');
	socket.setNoDelay(true);
	// Without this, a client that vanishes without a clean TCP close (NAT timeout, laptop sleep, a flaky
	// residential/mobile link, the app crashing) leaves a half-open "zombie" connection that sits ESTABLISHED
	// forever: we keep writing job broadcasts into it, our own write() calls count as "activity" so the
	// minerTimeout below never fires, and the unacked bytes pile up in the kernel send buffer (found live: 11
	// such zombies from one real remote miner within a few minutes, Send-Q 1-5 KB each, 0 reads). TCP keepalive
	// makes the OS actually probe the peer and fire close/error when it's truly gone.
	socket.setKeepAlive(true, 30000);

	let closed = false;
	let connectedAt = Date.now();
	let diff = Math.min(Math.max(portData.diff || varDiffConfig.startDiff, varDiffConfig.minDiff), varDiffConfig.maxDiff);
	let extraNonce1 = Buffer.alloc(EN1_SIZE);
	extraNonce1.writeUInt16BE(extraNonceCounter = (extraNonceCounter + 1) & 0xffff, 0);
	crypto.randomBytes(2).copy(extraNonce1, 2);
	let miner = {
		id: crypto.randomBytes(8).toString('hex'),
		ip: ip,
		address: null,
		workerName: null,
		rewardType: 'prop',
		diff: diff,
		fixedDiff: !!portData.fixedDiff,
		extraNonce1: extraNonce1,
		subscribed: false,
		sent: new Map(),               // job id sent to this miner -> {job, diff, nonces}
		sendSeq: 0,
		shareTimes: [],
		lastRetarget: Date.now(),
		sendJob: function (clean) { sendJob(!!clean); },
		destroy: function () {
			if (closed) return;
			closed = true;
			clearTimeout(loginTimer);
			miners.delete(miner);
			counter.total--;
			if (!authenticated) counter.unauth--;
			totalConnections--;
			if (counter.total <= 0) delete connectionsByIp[ip];
			let caller = (new Error().stack.split('\n')[2] || '').trim();
			log('info', logSystem, 'Closing connection of %s@%s after %ds, closed by: %s', [miner.address, ip, Math.round((Date.now() - connectedAt) / 1000), caller]);
			socket.destroy();
		}
	};

	let loginTimer = setTimeout(function () {
		if (authenticated) return;
		log('info', logSystem, 'No login from %s within %ds, closing', [ip, LOGIN_TIMEOUT / 1000]);
		miner.destroy();
	}, LOGIN_TIMEOUT);

	log('info', logSystem, 'Miner connected from %s on port %d', [ip, portData.port]);

	if (poolConfig.minerTimeout) {
		socket.setTimeout(poolConfig.minerTimeout * 1000, function () {
			log('info', logSystem, 'Miner %s@%s timed out', [miner.address, ip]);
			miner.destroy();
		});
	}

	function send (obj) {
		if (!closed && socket.writable) socket.write(JSON.stringify(obj) + '\n');
	}

	function reply (id, result, error) {
		send({id: id, result: result, error: error ? [error.code || 20, error.message, null] : null});
	}

	/** difficulty and job to this miner: the job id is its own (the miner applies a new target with the next job) **/
	function sendJob (clean) {
		if (!authenticated || !currentJob) return;
		let job = currentJob;
		miner.sendSeq++;
		let id = job.id + '.' + miner.sendSeq;
		miner.sent.set(id, {job: job, diff: miner.diff, nonces: new Set(), pending: new Set()});
		while (miner.sent.size > 40) miner.sent.delete(miner.sent.keys().next().value);
		send({id: null, method: 'mining.set_target', params: [minerTarget(miner.diff).toString(16).padStart(64, '0')]});
		send({id: null, method: 'mining.notify', params: builder.notifyParams(job, id, clean)});
	}

	function onLine (line) {
		let msg;
		try {
			msg = JSON.parse(line);
		} catch (e) {
			log('warn', logSystem, 'Malformed JSON from %s@%s', [miner.address, ip]);
			return miner.destroy();
		}
		if (!msg || typeof msg !== 'object') return miner.destroy();

		switch (msg.method) {
			case 'mining.subscribe':
				return onSubscribe(msg);
			case 'mining.authorize':
				return onAuthorize(msg);
			case 'mining.submit':
				return onSubmit(msg);
			case 'mining.extranonce.subscribe':
				return reply(msg.id, true);
			case 'mining.suggest_difficulty':
			case 'mining.configure':
				return reply(msg.id, msg.method === 'mining.configure' ? {} : true);
			default:
				return reply(msg.id, null, {code: 20, message: 'Unknown method'});
		}
	}

	function onSubscribe (msg) {
		miner.subscribed = true;
		// Same gap found+fixed on KCN/TDC/RTM/BTRM (same template): capture the client's own agent
		// string so monitor/miner_users.py's "agent=poolpayminer" filter can see real logins here too.
		let subParams = msg.params || [];
		if (typeof subParams[0] === 'string') miner.agent = subParams[0].substr(0, 60);
		reply(msg.id, [[['mining.set_target', 'sd' + miner.id], ['mining.notify', 'mn' + miner.id]], miner.extraNonce1.toString('hex'), EN2_SIZE]);
	}

	function onAuthorize (msg) {
		let params = msg.params || [];
		let parsed = parseLogin(params[0], params[1]);
		if (parsed.error) {
			log('warn', logSystem, 'Rejected login from %s: %s', [ip, parsed.error]);
			reply(msg.id, null, {code: 24, message: parsed.error});
			return setTimeout(miner.destroy, 100);
		}
		if (!currentJob) {
			reply(msg.id, null, {code: 20, message: 'The pool is starting (no block template yet), try again in a minute'});
			return setTimeout(miner.destroy, 100);
		}
		adoptRememberedDifficulty(parsed);

		if (!authenticated) {
			authenticated = true;
			counter.unauth--;
			clearTimeout(loginTimer);
		}
		miner.address = parsed.address;
		miner.workerName = parsed.workerName;
		miner.rewardType = parsed.rewardType;
		miners.add(miner);

		reply(msg.id, true);
		log('info', logSystem, 'Miner logged in: %s worker=%s type=%s ip=%s agent=%s', [parsed.address, parsed.workerName, parsed.rewardType, ip, miner.agent || '']);
		sendJob(true);
	}

	/** the same worker came back: continue with its difficulty and the share times of the earlier connection **/
	function adoptRememberedDifficulty (parsed) {
		if (miner.fixedDiff) return;
		let key = parsed.address + '~' + (parsed.workerName || '');
		let mem = diffMemory.get(key);
		if (mem && Date.now() - mem.seen <= DIFF_MEMORY_TTL) {
			miner.diff = Math.min(Math.max(mem.diff, varDiffConfig.minDiff), varDiffConfig.maxDiff);
			miner.shareTimes = mem.shareTimes;
			miner.lastRetarget = mem.lastRetarget;
		} else {
			mem = {diff: miner.diff, shareTimes: miner.shareTimes, lastRetarget: miner.lastRetarget, seen: Date.now()};
			diffMemory.set(key, mem);
		}
		miner.memory = mem;
	}

	function remember () {
		if (!miner.memory) return;
		miner.memory.diff = miner.diff;
		miner.memory.lastRetarget = miner.lastRetarget;
		miner.memory.seen = Date.now();
	}

	function reject (msg, message, code, count) {
		if (count !== false) checkBan(miner, false);
		log('info', logSystem, 'Rejected share from %s@%s: %s', [miner.address, ip, message]);
		reply(msg.id, null, {code: code || 23, message: message});
	}

	function onSubmit (msg) {
		if (!miner.address) return reply(msg.id, null, {code: 24, message: 'Unauthorized worker'});

		// real shape (equi_stratum_submit()): [worker, job_id, ntime, nonce, solution] -- params[0] (worker)
		// is not used for lookup, job_id already identifies this miner's own sent job.
		let params = msg.params || [];
		let jobId = String(params[1]);
		let sent = miner.sent.get(jobId);
		if (!sent || !currentJob || sent.job.height !== currentJob.height || sent.job.prevHash !== currentJob.prevHash) {
			return reject(msg, 'Job not found', 21, false);
		}
		let job = sent.job;
		let ntimeHex = String(params[2] || '').toLowerCase();
		let nonceHex = String(params[3] || '').toLowerCase();
		let solutionHex = String(params[4] || '').toLowerCase();
		if (!/^[0-9a-f]{8}$/.test(ntimeHex)) return reject(msg, 'Invalid ntime');
		if (nonceHex.length !== EN2_SIZE * 2 || !/^[0-9a-f]+$/.test(nonceHex)) return reject(msg, 'Invalid nonce');
		// the client echoes the solution back (see equi_stratum_submit()) but it's fixed, immutable data
		// this pool already has from the job -- never trust an echoed copy of something immutable, just
		// make sure the client didn't mangle it (a real difference would mean a confused/broken client).
		if (solutionHex.length !== job.solution.length * 2 || !/^[0-9a-f]*$/.test(solutionHex)) return reject(msg, 'Invalid solution');
		if (solutionHex !== job.solution.toString('hex')) return reject(msg, 'Solution does not match the job');
		let ntime = parseInt(ntimeHex, 16);
		if (ntime < job.mintime || ntime > job.time + MAX_NTIME_AHEAD) return reject(msg, 'ntime out of range');

		// a share counts once, but only a share that turned out valid is remembered (a wrong answer must not use up a nonce)
		let key = ntimeHex + nonceHex;
		if (sent.nonces.has(key) || sent.pending.has(key)) return reject(msg, 'Duplicate share', 22);
		sent.pending.add(key);

		// the 32 byte nonce field is extranonce1 + the client's full submitted nonce (= extranonce2, see
		// the module comment above) -- no separate extranonce2 param, no fixed-offset overwrite.
		let nonce32 = Buffer.concat([miner.extraNonce1, Buffer.from(nonceHex, 'hex')]);
		let header = builder.buildHeader(job, ntime, nonce32);
		let hashable = builder.hashableBuffer(header, job.solution);

		hasher.hash(hashable.toString('hex'), function (err, hashHex) {
			sent.pending.delete(key);
			if (err) {
				log('error', logSystem, 'Cannot check a share from %s: %s', [miner.address, err.message]);
				return reply(msg.id, null, {code: 20, message: 'Try again'});
			}
			let hash = Buffer.from(hashHex, 'hex');
			let top = hash.readBigUInt64LE(24);
			// the difficulty this share is credited with: the one of the job it was found for, or the previous one after a retarget
			let credited = top <= shareLimit(sent.diff) ? sent.diff : null;
			if (credited === null) return reject(msg, 'Low difficulty share');

			let isBlock = BigInt('0x' + builder.reverse(hash).toString('hex')) <= job.target;
			sent.nonces.add(key);
			checkBan(miner, true);
			reply(msg.id, true);
			acceptShare(job, credited, header, hash, isBlock);
		});
	}

	function acceptShare (job, creditedDiff, header, hash, isBlock) {
		let weight = shares.shareWeight(creditedDiff, job.blockHashes);

		let record = function (blockHash) {
			shares.record({
				login: miner.address,
				workerName: miner.workerName,
				ip: ip,
				rewardType: miner.rewardType,
				algo: ALGO_NAME,
				height: job.height,
				rawDifficulty: creditedDiff,
				weight: weight,
				blockCandidate: !!blockHash,
				hash: blockHash || null
			});
		};

		if (!isBlock) {
			record(null);
			retarget();
			return;
		}

		// Possible block solution. BEFORE building the real submission, this chain's own real
		// consensus rule needs a correction getblocktemplate never gives us: the solution's own
		// embedded "hashBlockMMRRoot" (a Merkle Mountain Range commitment over every transaction AND
		// this exact header, see mmrFixup.js's own module comment for the full story, found via a
		// live submitblock round-trip test, 2026-10-21). Using the template's own placeholder value
		// here would fail with "CheckBlock Merkle Mountain Range (MMR) root mismatch", never reaching
		// the real PoW check at all -- confirmed empirically, not theoretical. Because this changes
		// the solution bytes, the hash this share was checked against above no longer applies to the
		// corrected version -- re-hash and re-check against the network target before submitting;
		// losing the recheck (the corrected bytes happen to no longer beat network difficulty) is a
		// real possibility every time, not a bug, so it's handled quietly, not logged as an error.
		log('info', logSystem, 'Possible block solution at height %d from %s (worker %s), fixing up the MMR root before submitting', [job.height, miner.address, miner.workerName || '-']);
		let oldBlockHex = builder.serializeBlock(job, header);
		mmrFixup.fixup(oldBlockHex, function (fixErr, fixed) {
			if (fixErr) {
				log('error', logSystem, 'Could not compute the real MMR root for a possible block at height %d: %s', [job.height, fixErr.message]);
				record(null);
				return;
			}
			let patchedSolution = Buffer.from(fixed.patchedSolutionHex, 'hex');
			let patchedJob = Object.assign({}, job, {solution: patchedSolution});
			let hashable = builder.hashableBuffer(header, patchedSolution);
			hasher.hash(hashable.toString('hex'), function (hashErr, hashHex) {
				if (hashErr) {
					log('error', logSystem, 'Cannot re-check a possible block at height %d after the MMR fixup: %s', [job.height, hashErr.message]);
					record(null);
					return;
				}
				let correctedHash = Buffer.from(hashHex, 'hex');
				if (BigInt('0x' + builder.reverse(correctedHash).toString('hex')) > job.target) {
					log('info', logSystem, 'Possible block at height %d no longer beats the network target once the MMR root is corrected -- not a real find, share already credited', [job.height]);
					record(null);
					return;
				}

				let blockHex = builder.serializeBlock(patchedJob, header);
				// cosmetic/display only, doesn't affect what's submitted: VerusHash2.2 IS the block's
				// own GetHash() (src/primitives/block.cpp's GetVerusV2Hash()) -- reuse the corrected
				// hash rather than recomputing with a different algorithm.
				let blockHash = builder.reverse(correctedHash).toString('hex');
				rpc.call('submitblock', [blockHex], function (err, result) {
					if (err) {
						log('error', logSystem, 'Node rejected the block at height %d: %s', [job.height, err.message || JSON.stringify(err)]);
						record(null);
						return;
					}
					// null = accepted; a string is the reason (duplicate, inconclusive, high-hash, ...)
					if (result !== null && result !== undefined) {
						log('warn', logSystem, 'Block at height %d not accepted: %j', [job.height, result]);
						record(null);
						return;
					}
					rpc.call('getblockhash', [job.height], function (hashErr2, chainHash) {
						if (!hashErr2 && typeof chainHash === 'string' && chainHash !== blockHash) {
							log('warn', logSystem, 'Block accepted at height %d, but the chain has another block there (%s, ours %s)', [job.height, chainHash, blockHash]);
						}
						log('info', logSystem, 'BLOCK FOUND at height %d by %s (worker %s), hash %s', [job.height, miner.address, miner.workerName || '-', blockHash]);
						record(blockHash);
						lastTemplateAt = 0;
						setTimeout(refreshTemplate, 100);
					});
				});
			});
		});
	}

	/** variable difficulty: aim at one share per targetTime seconds **/
	function retarget () {
		if (miner.fixedDiff) return;
		let now = Date.now();
		miner.shareTimes.push(now);
		if (miner.shareTimes.length > 30) miner.shareTimes.shift();
		remember();
		if (now - miner.lastRetarget < varDiffConfig.retargetTime * 1000 || miner.shareTimes.length < 4) return;
		miner.lastRetarget = now;

		let span = (miner.shareTimes[miner.shareTimes.length - 1] - miner.shareTimes[0]) / 1000 / (miner.shareTimes.length - 1);
		if (!(span > 0)) span = 0.1;
		let ratio = varDiffConfig.targetTime / span;
		if (Math.abs(1 - ratio) * 100 < varDiffConfig.variancePercent) return;
		let newDiff = miner.diff * ratio;
		let jump = varDiffConfig.maxJump / 100;
		newDiff = Math.min(Math.max(newDiff, miner.diff * (1 - jump / (1 + jump))), miner.diff * (1 + jump));
		let cap = currentJob ? Math.min(varDiffConfig.maxDiff, currentJob.blockHashes / 4) : varDiffConfig.maxDiff;
		newDiff = Math.round(Math.min(Math.max(newDiff, varDiffConfig.minDiff), Math.max(cap, varDiffConfig.minDiff)));
		if (newDiff === miner.diff) return;
		log('info', logSystem, 'Difficulty of %s@%s: %d -> %d (a share every %ss)', [miner.address, ip, miner.diff, newDiff, span.toFixed(1)]);
		miner.diff = newDiff;
		miner.shareTimes.length = 0;          // the same array is shared with the memory of this worker
		remember();
		sendJob(false);
	}

	socket.on('data', lineSplitter(MAX_CLIENT_LINE, onLine, function () {
		log('warn', logSystem, 'Oversized line from %s@%s', [miner.address, ip]);
		miner.destroy();
	}));

	socket.on('error', function (err) {
		if (err.code !== 'ECONNRESET') log('warn', logSystem, 'Socket error from %s@%s: %s', [miner.address, ip, err]);
	});

	socket.on('close', function () {
		if (!closed) log('info', logSystem, 'Miner disconnected %s@%s', [miner.address, ip]);
		miner.destroy();
	});
}

/**
 * Start
 **/
shares.init();
refreshTemplate();
setInterval(refreshTemplate, JOB_REFRESH);

poolConfig.ports.forEach(function (portData) {
	let onConnection = function (socket) {
		handleConnection(socket, portData);
	};

	let server;
	if (portData.tls) {
		// poolServer.sslCert = certificate chain, poolServer.sslKey = private key (PEM). Read at start: restart after renewing.
		let options;
		try {
			options = {
				cert: fs.readFileSync(poolConfig.sslCert),
				key: fs.readFileSync(poolConfig.sslKey),
				minVersion: 'TLSv1.2'
			};
		} catch (e) {
			log('error', logSystem, 'Cannot read the TLS certificate/key for port %d: %s', [portData.port, e.message]);
			return;
		}
		server = tls.createServer(options, onConnection);
		server.on('tlsClientError', function (err, socket) {
			log('info', logSystem, 'TLS handshake failed from %s: %s', [socket && socket.remoteAddress, err.message]);
		});
	} else {
		server = net.createServer(onConnection);
	}

	server.listen(portData.port, poolConfig.bindIp || '0.0.0.0', function (error) {
		if (error) {
			log('error', logSystem, 'Could not start server listening on port %d: %j', [portData.port, error]);
			return;
		}
		log('info', logSystem, 'Started %sserver listening on port %d (%s)', [portData.tls ? 'TLS ' : '', portData.port, portData.desc || '']);
	});
});
