// verushash: share validation helper of the VRSC pool.
// VerusHash2.2 sources (verus-src/crypto/) are vendored from VerusCoin's OWN node source (src/crypto/
// verus_hash.{h,cpp}, verus_clhash.{h,cpp}, haraka.{h,c}), stripped of bitcoin-core-only dependencies
// this pool doesn't otherwise pull in (boost, tinyformat, uint256, hash.h/primitives/block.h) and with
// Haraka's generic plain-C symbols (haraka256/haraka512/load_constants/etc.) renamed verushash_* to
// avoid colliding with another vendored coin's crypto -- see critical-vendored-lib-symbol-collision
// memory and vrsc-project.md, which also documents ONE deliberate exception: the bare "rc" global is
// NOT renamed (empirically confirmed renaming it breaks verus_clhash.cpp's own local-variable shadowing
// of the same name, producing a real but silently WRONG hash -- do not "fix" this).
// Byte-verified against the real node's own compiled VerusHash2.2 code (linked straight from the
// node's own build artifacts on srv2) across multiple test vectors before being vendored here -- see
// vrsc-project.md for the exact repro.
//
// Reads commands on stdin, writes answers on stdout (one line each):
//   H <id> <hex>   the exact bytes VerusHash2.2 hashes: the 140 byte header (version|prevhash|
//                  merkleroot|finalsaplingroot|time|bits|nonce32, see blockBuilder.js buildHeader())
//                  followed by the compactsize-prefixed solution (blockBuilder.js hashableBuffer());
//                  answers "H <id> <64 hex>" (32 byte hash) or "H <id> err"
//   Q              quit
// Command line: --hash <hex> prints the hash.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include "crypto/verus_hash.h"

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int from_hex(const char *s, std::vector<unsigned char> &out)
{
	size_t n = strlen(s);
	if (n % 2) return -1;
	out.resize(n / 2);
	for (size_t i = 0; i < out.size(); i++) {
		int a = hexval(s[2 * i]), b = hexval(s[2 * i + 1]);
		if (a < 0 || b < 0) return -1;
		out[i] = (unsigned char)(a * 16 + b);
	}
	return 0;
}

static void to_hex(const unsigned char *in, size_t n, char *out)
{
	static const char d[] = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { out[2 * i] = d[in[i] >> 4]; out[2 * i + 1] = d[in[i] & 15]; }
	out[2 * n] = 0;
}

static void verusHash(const std::vector<unsigned char> &data, unsigned char hash[32])
{
	CVerusHashV2 hasher(SOLUTION_VERUSHHASH_V2_2);
	hasher.Write(data.data(), data.size());
	hasher.Finalize2b(hash);
}

int main(int argc, char **argv)
{
	CVerusHashV2::init();

	unsigned char hash[32];
	char hex[65];
	std::vector<unsigned char> data;

	if (argc == 3 && strcmp(argv[1], "--hash") == 0) {
		if (from_hex(argv[2], data)) { fprintf(stderr, "bad hex\n"); return 1; }
		verusHash(data, hash);
		to_hex(hash, 32, hex);
		puts(hex);
		return 0;
	}

	char line[8192];
	while (fgets(line, sizeof(line), stdin)) {
		if (line[0] == 'Q') break;
		if (line[0] != 'H') continue;
		char id[64], hexdata[8000];
		if (sscanf(line, "H %63s %7999s", id, hexdata) != 2 || from_hex(hexdata, data)) {
			printf("H %s err\n", (strlen(line) > 2) ? id : "0");
			fflush(stdout);
			continue;
		}
		verusHash(data, hash);
		to_hex(hash, 32, hex);
		printf("H %s %s\n", id, hex);
		fflush(stdout);
	}
	return 0;
}
