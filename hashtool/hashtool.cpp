// hashtool: computes the REAL CBlockHeader::GetHash() (VerusHash2.2 dispatch, including the
// PBaaS ClearNonCanonicalData() step the pool's own fast local hasher does NOT implement -- see
// critical-vrsc-hash-pbaas-mismatch.md) by deserializing JUST a header (140 bytes + varint-prefixed
// solution, the exact same bytes blockBuilder.js's hashableBuffer() already produces for every
// share -- no full block/transaction data needed, GetHash() never touches vtx) and linking directly
// against the real node's own compiled types, exactly like mmrtool does for the MMR root.
//
// Protocol (same convention as the pool's own verushash.cpp): reads lines on stdin, one request each:
//   H <id> <hex>   hex = 140 byte header + varint(solutionLen) + solution bytes (hashableBuffer())
//                  answers "H <id> <64 hex hash>" or "H <id> err"
//   Q              quit
// Kept resident (not re-exec'd per share) for performance -- CVerusHashV2::init()/SetVerusV2Hash()
// only need to run once.
#include <iostream>
#include <string>
#include <vector>
#include "primitives/block.h"
#include "streams.h"
#include "version.h"
#include "utilstrencodings.h"
#include "komodo_globals.h"
#include "komodo_defs.h"
#include "pbaas/pbaas.h"
#include "pbaas/identity.h"
#include "crypto/verus_hash.h"

struct CCcontract_info *CCinit(struct CCcontract_info *cp, uint8_t evalcode)
{
    return NULL;
}

uint64_t komodo_accrued_interest(int32_t *txheightp,uint32_t *locktimep,uint256 hash,int32_t n,int32_t checkheight,uint64_t checkvalue,int32_t tipheight)
{
    return(0);
}

CConnectedChains ConnectedChains;
CCurrencyDefinition CConnectedChains::GetCachedCurrency(const uint160 &currencyID)
{
    assert(false);
    return CCurrencyDefinition();
}

bool fIdIndex;
bool fConversionIndex;
uint160 CIdentity::IdentityPrimaryAddressKey(const CTxDestination &dest)
{
    assert(false);
    return uint160();
}

int main(int argc, char **argv)
{
    CVerusHash::init();
    CVerusHashV2::init();
    CBlockHeader::SetVerusV2Hash();

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        if (line[0] == 'Q') break;
        if (line[0] != 'H') continue;

        // "H <id> <hex>"
        size_t sp1 = line.find(' ');
        size_t sp2 = line.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) continue;
        std::string id = line.substr(sp1 + 1, sp2 - sp1 - 1);
        std::string hex = line.substr(sp2 + 1);

        if (!IsHex(hex)) {
            std::cout << "H " << id << " err" << std::endl;
            continue;
        }
        try {
            std::vector<unsigned char> data(ParseHex(hex));
            CDataStream ss(data, SER_NETWORK, PROTOCOL_VERSION);
            CBlockHeader header;
            ss >> header;
            std::cout << "H " << id << " " << header.GetHash().GetHex()
                      << " pbaas=" << header.HasPBaaSHeader()
                      << " nc=" << header.CheckNonCanonicalData()
                      << std::endl;
        } catch (const std::exception &e) {
            std::cout << "H " << id << " err" << std::endl;
        }
    }
    return 0;
}
