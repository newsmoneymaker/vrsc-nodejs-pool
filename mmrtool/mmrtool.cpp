// mmrtool: given a raw block hex (same shape submitblock takes: 140 byte header + varint-prefixed
// solution + varint tx count + tx data), deserialize it as a real CBlock (using the real node's own
// types/serialization, linked directly against its own compiled objects) and compute the REAL
// "advanced header" Merkle Mountain Range root the live node's CheckBlock() expects, then print a
// patched solution with that root embedded, ready to re-hash/resubmit.
//
// Why this exists: VRSC's getblocktemplate does NOT hand back a solution whose hashBlockMMRRoot is
// already correct for submission -- confirmed empirically (2026-10-21) by submitting the template's
// OWN unmodified nonce+solution and still getting "CheckBlock Merkle Mountain Range (MMR) root
// mismatch" (-25), and by independently recomputing the root here and finding it genuinely differs
// from the template's own stored value every time. The pool must compute this itself before
// submitblock. Rather than hand-port the BLAKE2b-personalized hash + templated Merkle Mountain Range
// combination algorithm (mmr.h, ~1500 lines, real risk of a subtle reimplementation bug with no way to
// verify except slow submitblock round trips), this links directly against the REAL node's own
// compiled types -- guaranteed byte-identical by construction (see build notes in vrsc-project.md).
//
// Real bug found building this (documented so it isn't "fixed" away later): CVerusHash(V2)::init()
// must be called once before ANY VerusHash-family code path runs, even one buried inside an unrelated
// helper (CPOSNonce::IsPOSNonce(), called from IsVerusPOSBlock(), called from
// GetVerusEntropyHashComponent() -- itself irrelevant to a PoW block's actual MMR leaf value, since
// GetSubstitutedPreHeader() ignores it whenever !IsVerusPOSBlock(), but still unconditionally
// COMPUTED). Omitting the init call segfaults on a null AES-NI/PCLMUL function pointer -- same bug
// class as poolpayminer's CpuWorker.cpp (see critical-wrong-randomx-variant-bug-adjacent notes).
#include <iostream>
#include <string>
#include <vector>
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "streams.h"
#include "version.h"
#include "utilstrencodings.h"
#include "komodo_globals.h"
#include "komodo_defs.h"
#include "pbaas/pbaas.h"
#include "pbaas/identity.h"
#include "crypto/verus_hash.h"

// Minimal stubs, copied verbatim from komodo-tx.cpp's own standalone-CLI stubs (this tool never
// touches cryptoconditions scripts, identities, or cross-chain RPC -- just block/transaction MMR
// hashing; these symbols are only referenced because they live in the same translation units as code
// this tool DOES need).
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

    if (argc < 2) {
        std::cerr << "usage: mmrtool <blockhex>" << std::endl;
        return 2;
    }
    std::string hex = argv[1];
    if (!IsHex(hex)) {
        std::cerr << "ERROR not hex" << std::endl;
        return 1;
    }
    std::vector<unsigned char> blockData(ParseHex(hex));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    try {
        ssBlock >> block;
    } catch (const std::exception &e) {
        std::cerr << "ERROR deserialize: " << e.what() << std::endl;
        return 1;
    }

    uint256 storedRoot = block.GetBlockMMRRoot();

    // Replicate CBlock::BuildBlockMMRTree() manually (primitives/block.cpp) -- same leaves, same
    // combination, just called directly rather than through GetBlockMMRTree(). The explicit per-leaf
    // .Add() calls below only track the LEAF COUNT (see mmr.h's COverlayNodeLayer::push_back(), which
    // ignores the value passed and just increments a counter) -- the real per-leaf VALUE is always
    // re-derived from block.GetMMRNode(idx) by the overlay whenever the tree needs it.
    BlockMMRNodeLayer blockLayer(block);
    BlockMMRange mmRange(blockLayer);
    for (auto &tx : block.vtx) {
        mmRange.Add(tx.GetDefaultMMRNode(block.HasCappedTransactionMap()));
    }
    int32_t advanced = block.IsAdvancedHeader();
    if (advanced != 0) {
        mmRange.Add(CDefaultMMRNode());
    }
    uint256 freshRoot = BlockMMView(mmRange).GetRoot();

    block.SetBlockMMRRoot(freshRoot);
    std::cout << storedRoot.GetHex() << " " << freshRoot.GetHex() << " "
              << (storedRoot == freshRoot ? 1 : 0) << " "
              << HexStr(block.nSolution) << std::endl;

    return 0;
}
