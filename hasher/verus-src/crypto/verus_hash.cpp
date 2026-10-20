// (C) 2023 The Verus Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
This provides the PoW hash function for Verus, a CPU-optimized hash 
function with a Haraka V2 core. Unlike Haraka, which is made for short 
inputs only, Verus Hash takes any length of input and produces a 256 
bit output.
*/
// poolpayminer port of VerusHash2.2 -- vendored from the real VerusCoin node source (src/crypto/
// verus_hash.cpp) and adapted to drop bitcoin-core-only dependencies (boost, tinyformat, uint256,
// hash.h/primitives/block.h) that this miner doesn't otherwise pull in. Haraka's own plain-C symbols
// (haraka256/haraka512/load_constants/etc., generic enough to collide with an unrelated vendored lib)
// are renamed with a verushash_ prefix in crypto/haraka.{h,c} -- see critical-vendored-lib-symbol-
// collision memory and vrsc-project.md. Only the AES-NI/PCLMUL-optimized path is ported (no portable/
// ARM fallback); CVerusHash(V2)::init() aborts with a clear message on a CPU that lacks it instead of
// silently falling through to an unimplemented path.
#include <cstdio>
#include <cstdlib>
#include <string.h>
#include "crypto/verus_hash.h"

void (*CVerusHash::haraka512Function)(unsigned char *out, const unsigned char *in);

void CVerusHash::Hash(void *result, const void *data, size_t _len)
{
    unsigned char buf[128];
    unsigned char *bufPtr = buf;
    int nextOffset = 64;
    uint32_t pos = 0, len = _len;
    unsigned char *bufPtr2 = bufPtr + nextOffset;
    unsigned char *ptr = (unsigned char *)data;

    // put our last result or zero at beginning of buffer each time
    memset(bufPtr, 0, 32);

    // digest up to 32 bytes at a time
    for ( ; pos < len; pos += 32)
    {
        if (len - pos >= 32)
        {
            memcpy(bufPtr + 32, ptr + pos, 32);
        }
        else
        {
            int i = (int)(len - pos);
            memcpy(bufPtr + 32, ptr + pos, i);
            memset(bufPtr + 32 + i, 0, 32 - i);
        }
        (*haraka512Function)(bufPtr2, bufPtr);
        bufPtr2 = bufPtr;
        bufPtr += nextOffset;
        nextOffset *= -1;
    }
    memcpy(result, bufPtr, 32);
};

void CVerusHash::init()
{
    if (!IsCPUVerusOptimized())
    {
        fprintf(stderr, "FATAL: this CPU lacks AES-NI/PCLMUL -- VerusHash2.2 requires an x86-64 CPU "
                         "from ~2013 or later (the portable/ARM fallback was not ported, see "
                         "vrsc-project.md)\n");
        abort();
    }
    haraka512Function = &verushash_haraka512_zero;
}

CVerusHash &CVerusHash::Write(const unsigned char *data, size_t _len)
{
    unsigned char *tmp;
    uint32_t pos, len = _len;

    // digest up to 32 bytes at a time
    for ( pos = 0; pos < len; )
    {
        uint32_t room = 32 - curPos;

        if (len - pos >= room)
        {
            memcpy(curBuf + 32 + curPos, data + pos, room);
            (*haraka512Function)(result, curBuf);
            tmp = curBuf;
            curBuf = result;
            result = tmp;
            pos += room;
            curPos = 0;
        }
        else
        {
            memcpy(curBuf + 32 + curPos, data + pos, len - pos);
            curPos += len - pos;
            pos = len;
        }
    }
    return *this;
}

// to be declared and accessed from C
void verus_hash(void *result, const void *data, size_t len)
{
    return CVerusHash::Hash(result, data, len);
}

void (*CVerusHashV2::haraka512Function)(unsigned char *out, const unsigned char *in);
void (*CVerusHashV2::haraka512KeyedFunction)(unsigned char *out, const unsigned char *in, const u128 *rc);
void (*CVerusHashV2::haraka256Function)(unsigned char *out, const unsigned char *in);

void CVerusHashV2::init()
{
    if (!IsCPUVerusOptimized())
    {
        fprintf(stderr, "FATAL: this CPU lacks AES-NI/PCLMUL -- VerusHash2.2 requires an x86-64 CPU "
                         "from ~2013 or later (the portable/ARM fallback was not ported, see "
                         "vrsc-project.md)\n");
        abort();
    }
    verushash_load_constants();
    haraka512Function = &verushash_haraka512;
    haraka512KeyedFunction = &verushash_haraka512_keyed;
    haraka256Function = &verushash_haraka256;
}

void CVerusHashV2::Hash(void *result, const void *data, size_t len)
{
    unsigned char buf[128];
    unsigned char *bufPtr = buf;
    int pos = 0, nextOffset = 64;
    unsigned char *bufPtr2 = bufPtr + nextOffset;
    unsigned char *ptr = (unsigned char *)data;

    // put our last result or zero at beginning of buffer each time
    memset(bufPtr, 0, 32);

    // digest up to 32 bytes at a time
    for ( ; pos < len; pos += 32)
    {
        if (len - pos >= 32)
        {
            memcpy(bufPtr + 32, ptr + pos, 32);
        }
        else
        {
            int i = (int)(len - pos);
            memcpy(bufPtr + 32, ptr + pos, i);
            memset(bufPtr + 32 + i, 0, 32 - i);
        }
        (*haraka512Function)(bufPtr2, bufPtr);
        bufPtr2 = bufPtr;
        bufPtr += nextOffset;
        nextOffset *= -1;
    }
    memcpy(result, bufPtr, 32);
};

CVerusHashV2 &CVerusHashV2::Write(const unsigned char *data, size_t len)
{
    unsigned char *tmp;

    // digest up to 32 bytes at a time
    for ( int pos = 0; pos < len; )
    {
        int room = 32 - curPos;

        if (len - pos >= room)
        {
            memcpy(curBuf + 32 + curPos, data + pos, room);
            (*haraka512Function)(result, curBuf);
            tmp = curBuf;
            curBuf = result;
            result = tmp;
            pos += room;
            curPos = 0;
        }
        else
        {
            memcpy(curBuf + 32 + curPos, data + pos, len - pos);
            curPos += len - pos;
            pos = len;
        }
    }
    return *this;
}

// to be declared and accessed from C
void verus_hash_v2(void *result, const void *data, size_t len)
{
    return CVerusHashV2::Hash(result, data, len);
}
