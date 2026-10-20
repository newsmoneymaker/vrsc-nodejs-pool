// poolpayminer port of VerusHash2.2: the small bits of infrastructure that the real node's
// verus_clhash.h declares but that live in its OWN "portable" translation unit (src/crypto/
// verus_clhash_portable.cpp), not in verus_clhash.cpp -- the per-thread key buffer, the CPU-optimized
// flag, and the aligned allocator. Vendored/adapted from that file; see vrsc-project.md.
//
// The six *_port functions below are declared by crypto/verus_clhash.h (so verusclhasher's constructor
// link-resolves even though that branch is dead in this build) but were never actually ported --
// this build only supports the AES-NI/PCLMUL path (see verus_clhash.h's ENABLE_VERUS_ISA note) and
// CVerusHash(V2)::init() already aborts before any of these could be reached on real hardware. If one
// ever DOES get called (CPU detection raced/changed under us), fail loudly instead of hashing wrong.
#include <cstdio>
#include <cstdlib>
#include "crypto/verus_clhash.h"

int __cpuverusoptimized = 0x80;

thread_local thread_specific_ptr verusclhasher_key;
thread_local thread_specific_ptr verusclhasher_descr;

#if defined(_WIN32)
thread_specific_ptr::~thread_specific_ptr() {
    if (verusclhasher_key.ptr) verusclhasher_key.reset();
    if (verusclhasher_descr.ptr) verusclhasher_descr.reset();
}
#endif

void *alloc_aligned_buffer(uint64_t bufSize)
{
    void *answer = NULL;
    if (posix_memalign(&answer, sizeof(__m128i) * 2, bufSize)) return NULL;
    return answer;
}

static void unported_portable_path()
{
    fprintf(stderr, "FATAL: VerusHash2.2 portable (non-AES-NI/PCLMUL) path was not ported into "
                     "poolpayminer -- see vrsc-project.md\n");
    abort();
}

extern "C" {
uint64_t verusclhash_port(void *, const unsigned char[64], uint64_t, __m128i **) { unported_portable_path(); return 0; }
uint64_t verusclhash_sv2_1_port(void *, const unsigned char[64], uint64_t, __m128i **) { unported_portable_path(); return 0; }
uint64_t verusclhash_sv2_2_port(void *, const unsigned char[64], uint64_t, __m128i **) { unported_portable_path(); return 0; }
__m128i __verusclmulwithoutreduction64alignedrepeat_port(__m128i *, const __m128i[4], uint64_t, __m128i **) { unported_portable_path(); return _mm_setzero_si128(); }
__m128i __verusclmulwithoutreduction64alignedrepeat_sv2_1_port(__m128i *, const __m128i[4], uint64_t, __m128i **) { unported_portable_path(); return _mm_setzero_si128(); }
__m128i __verusclmulwithoutreduction64alignedrepeat_sv2_2_port(__m128i *, const __m128i[4], uint64_t, __m128i **) { unported_portable_path(); return _mm_setzero_si128(); }
}
