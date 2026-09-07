#ifndef LMCRACK_BITSLICE_VEC_H
#define LMCRACK_BITSLICE_VEC_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#define BS_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define BS_FORCE_INLINE inline __attribute__((always_inline))
#else
#define BS_FORCE_INLINE inline
#endif

#if defined(LMCRACK_BITSLICE_SCALAR)
typedef uint64_t bs_vec;
#define BS_LANES 64U
#define BS_BYTES 8U
static BS_FORCE_INLINE bs_vec bs_zero(void) { return UINT64_C(0); }
static BS_FORCE_INLINE bs_vec bs_ones(void) { return UINT64_MAX; }
static BS_FORCE_INLINE bs_vec bs_xor(bs_vec a, bs_vec b) { return a^b; }
static BS_FORCE_INLINE bs_vec bs_and(bs_vec a, bs_vec b) { return a&b; }
static BS_FORCE_INLINE bs_vec bs_or(bs_vec a, bs_vec b) { return a|b; }
static BS_FORCE_INLINE bs_vec bs_not(bs_vec a) { return ~a; }
static BS_FORCE_INLINE bs_vec bs_load(const void *p) { bs_vec v; memcpy(&v,p,sizeof(v)); return v; }
static BS_FORCE_INLINE void bs_store(void *p, bs_vec a) { memcpy(p,&a,sizeof(a)); }
#elif defined(AVX512) || defined(__AVX512F__)
#include <immintrin.h>
typedef __m512i bs_vec;
#define BS_LANES 512U
#define BS_BYTES 64U
static BS_FORCE_INLINE bs_vec bs_zero(void) { return _mm512_setzero_si512(); }
static BS_FORCE_INLINE bs_vec bs_ones(void) { return _mm512_set1_epi32(-1); }
static BS_FORCE_INLINE bs_vec bs_xor(bs_vec a, bs_vec b) { return _mm512_xor_si512(a,b); }
static BS_FORCE_INLINE bs_vec bs_and(bs_vec a, bs_vec b) { return _mm512_and_si512(a,b); }
static BS_FORCE_INLINE bs_vec bs_or(bs_vec a, bs_vec b) { return _mm512_or_si512(a,b); }
static BS_FORCE_INLINE bs_vec bs_not(bs_vec a) { return _mm512_xor_si512(a,bs_ones()); }
static BS_FORCE_INLINE bs_vec bs_load(const void *p) { return _mm512_loadu_si512(p); }
static BS_FORCE_INLINE void bs_store(void *p, bs_vec a) { _mm512_storeu_si512(p,a); }
#elif defined(AVX2) || defined(__AVX2__)
#include <immintrin.h>
typedef __m256i bs_vec;
#define BS_LANES 256U
#define BS_BYTES 32U
static BS_FORCE_INLINE bs_vec bs_zero(void) { return _mm256_setzero_si256(); }
static BS_FORCE_INLINE bs_vec bs_ones(void) { return _mm256_set1_epi32(-1); }
static BS_FORCE_INLINE bs_vec bs_xor(bs_vec a, bs_vec b) { return _mm256_xor_si256(a,b); }
static BS_FORCE_INLINE bs_vec bs_and(bs_vec a, bs_vec b) { return _mm256_and_si256(a,b); }
static BS_FORCE_INLINE bs_vec bs_or(bs_vec a, bs_vec b) { return _mm256_or_si256(a,b); }
static BS_FORCE_INLINE bs_vec bs_not(bs_vec a) { return _mm256_xor_si256(a,bs_ones()); }
static BS_FORCE_INLINE bs_vec bs_load(const void *p) { return _mm256_loadu_si256((const __m256i*)p); }
static BS_FORCE_INLINE void bs_store(void *p, bs_vec a) { _mm256_storeu_si256((__m256i*)p,a); }
#elif defined(SSE2) || defined(__SSE2__)
#include <emmintrin.h>
typedef __m128i bs_vec;
#define BS_LANES 128U
#define BS_BYTES 16U
static BS_FORCE_INLINE bs_vec bs_zero(void) { return _mm_setzero_si128(); }
static BS_FORCE_INLINE bs_vec bs_ones(void) { return _mm_set1_epi32(-1); }
static BS_FORCE_INLINE bs_vec bs_xor(bs_vec a, bs_vec b) { return _mm_xor_si128(a,b); }
static BS_FORCE_INLINE bs_vec bs_and(bs_vec a, bs_vec b) { return _mm_and_si128(a,b); }
static BS_FORCE_INLINE bs_vec bs_or(bs_vec a, bs_vec b) { return _mm_or_si128(a,b); }
static BS_FORCE_INLINE bs_vec bs_not(bs_vec a) { return _mm_xor_si128(a,bs_ones()); }
static BS_FORCE_INLINE bs_vec bs_load(const void *p) { return _mm_loadu_si128((const __m128i*)p); }
static BS_FORCE_INLINE void bs_store(void *p, bs_vec a) { _mm_storeu_si128((__m128i*)p,a); }
#elif defined(LMCRACK_NEON) || defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
typedef uint8x16_t bs_vec;
#define BS_LANES 128U
#define BS_BYTES 16U
static BS_FORCE_INLINE bs_vec bs_zero(void) { return vdupq_n_u8(0); }
static BS_FORCE_INLINE bs_vec bs_ones(void) { return vdupq_n_u8(0xff); }
static BS_FORCE_INLINE bs_vec bs_xor(bs_vec a, bs_vec b) { return veorq_u8(a,b); }
static BS_FORCE_INLINE bs_vec bs_and(bs_vec a, bs_vec b) { return vandq_u8(a,b); }
static BS_FORCE_INLINE bs_vec bs_or(bs_vec a, bs_vec b) { return vorrq_u8(a,b); }
static BS_FORCE_INLINE bs_vec bs_not(bs_vec a) { return vmvnq_u8(a); }
static BS_FORCE_INLINE bs_vec bs_load(const void *p) { return vld1q_u8((const uint8_t*)p); }
static BS_FORCE_INLINE void bs_store(void *p, bs_vec a) { vst1q_u8((uint8_t*)p,a); }
#else
typedef uint64_t bs_vec;
#define BS_LANES 64U
#define BS_BYTES 8U
static BS_FORCE_INLINE bs_vec bs_zero(void) { return UINT64_C(0); }
static BS_FORCE_INLINE bs_vec bs_ones(void) { return UINT64_MAX; }
static BS_FORCE_INLINE bs_vec bs_xor(bs_vec a, bs_vec b) { return a^b; }
static BS_FORCE_INLINE bs_vec bs_and(bs_vec a, bs_vec b) { return a&b; }
static BS_FORCE_INLINE bs_vec bs_or(bs_vec a, bs_vec b) { return a|b; }
static BS_FORCE_INLINE bs_vec bs_not(bs_vec a) { return ~a; }
static BS_FORCE_INLINE bs_vec bs_load(const void *p) { bs_vec v; memcpy(&v,p,sizeof(v)); return v; }
static BS_FORCE_INLINE void bs_store(void *p, bs_vec a) { memcpy(p,&a,sizeof(a)); }
#endif

/* Select bits from b where mask is set, otherwise from a. */
static BS_FORCE_INLINE bs_vec bs_select(bs_vec a, bs_vec b, bs_vec mask)
{
#if defined(LMCRACK_NEON) || defined(__aarch64__) || defined(_M_ARM64)
    return vbslq_u8(mask,b,a);
#else
    return bs_xor(a,bs_and(bs_xor(a,b),mask));
#endif
}

/* a AND NOT b; a single instruction on each supported SIMD backend. */
static BS_FORCE_INLINE bs_vec bs_andnot(bs_vec a, bs_vec b)
{
#if defined(LMCRACK_BITSLICE_SCALAR)
    return a&~b;
#elif defined(AVX512) || defined(__AVX512F__)
    return _mm512_andnot_si512(b,a);
#elif defined(AVX2) || defined(__AVX2__)
    return _mm256_andnot_si256(b,a);
#elif defined(SSE2) || defined(__SSE2__)
    return _mm_andnot_si128(b,a);
#elif defined(LMCRACK_NEON) || defined(__aarch64__) || defined(_M_ARM64)
    return vbicq_u8(a,b);
#else
    return a&~b;
#endif
}

#if defined(__cplusplus)
static_assert(sizeof(bs_vec)==BS_BYTES,"bitslice vector size mismatch");
static_assert(BS_LANES==BS_BYTES*8U,"bitslice lane count mismatch");
#endif

static BS_FORCE_INLINE bs_vec bs_valid_lane_mask(size_t valid_lanes)
{
    uint8_t packed[BS_BYTES];
    size_t full_bytes,remainder;
    if (valid_lanes>BS_LANES) valid_lanes=BS_LANES;
    memset(packed,0,sizeof(packed));
    full_bytes=valid_lanes>>3;
    remainder=valid_lanes&7U;
    if (full_bytes!=0) memset(packed,0xff,full_bytes);
    if (remainder!=0) packed[full_bytes]=(uint8_t)((1U<<remainder)-1U);
    return bs_load(packed);
}

/* True when at least one bitslice lane is set. */
static BS_FORCE_INLINE int bs_any(bs_vec value)
{
#if defined(LMCRACK_BITSLICE_SCALAR)
    return value!=UINT64_C(0);
#elif defined(AVX512) || defined(__AVX512F__)
    return _mm512_cmpeq_epi64_mask(value,bs_zero())!=(__mmask8)0xff;
#elif defined(AVX2) || defined(__AVX2__)
    return (unsigned int)_mm256_movemask_epi8(
             _mm256_cmpeq_epi8(value,bs_zero()))!=UINT32_MAX;
#elif defined(SSE2) || defined(__SSE2__)
    return _mm_movemask_epi8(_mm_cmpeq_epi8(value,bs_zero()))!=0xffff;
#elif defined(LMCRACK_NEON) || defined(__aarch64__) || defined(_M_ARM64)
    return vmaxvq_u8(value)!=0;
#else
    return value!=UINT64_C(0);
#endif
}

#undef BS_FORCE_INLINE

#endif
