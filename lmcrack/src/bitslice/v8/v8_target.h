#ifndef LMCRACK_V8_TARGET_H
#define LMCRACK_V8_TARGET_H

#include <stddef.h>
#include <stdint.h>

#include "bitslice_block.h"

#if defined(_MSC_VER)
#define V8_TARGET_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define V8_TARGET_FORCE_INLINE inline __attribute__((always_inline))
#else
#define V8_TARGET_FORCE_INLINE inline
#endif

/*
 * Expected DES state after round 16.  DES IP applied to the ciphertext gives
 * the preoutput R16 || L16, while the round functions retain L16 and R16 as
 * separate arrays.  Keeping single-bit constants avoids broadcasting and
 * permuting the target for every candidate batch.
 */
typedef struct {
    uint8_t left[32];
    uint8_t right[32];
} v8_target_state;

static inline int v8_prepare_target_state(const uint8_t target[8],
                                          v8_target_state *state)
{
    size_t bit;
    if (target==NULL || state==NULL) return 0;
    for (bit=0;bit<32;bit++) {
      unsigned int right_source=bs_des_ip[bit]-1U;
      unsigned int left_source=bs_des_ip[32U+bit]-1U;
      state->right[bit]=(uint8_t)((target[right_source>>3] >>
                         (7U-(right_source&7U)))&1U);
      state->left[bit]=(uint8_t)((target[left_source>>3] >>
                        (7U-(left_source&7U)))&1U);
    }
    return 1;
}

/* Full comparison retained as a simple reference for differential tests. */
static V8_TARGET_FORCE_INLINE bs_vec v8_match_target_state_full(
    const bs_vec left[32],const bs_vec right[32],
    const v8_target_state *target,size_t valid_lanes)
{
    bs_vec match=bs_valid_lane_mask(valid_lanes);
    for (size_t bit=0;bit<32;bit++) {
      match=bs_and(match,target->left[bit]?left[bit]:bs_not(left[bit]));
      match=bs_and(match,target->right[bit]?right[bit]:bs_not(right[bit]));
    }
    return match;
}

/*
 * Test 16 state planes first.  A nonmatching lane has probability 1/65536 of
 * surviving this prefix, so the normal no-match batch avoids 48 vector ANDs
 * and complements.  Returning zero here is safe because subsequent equality
 * tests can only clear lanes; they can never restore one.
 */
static V8_TARGET_FORCE_INLINE bs_vec v8_match_target_state(
    const bs_vec left[32],const bs_vec right[32],
    const v8_target_state *target,size_t valid_lanes)
{
    bs_vec match=bs_valid_lane_mask(valid_lanes);
    size_t bit;
    for (bit=0;bit<8;bit++) {
      match=bs_and(match,target->left[bit]?left[bit]:bs_not(left[bit]));
      match=bs_and(match,target->right[bit]?right[bit]:bs_not(right[bit]));
    }
    if (!bs_any(match)) return match;
    for (;bit<32;bit++) {
      match=bs_and(match,target->left[bit]?left[bit]:bs_not(left[bit]));
      match=bs_and(match,target->right[bit]?right[bit]:bs_not(right[bit]));
    }
    return match;
}

#undef V8_TARGET_FORCE_INLINE

#endif
