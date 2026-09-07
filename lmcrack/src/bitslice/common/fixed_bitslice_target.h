#ifndef LMCRACK_FIXED_BITSLICE_TARGET_H
#define LMCRACK_FIXED_BITSLICE_TARGET_H

/* Alphabet-neutral compatibility interface retained for v9. */
#include "bitslice_target.h"

typedef bs_target_state fixed_target_state;

static inline int fixed_prepare_target_state(const uint8_t target[8],
                                             fixed_target_state *state)
{
    return bs_prepare_target_state(target,state);
}

#if defined(_MSC_VER)
#define FIXED_TARGET_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define FIXED_TARGET_FORCE_INLINE inline __attribute__((always_inline))
#else
#define FIXED_TARGET_FORCE_INLINE inline
#endif

static FIXED_TARGET_FORCE_INLINE bs_vec fixed_match_target_state(
    const bs_vec left[32],const bs_vec right[32],
    const fixed_target_state *target,size_t valid_lanes)
{
    return bs_match_target_state(left,right,target,valid_lanes);
}

#undef FIXED_TARGET_FORCE_INLINE

#endif
