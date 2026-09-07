#ifndef LMCRACK_BITSLICE_TARGET_H
#define LMCRACK_BITSLICE_TARGET_H

/*
 * Generic target interface. The implementation remains behind the proven v8
 * compatibility layer until the neutral DES extraction in checklist step 5.
 */
#include "v8_target.h"

typedef v8_target_state bs_target_state;

static inline int bs_prepare_target_state(const uint8_t ciphertext[8],
                                          bs_target_state *state)
{
    return v8_prepare_target_state(ciphertext,state);
}

static inline bs_vec bs_match_target_state_full(
    const bs_vec left[32],const bs_vec right[32],
    const bs_target_state *target,size_t valid_lanes)
{
    return v8_match_target_state_full(left,right,target,valid_lanes);
}

static inline bs_vec bs_match_target_state(
    const bs_vec left[32],const bs_vec right[32],
    const bs_target_state *target,size_t valid_lanes)
{
    return v8_match_target_state(left,right,target,valid_lanes);
}

#endif
