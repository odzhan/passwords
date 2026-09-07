#ifndef LMCRACK_FIXED_BITSLICE_DES_H
#define LMCRACK_FIXED_BITSLICE_DES_H

/*
 * Compatibility interface retained for v9. New code should include
 * bitslice_fixed_des.h directly.
 */
#include "bitslice_fixed_des.h"
#include "v8_direct_des.h"

#define fixed_round_key_plane bs_fixed_round_key_plane

static inline void fixed_bs_des_rounds(bs_vec left[32],bs_vec right[32],
                                       const bs_vec password[BS_KEY_PLANES])
{
    bs_fixed_des_rounds(left,right,password);
}

#endif
