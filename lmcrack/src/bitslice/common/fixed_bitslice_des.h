#ifndef LMCRACK_FIXED_BITSLICE_DES_H
#define LMCRACK_FIXED_BITSLICE_DES_H

/*
 * The schedule-free DES implementation was introduced by v8.  This neutral
 * interface lets additional fixed-alphabet generators reuse it without
 * duplicating the round-key mapping or round code.  The v8 names remain the
 * implementation ABI for its existing tests.
 */
#include "v8_direct_des.h"

#define fixed_round_key_plane v8_round_key_plane

static inline void fixed_bs_des_rounds(bs_vec left[32],bs_vec right[32],
                                       const bs_vec password[BS_KEY_PLANES])
{
    v8_bs_des_rounds(left,right,password);
}

#endif
