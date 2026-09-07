#ifndef LMCRACK_V8_DIRECT_DES_H
#define LMCRACK_V8_DIRECT_DES_H

#include "bitslice_fixed_des.h"
#include "v8_key_planes.h"

#define v8_round_key_plane bs_fixed_round_key_plane

template <unsigned int Round>
static inline void v8_bs_des_f(const bs_vec right[32],
                               const bs_vec password[BS_KEY_PLANES],
                               bs_vec output[32])
{
    bs_fixed_des_f<Round>(right,password,output);
}

template <unsigned int Round>
static inline void v8_bs_apply_round(bs_vec destination[32],
                                     const bs_vec source[32],
                                     const bs_vec password[BS_KEY_PLANES])
{
    bs_fixed_apply_round<Round>(destination,source,password);
}

static inline void v8_bs_des_rounds(bs_vec left[32],bs_vec right[32],
                                    const bs_vec password[BS_KEY_PLANES])
{
    bs_fixed_des_rounds(left,right,password);
}

#endif
