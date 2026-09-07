#ifndef LMCRACK_BITSLICE_KEY_H
#define LMCRACK_BITSLICE_KEY_H

#include <stdint.h>
#include "bitslice_transpose.h"

#define BS_DES_ROUNDS 16U
#define BS_ROUND_KEY_PLANES 48U

typedef struct { bs_vec plane[BS_DES_ROUNDS][BS_ROUND_KEY_PLANES]; } bs_key_schedule;

#if defined(__cplusplus)
static_assert(BS_KEY_PLANES==56U,"DES must have 56 source key planes");
static_assert(BS_DES_ROUNDS==16U,"DES must have 16 rounds");
static_assert(BS_ROUND_KEY_PLANES==48U,"DES round keys must have 48 planes");
#endif

static const uint8_t bs_pc1[56]={
  57,49,41,33,25,17,9,1,58,50,42,34,26,18,
  10,2,59,51,43,35,27,19,11,3,60,52,44,36,
  63,55,47,39,31,23,15,7,62,54,46,38,30,22,
  14,6,61,53,45,37,29,21,13,5,28,20,12,4
};
static const uint8_t bs_pc2[48]={
  14,17,11,24,1,5,3,28,15,6,21,10,
  23,19,12,4,26,8,16,7,27,20,13,2,
  41,52,31,37,47,55,30,40,51,45,33,48,
  44,49,39,56,34,53,46,42,50,36,29,32
};
static const uint8_t bs_key_shifts[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

/* Convert a 1-based DES key bit (parity excluded by PC-1) to an LSB-first
 * plane in the original seven LM password bytes. */
static inline uint8_t bs_lm_plane_for_des_bit(unsigned int des_bit)
{
    unsigned int zero=des_bit-1U;
    unsigned int stream=(zero>>3)*7U+(zero&7U);
    return (uint8_t)((stream>>3)*8U+7U-(stream&7U));
}

static inline void bs_make_key_schedule(const bs_vec password[BS_KEY_PLANES],
                                        bs_key_schedule *schedule)
{
    uint8_t cd[56], next[56];
    unsigned int i, round, shift;
    for (i=0;i<56;i++) cd[i]=bs_lm_plane_for_des_bit(bs_pc1[i]);
    for (round=0;round<BS_DES_ROUNDS;round++) {
      shift=bs_key_shifts[round];
      for (i=0;i<28;i++) {
        next[i]=cd[(i+shift)%28U];
        next[28+i]=cd[28+(i+shift)%28U];
      }
      for (i=0;i<56;i++) cd[i]=next[i];
      for (i=0;i<BS_ROUND_KEY_PLANES;i++)
        schedule->plane[round][i]=password[cd[bs_pc2[i]-1U]];
    }
}

#endif
