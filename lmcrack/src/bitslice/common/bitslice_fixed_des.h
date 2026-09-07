#ifndef LMCRACK_BITSLICE_FIXED_DES_H
#define LMCRACK_BITSLICE_FIXED_DES_H

#include "bitslice_block.h"
#include "bitslice_des.h"

/*
 * PC-1, all cumulative round rotations, and PC-2 collapsed to indexes in the
 * original 56 LSB-first LM password planes.  This table is immutable and lets
 * fixed-alphabet workers select round keys without materializing a 16 x 48
 * vector schedule.
 */
static const uint8_t bs_fixed_round_key_plane[BS_DES_ROUNDS][BS_ROUND_KEY_PLANES]={
  {15,43,26,51,45,9,27,54,6,0,23,35,5,25,17,18,33,53,52,7,24,16,8,36,20,31,37,40,39,4,46,29,3,41,19,30,50,21,38,48,10,22,32,11,12,49,55,28},
  {6,34,17,42,36,0,18,45,52,7,14,26,51,16,8,9,24,44,43,53,54,23,15,27,11,22,28,47,30,48,37,20,31,32,10,21,41,12,29,55,1,13,39,2,3,40,46,19},
  {43,16,15,24,18,53,0,27,34,44,51,8,33,14,6,7,45,26,25,35,36,5,52,9,50,4,10,29,12,46,19,2,13,30,49,3,39,31,11,37,40,48,21,41,22,38,28,1},
  {25,14,52,45,0,35,53,9,16,26,33,6,54,51,43,44,27,8,23,17,18,42,34,7,32,55,49,11,31,28,1,41,48,12,47,22,21,13,50,19,38,46,3,39,4,20,10,40},
  {23,51,34,27,53,17,35,7,14,8,54,43,36,33,25,26,9,6,5,15,0,24,16,44,30,37,47,50,13,10,40,39,46,31,29,4,3,48,32,1,20,28,22,21,55,2,49,38},
  {5,33,16,9,35,15,17,44,51,6,36,25,18,54,23,8,7,43,42,52,53,45,14,26,12,19,29,32,48,49,38,21,28,13,11,55,22,46,30,40,2,10,4,3,37,41,47,20},
  {42,54,14,7,17,52,15,26,33,43,18,23,0,36,5,6,44,25,24,34,35,27,51,8,31,1,11,30,46,47,20,3,10,48,50,37,4,28,12,38,41,49,55,22,19,39,29,2},
  {24,36,51,44,15,34,52,8,54,25,0,5,53,18,42,43,26,23,45,16,17,9,33,6,13,40,50,12,28,29,2,22,49,46,32,19,55,10,31,20,39,47,37,4,1,21,11,41},
  {54,27,42,35,6,25,43,15,45,16,7,51,44,9,33,34,17,14,36,23,8,0,24,52,4,47,41,3,19,20,50,13,40,37,39,10,46,1,22,11,30,38,28,48,49,12,2,32},
  {36,9,24,17,43,23,25,52,27,14,44,33,26,7,54,16,15,51,18,5,6,53,45,34,55,29,39,22,1,2,32,48,38,19,21,49,28,40,4,50,12,20,10,46,47,31,41,30},
  {18,7,45,15,25,5,23,34,9,51,26,54,8,44,36,14,52,33,0,42,43,35,27,16,37,11,21,4,40,41,30,46,20,1,3,47,10,38,55,32,31,2,49,28,29,13,39,12},
  {0,44,27,52,23,42,5,16,7,33,8,36,6,26,18,51,34,54,53,24,25,17,9,14,19,50,3,55,38,39,12,28,2,40,22,29,49,20,37,30,13,41,47,10,11,48,21,31},
  {53,26,9,34,5,24,42,14,44,54,6,18,43,8,0,33,16,36,35,45,23,15,7,51,1,32,22,37,20,21,31,10,41,38,4,11,47,2,19,12,48,39,29,49,50,46,3,13},
  {35,8,7,16,42,45,24,51,26,36,43,0,25,6,53,54,14,18,17,27,5,52,44,33,40,30,4,19,2,3,13,49,39,20,55,50,29,41,1,31,46,21,11,47,32,28,22,48},
  {17,6,44,14,24,27,45,33,8,18,25,53,23,43,35,36,51,0,15,9,42,34,26,54,38,12,55,1,41,22,48,47,21,2,37,32,11,39,40,13,28,3,50,29,30,10,4,46},
  {8,52,35,5,54,18,36,24,15,9,16,44,14,34,26,27,42,7,6,0,33,25,17,45,29,3,46,49,32,13,55,38,12,50,28,39,2,30,47,4,19,31,41,20,21,1,48,37}
};

template <unsigned int Round>
static inline void bs_fixed_des_f(const bs_vec right[32],
                                  const bs_vec password[BS_KEY_PLANES],
                                  bs_vec output[32])
{
    static_assert(Round<BS_DES_ROUNDS,"invalid DES round");
    bs_vec substituted[32],input[6],sbox_output[4];
    for (unsigned int box=0;box<8;box++) {
      for (unsigned int bit=0;bit<6;bit++) {
        unsigned int expanded=box*6U+bit;
        input[bit]=bs_xor(right[bs_des_e[expanded]-1U],
                          password[bs_fixed_round_key_plane[Round][expanded]]);
      }
      bs_sbox_optimized(box,input,sbox_output);
      for (unsigned int bit=0;bit<4;bit++)
        substituted[box*4U+bit]=sbox_output[bit];
    }
    for (unsigned int bit=0;bit<32;bit++)
      output[bit]=substituted[bs_des_p[bit]-1U];
}

template <unsigned int Round>
static inline void bs_fixed_apply_round(bs_vec destination[32],
                                        const bs_vec source[32],
                                        const bs_vec password[BS_KEY_PLANES])
{
    bs_vec f[32];
    bs_fixed_des_f<Round>(source,password,f);
    for (unsigned int bit=0;bit<32;bit++)
      destination[bit]=bs_xor(destination[bit],f[bit]);
}

/* Explicit calls keep Round constant and expose every key-plane index. */
static inline void bs_fixed_des_rounds(bs_vec left[32],bs_vec right[32],
                                       const bs_vec password[BS_KEY_PLANES])
{
    bs_fixed_apply_round<0>(left,right,password);
    bs_fixed_apply_round<1>(right,left,password);
    bs_fixed_apply_round<2>(left,right,password);
    bs_fixed_apply_round<3>(right,left,password);
    bs_fixed_apply_round<4>(left,right,password);
    bs_fixed_apply_round<5>(right,left,password);
    bs_fixed_apply_round<6>(left,right,password);
    bs_fixed_apply_round<7>(right,left,password);
    bs_fixed_apply_round<8>(left,right,password);
    bs_fixed_apply_round<9>(right,left,password);
    bs_fixed_apply_round<10>(left,right,password);
    bs_fixed_apply_round<11>(right,left,password);
    bs_fixed_apply_round<12>(left,right,password);
    bs_fixed_apply_round<13>(right,left,password);
    bs_fixed_apply_round<14>(left,right,password);
    bs_fixed_apply_round<15>(right,left,password);
}

static inline int bs_fixed_encrypt_state(bs_block_state *state,
                                         const bs_vec password[BS_KEY_PLANES])
{
    if (state==NULL || password==NULL) return 0;
    bs_fixed_des_rounds(state->left,state->right,password);
    return 1;
}

#endif
