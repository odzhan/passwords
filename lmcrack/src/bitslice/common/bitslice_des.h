#ifndef LMCRACK_BITSLICE_DES_H
#define LMCRACK_BITSLICE_DES_H

#include "bitslice_key.h"
#include "bitslice_sbox.h"

static const uint8_t bs_des_e[48]={
  32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
  12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,
  24,25,26,27,28,29,28,29,30,31,32,1
};
static const uint8_t bs_des_p[32]={
  16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
  2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
};

static inline void bs_des_f(const bs_vec right[32],
                            const bs_vec round_key[48],bs_vec output[32])
{
    bs_vec substituted[32],input[6],sbox_output[4];
    for(unsigned box=0;box<8;box++) {
      for(unsigned bit=0;bit<6;bit++) {
        unsigned expanded=box*6U+bit;
        input[bit]=bs_xor(right[bs_des_e[expanded]-1U],round_key[expanded]);
      }
      bs_sbox_optimized(box,input,sbox_output);
      for(unsigned bit=0;bit<4;bit++) substituted[box*4U+bit]=sbox_output[bit];
    }
    for(unsigned bit=0;bit<32;bit++) output[bit]=substituted[bs_des_p[bit]-1U];
}

/* Input/output arrays use canonical MSB-first L/R bit numbering. */
static inline void bs_des_rounds(bs_vec left[32],bs_vec right[32],
                                 const bs_key_schedule *schedule)
{
    bs_vec f[32];
    bs_vec *l=left,*r=right,*swap;
    for(unsigned round=0;round<16;round++) {
      bs_des_f(r,schedule->plane[round],f);
      for(unsigned bit=0;bit<32;bit++) l[bit]=bs_xor(l[bit],f[bit]);
      swap=l;l=r;r=swap;
    }
}

#endif
