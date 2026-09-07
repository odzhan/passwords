#ifndef LMCRACK_BITSLICE_SBOX_H
#define LMCRACK_BITSLICE_SBOX_H

#include "bitslice_vec.h"

/* Canonical DES S-boxes, stored as four rows of sixteen columns. */
static const uint8_t bs_des_sbox[8][1][64]={
{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

static inline uint8_t bs_sbox_value(unsigned box,unsigned input)
{
    unsigned row=((input&0x20U)>>4)|(input&1U);
    unsigned col=(input>>1)&0x0fU;
    return bs_des_sbox[box][0][row*16U+col];
}

/* Reference implementation. Input and output planes are MSB first. */
static inline void bs_sbox_reference(unsigned box,const bs_vec input[6],
                                     bs_vec output[4])
{
    for(unsigned ob=0;ob<4;ob++) output[ob]=bs_zero();
    for(unsigned value=0;value<64;value++) {
      bs_vec term=bs_ones();
      for(unsigned bit=0;bit<6;bit++) {
        bs_vec selected=((value>>(5U-bit))&1U)?input[bit]:bs_not(input[bit]);
        term=bs_and(term,selected);
      }
      uint8_t result=bs_sbox_value(box,value);
      for(unsigned ob=0;ob<4;ob++)
        if ((result>>(3U-ob))&1U) output[ob]=bs_xor(output[ob],term);
    }
}

/*
 * Fixed minimized circuits generated for Openwall's John the Ripper.  Use the
 * 32.875-gate conditional-select family where select is native, and the
 * 44.125-gate AND/OR/XOR/AND-NOT family on SSE2 and AVX2.
 */
#define vtype bs_vec
#define MAYBE_INLINE inline
#define vxor(dst,a,b) ((dst)=bs_xor((a),(b)))
#define vand(dst,a,b) ((dst)=bs_and((a),(b)))
#define vor(dst,a,b)  ((dst)=bs_or((a),(b)))
#define vnot(dst,a)   ((dst)=bs_not((a)))
#define vsel(dst,a,b,mask) ((dst)=bs_select((a),(b),(mask)))
#define vandn(dst,a,b) ((dst)=bs_andnot((a),(b)))
#if defined(LMCRACK_NEON) || defined(__aarch64__) || defined(_M_ARM64) || \
    defined(AVX512) || defined(__AVX512F__)
#include "bitslice_sboxes_openwall.inc"
#else
#define andn 1
#include "bitslice_sboxes_openwall_std.inc"
#undef andn
#endif
#undef latency
#undef triop
#undef regs
#undef vandn
#undef vsel
#undef vnot
#undef vor
#undef vand
#undef vxor
#undef MAYBE_INLINE
#undef vtype

/* Kept as a no-op so existing one-time v7 initialization remains compatible. */
static inline void bs_sbox_init(void) {}

static inline void bs_sbox_optimized(unsigned box,const bs_vec input[6],
                                     bs_vec output[4])
{
    output[0]=output[1]=output[2]=output[3]=bs_zero();
    switch(box) {
      case 0: s1(input[0],input[1],input[2],input[3],input[4],input[5],
                 &output[0],&output[1],&output[2],&output[3]); break;
      case 1: s2(input[0],input[1],input[2],input[3],input[4],input[5],
                 &output[0],&output[1],&output[2],&output[3]); break;
      case 2: s3(input[0],input[1],input[2],input[3],input[4],input[5],
                 &output[0],&output[1],&output[2],&output[3]); break;
      case 3: s4(input[0],input[1],input[2],input[3],input[4],input[5],
                 &output[0],&output[1],&output[2],&output[3]); break;
      case 4: s5(input[0],input[1],input[2],input[3],input[4],input[5],
                 &output[0],&output[1],&output[2],&output[3]); break;
      case 5: s6(input[0],input[1],input[2],input[3],input[4],input[5],
                 &output[0],&output[1],&output[2],&output[3]); break;
      case 6: s7(input[0],input[1],input[2],input[3],input[4],input[5],
                 &output[0],&output[1],&output[2],&output[3]); break;
      default:s8(input[0],input[1],input[2],input[3],input[4],input[5],
                 &output[0],&output[1],&output[2],&output[3]); break;
    }
}

#endif
