#ifndef LMCRACK_BITSLICE_BLOCK_H
#define LMCRACK_BITSLICE_BLOCK_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bitslice_vec.h"

#define BS_BLOCK_PLANES 64U

static const uint8_t bs_des_ip[BS_BLOCK_PLANES]={
  58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
  62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
  57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};
static const uint8_t bs_des_fp[BS_BLOCK_PLANES]={
  40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
  38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
  36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};

/*
 * Broadcast one external DES block into SIMD planes. Plane zero is the
 * most-significant bit of input[0]; plane 63 is the least-significant bit
 * of input[7]. Every candidate lane receives the same block bit.
 */
static inline int bs_broadcast_block(const uint8_t input[8],
                                     bs_vec planes[BS_BLOCK_PLANES])
{
    size_t plane;
    if (input==NULL || planes==NULL) return 0;
    for (plane=0;plane<BS_BLOCK_PLANES;plane++) {
      unsigned int bit=(input[plane>>3]>>(7U-(plane&7U)))&1U;
      planes[plane]=bit?bs_ones():bs_zero();
    }
    return 1;
}

/* Apply canonical DES IP and split its MSB-first output into L0 and R0. */
static inline int bs_initial_permutation(const bs_vec input[BS_BLOCK_PLANES],
                                         bs_vec left[32],bs_vec right[32])
{
    size_t bit;
    if (input==NULL || left==NULL || right==NULL) return 0;
    for (bit=0;bit<32;bit++) {
      left[bit]=input[bs_des_ip[bit]-1U];
      right[bit]=input[bs_des_ip[32U+bit]-1U];
    }
    return 1;
}

/* DES preoutput is R16 || L16. Output remains in external MSB-first planes. */
static inline int bs_final_permutation(const bs_vec left[32],
                                       const bs_vec right[32],
                                       bs_vec output[BS_BLOCK_PLANES])
{
    size_t bit;
    if (left==NULL || right==NULL || output==NULL) return 0;
    for (bit=0;bit<BS_BLOCK_PLANES;bit++) {
      unsigned int source=bs_des_fp[bit]-1U;
      output[bit]=(source<32U)?right[source]:left[source-32U];
    }
    return 1;
}

/* Return one set bit for each lane whose external ciphertext equals target. */
static inline bs_vec bs_match_block(const bs_vec output[BS_BLOCK_PLANES],
                                    const uint8_t target[8])
{
    bs_vec match=bs_ones();
    for (size_t bit=0;bit<BS_BLOCK_PLANES;bit++) {
      unsigned int expected=(target[bit>>3]>>(7U-(bit&7U)))&1U;
      match=bs_and(match,expected?output[bit]:bs_not(output[bit]));
    }
    return match;
}

static inline bs_vec bs_match_valid_block(const bs_vec output[BS_BLOCK_PLANES],
    const uint8_t target[8],size_t valid_lanes)
{
    return bs_and(bs_match_block(output,target),bs_valid_lane_mask(valid_lanes));
}

typedef struct {
    bs_vec left[32];
    bs_vec right[32];
} bs_block_state;

static bs_block_state bs_lm_plaintext_state;
static int bs_lm_plaintext_ready=0;

/* Call once before starting v7 worker threads. */
static inline void bs_init_lm_plaintext_state(void)
{
    static const uint8_t plaintext[8]={'K','G','S','!','@','#','$','%'};
    bs_vec input[BS_BLOCK_PLANES];
    bs_broadcast_block(plaintext,input);
    bs_initial_permutation(input,bs_lm_plaintext_state.left,
                           bs_lm_plaintext_state.right);
    bs_lm_plaintext_ready=1;
}

static inline int bs_copy_lm_plaintext_state(bs_block_state *state)
{
    if (state==NULL || !bs_lm_plaintext_ready) return 0;
    memcpy(state,&bs_lm_plaintext_state,sizeof(*state));
    return 1;
}

#endif
