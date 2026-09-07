#include <cstdint>
#include <cstring>

#include "bitslice_block.h"
#include "v8_direct_des.h"

static int verify_mapping(void)
{
    uint8_t cd[56],next[56];
    for (unsigned int i=0;i<56;i++) cd[i]=bs_lm_plane_for_des_bit(bs_pc1[i]);
    for (unsigned int round=0;round<BS_DES_ROUNDS;round++) {
      unsigned int shift=bs_key_shifts[round];
      for (unsigned int i=0;i<28;i++) {
        next[i]=cd[(i+shift)%28U];
        next[28+i]=cd[28+(i+shift)%28U];
      }
      for (unsigned int i=0;i<56;i++) cd[i]=next[i];
      for (unsigned int i=0;i<BS_ROUND_KEY_PLANES;i++)
        if (v8_round_key_plane[round][i]!=cd[bs_pc2[i]-1U])
          return 1+(int)(round*BS_ROUND_KEY_PLANES+i);
    }
    return 0;
}

static int equal_vec(bs_vec a,bs_vec b)
{
    uint8_t aa[BS_BYTES],bb[BS_BYTES];
    bs_store(aa,a);
    bs_store(bb,b);
    return std::memcmp(aa,bb,sizeof(aa))==0;
}

static int run_range(uint64_t start,uint64_t count)
{
    v8_bitslice_counter counter;
    if (!v8_bs_counter_init(&counter,start,count)) return 1;
    for (;;) {
      bs_vec password[V8_LM_KEY_PLANES];
      bs_key_schedule schedule;
      bs_block_state regular,direct;
      bs_vec regular_output[BS_BLOCK_PLANES],direct_output[BS_BLOCK_PLANES];

      if (!v8_bs_make_key_planes(&counter,password)) return 2;
      bs_make_key_schedule(password,&schedule);
      for (unsigned int round=0;round<BS_DES_ROUNDS;round++)
        for (unsigned int bit=0;bit<BS_ROUND_KEY_PLANES;bit++)
          if (!equal_vec(schedule.plane[round][bit],
                         password[v8_round_key_plane[round][bit]])) return 3;

      if (!bs_copy_lm_plaintext_state(&regular)) return 4;
      direct=regular;
      bs_des_rounds(regular.left,regular.right,&schedule);
      v8_bs_des_rounds(direct.left,direct.right,password);
      for (unsigned int bit=0;bit<32;bit++) {
        if (!equal_vec(regular.left[bit],direct.left[bit])) return 5;
        if (!equal_vec(regular.right[bit],direct.right[bit])) return 6;
      }

      if (!bs_final_permutation(regular.left,regular.right,regular_output) ||
          !bs_final_permutation(direct.left,direct.right,direct_output)) return 7;
      for (unsigned int bit=0;bit<BS_BLOCK_PLANES;bit++)
        if (!equal_vec(regular_output[bit],direct_output[bit])) return 8;

      if (!v8_bs_counter_advance(&counter)) break;
    }
    return 0;
}

int main(void)
{
    int mapping_result=verify_mapping();
    if (mapping_result) return mapping_result;
    bs_sbox_init();
    bs_init_lm_plaintext_state();

    if (run_range(0,BS_LANES*2U+17U)) return 1;
    if (run_range(695,BS_LANES+19U)) return 2;
    if (run_range(v8_length_block_start(5)+12345,BS_LANES*3U+1U)) return 3;
    if (run_range(V8_TOTAL_CANDIDATES-(BS_LANES+13U),BS_LANES+13U)) return 4;
    return 0;
}
