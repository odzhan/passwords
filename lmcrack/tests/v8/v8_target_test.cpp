#include <cstdint>
#include <cstring>

#include "v8_direct_des.h"
#include "v8_target.h"

static int equal_vec(bs_vec a,bs_vec b)
{
    uint8_t aa[BS_BYTES],bb[BS_BYTES];
    bs_store(aa,a);
    bs_store(bb,b);
    return std::memcmp(aa,bb,sizeof(aa))==0;
}

static unsigned int lane_bit(bs_vec value,size_t lane)
{
    uint8_t bytes[BS_BYTES];
    bs_store(bytes,value);
    return (bytes[lane>>3]>>(lane&7U))&1U;
}

static void extract_lane_block(const bs_vec planes[BS_BLOCK_PLANES],
                               size_t lane,uint8_t block[8])
{
    std::memset(block,0,8);
    for (size_t bit=0;bit<BS_BLOCK_PLANES;bit++)
      if (lane_bit(planes[bit],lane))
        block[bit>>3]|=(uint8_t)(1U<<(7U-(bit&7U)));
}

static int verify_preparation(const uint8_t target[8],
                              const v8_target_state *state)
{
    for (size_t bit=0;bit<32;bit++) {
      unsigned int rs=bs_des_ip[bit]-1U;
      unsigned int ls=bs_des_ip[32U+bit]-1U;
      unsigned int expected_right=(target[rs>>3]>>(7U-(rs&7U)))&1U;
      unsigned int expected_left=(target[ls>>3]>>(7U-(ls&7U)))&1U;
      if (state->right[bit]!=expected_right) return 1;
      if (state->left[bit]!=expected_left) return 2;
    }
    return 0;
}

static int run_case(uint64_t start,size_t generated_lanes,size_t target_lane,
                    size_t valid_lanes)
{
    v8_bitslice_counter counter;
    bs_vec password[V8_LM_KEY_PLANES],output[BS_BLOCK_PLANES];
    bs_block_state state;
    uint8_t target[8];
    v8_target_state prepared;

    if (generated_lanes==0 || generated_lanes>BS_LANES ||
        target_lane>=BS_LANES) return 1;
    if (!v8_bs_counter_init(&counter,start,generated_lanes)) return 2;
    if (!v8_bs_make_key_planes(&counter,password)) return 3;
    if (!bs_copy_lm_plaintext_state(&state)) return 4;
    v8_bs_des_rounds(state.left,state.right,password);
    if (!bs_final_permutation(state.left,state.right,output)) return 5;

    extract_lane_block(output,target_lane,target);
    if (!v8_prepare_target_state(target,&prepared)) return 6;
    if (verify_preparation(target,&prepared)) return 7;

    bs_vec conventional=bs_match_valid_block(output,target,valid_lanes);
    bs_vec full=v8_match_target_state_full(state.left,state.right,&prepared,
                                           valid_lanes);
    bs_vec direct=v8_match_target_state(state.left,state.right,&prepared,
                                        valid_lanes);
    if (!equal_vec(conventional,full)) return 8;
    if (!equal_vec(full,direct)) return 9;
    if (lane_bit(direct,target_lane)!=(unsigned int)(target_lane<valid_lanes))
      return 10;
    return 0;
}

int main(void)
{
    bs_sbox_init();
    bs_init_lm_plaintext_state();

    if (bs_any(bs_zero()) || !bs_any(bs_valid_lane_mask(1))) return 6;
    {
      alignas(64) bs_vec left[32],right[32];
      v8_target_state impossible;
      for (size_t bit=0;bit<32;bit++) {
        left[bit]=right[bit]=bs_zero();
        impossible.left[bit]=impossible.right[bit]=1;
      }
      bs_vec full=v8_match_target_state_full(left,right,&impossible,BS_LANES);
      bs_vec staged=v8_match_target_state(left,right,&impossible,BS_LANES);
      if (bs_any(full) || bs_any(staged) || !equal_vec(full,staged)) return 7;
    }

    if (run_case(0,BS_LANES,0,BS_LANES)) return 1;
    if (run_case(26,BS_LANES,BS_LANES/2U,BS_LANES)) return 2;
    if (run_case(v8_length_block_start(5)+12345U,BS_LANES,
                 BS_LANES-1U,BS_LANES)) return 3;

    {
      size_t partial=BS_LANES>17U?BS_LANES-17U:BS_LANES-1U;
      if (run_case(695,partial,partial-1U,partial)) return 4;
      if (run_case(695,partial,partial,partial)) return 5;
    }
    return 0;
}
