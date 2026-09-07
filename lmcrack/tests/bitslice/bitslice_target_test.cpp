#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "des.h"
#include "bitslice_target.h"
#include "v8_direct_des.h"

static unsigned int lane_bit(bs_vec value,size_t lane)
{
    uint8_t bytes[BS_BYTES];
    bs_store(bytes,value);
    return (bytes[lane>>3]>>(lane&7U))&1U;
}

int main(void)
{
    const uint8_t plaintext[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    uint8_t password[7]={'A',0,0,0,0,0,0};
    DES_cblock des_key,input,output;
    DES_key_schedule schedule;
    v8_bitslice_counter counter;
    bs_vec key_planes[V8_LM_KEY_PLANES];
    bs_block_state state;
    bs_target_state target;

    memcpy(input,plaintext,sizeof(input));
    DES_str_to_key(password,des_key);
    DES_set_key(&des_key,&schedule);
    DES_ecb_encrypt(&input,&output,&schedule,1);

    bs_sbox_init();
    assert(v8_bs_counter_init(&counter,0,BS_LANES));
    assert(v8_bs_make_key_planes(&counter,key_planes));
    assert(bs_prepare_plaintext_state(plaintext,&state));
    v8_bs_des_rounds(state.left,state.right,key_planes);
    assert(bs_prepare_target_state(output,&target));

    const bs_vec full=bs_match_target_state_full(
      state.left,state.right,&target,BS_LANES);
    const bs_vec staged=bs_match_target_state(
      state.left,state.right,&target,BS_LANES);
    assert(lane_bit(full,0)==1U);
    assert(lane_bit(staged,0)==1U);
    for (size_t lane=1;lane<BS_LANES;lane++)
      assert(lane_bit(full,lane)==lane_bit(staged,lane));

    assert(!bs_any(bs_match_target_state(
      state.left,state.right,&target,0)));
    assert(!bs_prepare_target_state(NULL,&target));
    assert(!bs_prepare_target_state(output,NULL));
    return 0;
}
