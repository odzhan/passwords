#include <cstdint>
#include <cstring>

#include "fixed_bitslice_des.h"
#include "fixed_bitslice_target.h"

static int equal_vec(bs_vec a,bs_vec b)
{
    uint8_t aa[BS_BYTES],bb[BS_BYTES]; bs_store(aa,a); bs_store(bb,b);
    return std::memcmp(aa,bb,sizeof(aa))==0;
}

int main(void)
{
    bs_sbox_init(); bs_init_lm_plaintext_state();
    v8_bitslice_counter counter;
    if (!v8_bs_counter_init(&counter,12345,BS_LANES)) return 1;
    bs_vec password[56]; bs_block_state legacy,shared;
    if (!v8_bs_make_key_planes(&counter,password) ||
        !bs_copy_lm_plaintext_state(&legacy)) return 2;
    shared=legacy;
    v8_bs_des_rounds(legacy.left,legacy.right,password);
    fixed_bs_des_rounds(shared.left,shared.right,password);
    for (unsigned int bit=0;bit<32;bit++)
      if (!equal_vec(legacy.left[bit],shared.left[bit]) ||
          !equal_vec(legacy.right[bit],shared.right[bit])) return 3;

    static const uint8_t hash[8]={0x1f,0xb3,0x63,0xfe,0xb8,0x34,0xc1,0x2d};
    v8_target_state old_target; fixed_target_state shared_target;
    if (!v8_prepare_target_state(hash,&old_target) ||
        !fixed_prepare_target_state(hash,&shared_target)) return 4;
    bs_vec old_match=v8_match_target_state(legacy.left,legacy.right,&old_target,
                                           BS_LANES);
    bs_vec shared_match=fixed_match_target_state(shared.left,shared.right,
                                                 &shared_target,BS_LANES);
    return equal_vec(old_match,shared_match)?0:5;
}
