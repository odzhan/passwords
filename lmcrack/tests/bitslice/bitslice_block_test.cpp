#include <cstdint>
#include "bitslice_block.h"

static unsigned lane_bit(const bs_vec &plane,size_t lane)
{
    uint8_t bytes[BS_BYTES];
    bs_store(bytes,plane);
    return (bytes[lane>>3]>>(lane&7U))&1U;
}

static int check(const uint8_t block[8])
{
    bs_vec planes[BS_BLOCK_PLANES],left[32],right[32];
    if (!bs_broadcast_block(block,planes)) return 1;
    for (size_t plane=0;plane<BS_BLOCK_PLANES;plane++) {
      unsigned expected=(block[plane>>3]>>(7U-(plane&7U)))&1U;
      for (size_t lane=0;lane<BS_LANES;lane++)
        if (lane_bit(planes[plane],lane)!=expected) return 2;
    }
    if (!bs_initial_permutation(planes,left,right)) return 3;
    for (size_t lane=0;lane<BS_LANES;lane++) {
      uint32_t got_left=0,got_right=0,expected_left=0,expected_right=0;
      for (unsigned bit=0;bit<32;bit++) {
        unsigned source_left=bs_des_ip[bit]-1U;
        unsigned source_right=bs_des_ip[32U+bit]-1U;
        expected_left=(expected_left<<1)|((block[source_left>>3]>>(7U-(source_left&7U)))&1U);
        expected_right=(expected_right<<1)|((block[source_right>>3]>>(7U-(source_right&7U)))&1U);
        got_left=(got_left<<1)|lane_bit(left[bit],lane);
        got_right=(got_right<<1)|lane_bit(right[bit],lane);
      }
      if (got_left!=expected_left || got_right!=expected_right) return 4;
    }
    return 0;
}

int main(void)
{
    const uint8_t zero[8]={0};
    const uint8_t ones[8]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    const uint8_t pattern[8]={0x80,0x01,0xa5,0x5a,0x12,0x34,0x56,0x78};
    const uint8_t lm_plaintext[8]={'K','G','S','!','@','#','$','%'};
    if (check(zero)) return 1;
    if (check(ones)) return 2;
    if (check(pattern)) return 3;
    if (check(lm_plaintext)) return 4;
    {
      bs_block_state cached;
      bs_vec input[BS_BLOCK_PLANES],left[32],right[32];
      if (bs_copy_lm_plaintext_state(&cached)) return 5;
      bs_init_lm_plaintext_state();
      if (!bs_copy_lm_plaintext_state(&cached)) return 6;
      bs_broadcast_block(lm_plaintext,input);
      bs_initial_permutation(input,left,right);
      for (unsigned bit=0;bit<32;bit++) {
        uint8_t a[BS_BYTES],b[BS_BYTES];
        bs_store(a,cached.left[bit]);bs_store(b,left[bit]);
        if (memcmp(a,b,BS_BYTES)!=0) return 7;
        bs_store(a,cached.right[bit]);bs_store(b,right[bit]);
        if (memcmp(a,b,BS_BYTES)!=0) return 8;
      }
      for (size_t lane=0;lane<BS_LANES;lane++) {
        uint32_t cached_left=0,cached_right=0;
        for (unsigned bit=0;bit<32;bit++) {
          cached_left=(cached_left<<1)|lane_bit(cached.left[bit],lane);
          cached_right=(cached_right<<1)|lane_bit(cached.right[bit],lane);
        }
        if (cached_left!=UINT32_C(0x1704c2af) ||
            cached_right!=UINT32_C(0x00e80127)) return 9;
      }
    }
    {
      const uint8_t target[8]={0x1f,0xb3,0x63,0xfe,0xb8,0x34,0xc1,0x2d};
      bs_vec external[64],ip_planes[64],left[32],right[32],roundtrip[64];
      uint8_t mask[BS_BYTES];
      bs_broadcast_block(target,external);
      bs_initial_permutation(external,left,right);
      /* Swap the IP halves because final permutation consumes R16 || L16. */
      bs_final_permutation(right,left,roundtrip);
      for (unsigned bit=0;bit<64;bit++) {
        uint8_t a[BS_BYTES],b[BS_BYTES];
        bs_store(a,external[bit]);bs_store(b,roundtrip[bit]);
        if(memcmp(a,b,BS_BYTES)!=0)return 10;
      }
      bs_store(mask,bs_match_block(roundtrip,target));
      for(size_t i=0;i<BS_BYTES;i++)if(mask[i]!=0xff)return 11;

      /* Flip target bit zero in odd lanes; only even lanes may still match. */
      uint8_t first[BS_BYTES];bs_store(first,roundtrip[0]);
      for(size_t lane=1;lane<BS_LANES;lane+=2)first[lane>>3]^=(uint8_t)(1U<<(lane&7U));
      roundtrip[0]=bs_load(first);
      bs_store(mask,bs_match_block(roundtrip,target));
      for(size_t lane=0;lane<BS_LANES;lane++)
        if(((mask[lane>>3]>>(lane&7U))&1U)!=(unsigned)((lane&1U)==0))return 12;
      bs_store(mask,bs_match_valid_block(external,target,BS_LANES-5U));
      for(size_t lane=0;lane<BS_LANES;lane++)
        if(((mask[lane>>3]>>(lane&7U))&1U)!=(unsigned)(lane<BS_LANES-5U))return 13;
      (void)ip_planes;
    }
    return 0;
}
