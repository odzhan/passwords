#include <cstdint>
#include <cstring>
#include "bitslice_des.h"

static uint32_t scalar_f(uint32_t r,uint64_t key)
{
    unsigned input[48],sout[32]; uint32_t out=0;
    for(unsigned i=0;i<48;i++) input[i]=((r>>(32U-bs_des_e[i]))&1U)^((key>>(47U-i))&1U);
    for(unsigned box=0;box<8;box++) {
      unsigned value=0;
      for(unsigned bit=0;bit<6;bit++) value=(value<<1)|input[box*6+bit];
      unsigned s=bs_sbox_value(box,value);
      for(unsigned bit=0;bit<4;bit++) sout[box*4+bit]=(s>>(3U-bit))&1U;
    }
    for(unsigned i=0;i<32;i++) out=(out<<1)|sout[bs_des_p[i]-1U];
    return out;
}

static unsigned lane_bit(const bs_vec &v,size_t lane)
{
    uint8_t bytes[BS_BYTES];bs_store(bytes,v);return(bytes[lane>>3]>>(lane&7U))&1U;
}

int main(void)
{
    bs_vec left[32],right[32];bs_key_schedule schedule;
    bs_sbox_init();
    uint8_t packed[BS_BYTES];
    for(unsigned bit=0;bit<32;bit++) {
      memset(packed,0,sizeof(packed));
      for(size_t lane=0;lane<BS_LANES;lane++) if((((uint32_t)(lane*0x9e3779b1U+3U))>>(31U-bit))&1U) packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
      left[bit]=bs_load(packed);
      memset(packed,0,sizeof(packed));
      for(size_t lane=0;lane<BS_LANES;lane++) if((((uint32_t)(lane*0x7f4a7c15U+5U))>>(31U-bit))&1U) packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
      right[bit]=bs_load(packed);
    }
    for(unsigned round=0;round<16;round++) for(unsigned bit=0;bit<48;bit++) {
      memset(packed,0,sizeof(packed));
      for(size_t lane=0;lane<BS_LANES;lane++) if((((uint64_t)(lane*17U+round*31U+7U)*UINT64_C(0x123456789ab))>>(47U-bit))&1U) packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
      schedule.plane[round][bit]=bs_load(packed);
    }
    bs_des_rounds(left,right,&schedule);
    for(size_t lane=0;lane<BS_LANES;lane++) {
      uint32_t l=(uint32_t)(lane*0x9e3779b1U+3U),r=(uint32_t)(lane*0x7f4a7c15U+5U);
      for(unsigned round=0;round<16;round++) {
        uint64_t k=((uint64_t)(lane*17U+round*31U+7U)*UINT64_C(0x123456789ab))&UINT64_C(0xffffffffffff);
        l^=scalar_f(r,k);uint32_t tmp=l;l=r;r=tmp;
      }
      uint32_t got_l=0,got_r=0;
      for(unsigned bit=0;bit<32;bit++){got_l=(got_l<<1)|lane_bit(left[bit],lane);got_r=(got_r<<1)|lane_bit(right[bit],lane);}
      if(got_l!=l||got_r!=r)return 1;
    }
    return 0;
}
