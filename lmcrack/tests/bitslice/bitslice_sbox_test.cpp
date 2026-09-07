#include <cstdint>
#include <cstring>
#include "bitslice_sbox.h"

int main(void)
{
    uint8_t packed[BS_BYTES],result[BS_BYTES];
    bs_vec input[6],output[4];
    for(unsigned bit=0;bit<6;bit++) {
      memset(packed,0,sizeof(packed));
      for(size_t lane=0;lane<BS_LANES;lane++)
        if (((lane&63U)>>(5U-bit))&1U) packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
      input[bit]=bs_load(packed);
    }
    bs_sbox_init();
    for(unsigned box=0;box<8;box++) {
      bs_vec reference[4];
      bs_sbox_reference(box,input,reference);
      bs_sbox_optimized(box,input,output);
      for(unsigned ob=0;ob<4;ob++) {
        bs_store(result,output[ob]);
        uint8_t reference_bytes[BS_BYTES];bs_store(reference_bytes,reference[ob]);
        if(memcmp(result,reference_bytes,BS_BYTES)!=0)return 41;
        for(size_t lane=0;lane<BS_LANES;lane++) {
          unsigned got=(result[lane>>3]>>(lane&7U))&1U;
          unsigned expected=(bs_sbox_value(box,(unsigned)lane&63U)>>(3U-ob))&1U;
          if(got!=expected) return (int)(1+box*4+ob);
        }
      }
    }
    return 0;
}
