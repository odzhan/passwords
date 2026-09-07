#include <assert.h>
#include <stdint.h>

#include "destool_key_planes.h"

static unsigned int lane_bit(bs_vec value,size_t lane)
{
    uint8_t bytes[BS_BYTES];
    bs_store(bytes,value);
    return (bytes[lane>>3]>>(lane&7U))&1U;
}

static void verify_range(unsigned int alphabet,unsigned int length,
                         uint64_t start,uint64_t count)
{
    destool_bitslice_counter counter;
    assert(destool_bs_counter_init(&counter,alphabet,length,start,count));
    do {
      bs_vec planes[BS_KEY_PLANES];
      assert(destool_bs_make_key_planes(&counter,planes));
      for (size_t lane=0;lane<BS_LANES;lane++) {
        uint8_t expected[DESTOOL_MAX_KEY_BYTES]={0};
        if (lane<counter.count)
          assert(destool_cbn_to_key(counter.current_cbn+lane,alphabet,length,
                                    expected));
        for (unsigned int position=0;position<DESTOOL_MAX_KEY_BYTES;position++) {
          unsigned int actual=0;
          for (unsigned int bit=0;bit<8;bit++)
            actual|=lane_bit(planes[position*8U+bit],lane)<<bit;
          assert(actual==expected[position]);
        }
      }
    } while (destool_bs_counter_advance(&counter));
}

int main(void)
{
    for (unsigned int alphabet=1;alphabet<=7;alphabet++) {
      const uint64_t radix=destool_alphabet_radix(alphabet);
      for (unsigned int length=1;length<=7;length++) {
        uint64_t size=0;
        assert(destool_keyspace_size(alphabet,length,&size));
        const uint64_t front=size<BS_LANES+5U?size:BS_LANES+5U;
        verify_range(alphabet,length,0,front);
        if (length>1 && size>radix+BS_LANES)
          verify_range(alphabet,length,radix-2U,BS_LANES+2U);
        const uint64_t tail=size<17U?size:17U;
        verify_range(alphabet,length,size-tail,tail);
      }
    }
    destool_bitslice_counter invalid;
    bs_vec planes[BS_KEY_PLANES];
    assert(destool_bs_counter_init(&invalid,2,1,0,1));
    invalid.alphabet_id=8;
    assert(!destool_bs_make_key_planes(&invalid,planes));
    assert(!destool_bs_make_key_planes(NULL,planes));
    assert(!destool_bs_make_key_planes(&invalid,NULL));
    return 0;
}
