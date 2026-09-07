#include <assert.h>
#include <stdint.h>

#include "destool_key_planes.h"

static unsigned int lane_bit(bs_vec value,size_t lane)
{
    uint8_t bytes[BS_BYTES];
    bs_store(bytes,value);
    return (bytes[lane>>3]>>(lane&7U))&1U;
}

static void compare_range(unsigned int alphabet,unsigned int length,
                          uint64_t start,uint64_t count)
{
    destool_bitslice_counter counter;
    assert(destool_bs_counter_init(&counter,alphabet,length,start,count));
    uint64_t consumed=0;
    do {
      bs_vec planes[BS_KEY_PLANES];
      assert(destool_bs_make_key_planes(&counter,planes));
      for (size_t lane=0;lane<counter.count;lane++) {
        uint8_t scalar[DESTOOL_MAX_KEY_BYTES]={0};
        uint8_t generated[DESTOOL_MAX_KEY_BYTES]={0};
        const uint64_t expected_cbn=counter.current_cbn+lane;
        assert(destool_cbn_to_key(expected_cbn,alphabet,length,scalar));
        for (unsigned int position=0;position<DESTOOL_MAX_KEY_BYTES;position++)
          for (unsigned int bit=0;bit<8;bit++)
            generated[position]|=(uint8_t)(lane_bit(
              planes[position*8U+bit],lane)<<bit);
        for (unsigned int position=0;position<DESTOOL_MAX_KEY_BYTES;position++)
          assert(generated[position]==scalar[position]);
        uint64_t recovered=UINT64_MAX;
        assert(destool_key_to_cbn(generated,alphabet,length,&recovered));
        assert(recovered==expected_cbn);
      }
      consumed+=counter.count;
    } while (destool_bs_counter_advance(&counter));
    assert(consumed==count);
}

int main(void)
{
    for (unsigned int alphabet=1;alphabet<=7;alphabet++) {
      const uint64_t radix=destool_alphabet_radix(alphabet);
      for (unsigned int length=1;length<=7;length++) {
        uint64_t size=0;
        assert(destool_keyspace_size(alphabet,length,&size));
        const uint64_t first_count=size<BS_LANES*2U+13U?
          size:BS_LANES*2U+13U;
        compare_range(alphabet,length,0,first_count);
        if (length>1 && size>radix+BS_LANES+11U)
          compare_range(alphabet,length,radix-3U,BS_LANES+11U);
        if (size>BS_LANES+19U) {
          uint64_t arbitrary=size/3U+7U;
          uint64_t available=size-arbitrary;
          uint64_t count=available<BS_LANES+19U?available:BS_LANES+19U;
          compare_range(alphabet,length,arbitrary,count);
        }
        const uint64_t final_count=size<BS_LANES+3U?size:BS_LANES+3U;
        compare_range(alphabet,length,size-final_count,final_count);
      }
    }
    return 0;
}
