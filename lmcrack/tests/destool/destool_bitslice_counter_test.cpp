#include <assert.h>
#include <stdint.h>

#include "destool_bitslice_counter.h"

static unsigned int lane_bit(bs_vec value,size_t lane)
{
    uint8_t bytes[BS_BYTES];
    bs_store(bytes,value);
    return (bytes[lane>>3]>>(lane&7U))&1U;
}

static void verify_batch(const destool_bitslice_counter *counter)
{
    for (size_t lane=0;lane<counter->count;lane++) {
      uint64_t value=counter->current_cbn+lane;
      for (unsigned int position=0;position<counter->length;position++) {
        const unsigned int expected=(unsigned int)(value%counter->radix);
        value/=counter->radix;
        unsigned int actual=0;
        for (unsigned int bit=0;bit<counter->digit_bits;bit++)
          actual|=lane_bit(counter->digit[position][bit],lane)<<bit;
        assert(actual==expected);
      }
    }
}

static void run_range(unsigned int alphabet,unsigned int length,
                      uint64_t start,uint64_t count)
{
    destool_bitslice_counter counter;
    assert(destool_bs_counter_init(&counter,alphabet,length,start,count));
    uint64_t observed=0;
    do {
      verify_batch(&counter);
      observed+=counter.count;
    } while (destool_bs_counter_advance(&counter));
    assert(observed==count);
}

int main(void)
{
    for (unsigned int alphabet=1;alphabet<=7;alphabet++) {
      const unsigned int radix=destool_alphabet_radix(alphabet);
      for (unsigned int length=1;length<=7;length++) {
        uint64_t size=0;
        assert(destool_keyspace_size(alphabet,length,&size));
        run_range(alphabet,length,0,size<BS_LANES+3U?size:BS_LANES+3U);
        if (length>1) {
          const uint64_t boundary=radix-2U;
          const uint64_t count=(size-boundary)<(BS_LANES*2U+5U)?
            size-boundary:BS_LANES*2U+5U;
          run_range(alphabet,length,boundary,count);
        }
        const uint64_t tail=size<(BS_LANES+7U)?size:BS_LANES+7U;
        run_range(alphabet,length,size-tail,tail);
      }
    }
    destool_bitslice_counter counter;
    assert(!destool_bs_counter_init(&counter,0,1,0,1));
    assert(!destool_bs_counter_init(&counter,1,0,0,1));
    assert(!destool_bs_counter_init(&counter,1,1,256,1));
    assert(!destool_bs_counter_init(&counter,1,1,0,0));
    return 0;
}
