#include <cstdint>

#include "v8_bitslice_counter.h"

static unsigned int plane_lane(bs_vec value,size_t lane)
{
    uint8_t packed[BS_BYTES];
    bs_store(packed,value);
    return (packed[lane>>3]>>(lane&7U))&1U;
}

static unsigned int counter_digit(const v8_bitslice_counter *counter,
                                  unsigned int position,size_t lane)
{
    unsigned int value=0;
    for (unsigned int bit=0;bit<V8_DIGIT_BITS;bit++)
      value|=plane_lane(counter->digit[position][bit],lane)<<bit;
    return value;
}

static int validate_batch(const v8_bitslice_counter *counter)
{
    for (size_t lane=0;lane<counter->count;lane++) {
      uint8_t expected[V8_MAX_PASSWORD_LENGTH];
      unsigned int length=0;
      if (!v8_cbn_to_digits(counter->current_cbn+lane,expected,&length))
        return 1;
      if (length!=counter->length) return 2;
      for (unsigned int position=0;position<length;position++)
        if (counter_digit(counter,position,lane)!=expected[position]) return 3;
      for (unsigned int position=length;position<V8_MAX_PASSWORD_LENGTH;position++)
        if (counter_digit(counter,position,lane)!=0) return 4;
    }
    return 0;
}

static int run_range(uint64_t start,uint64_t count)
{
    v8_bitslice_counter counter;
    uint64_t processed=0;
    if (!v8_bs_counter_init(&counter,start,count)) return 1;
    for (;;) {
      int result=validate_batch(&counter);
      if (result) return 10+result;
      processed+=counter.count;
      if (!v8_bs_counter_advance(&counter)) break;
    }
    if (processed!=count || counter.remaining!=0 || counter.count!=0) return 20;
    return 0;
}

int main(void)
{
    const uint64_t length4=v8_length_block_start(4);
    const uint64_t length6=v8_length_block_start(6);
    v8_bitslice_counter invalid;

    if (run_range(0,2000)) return 1;                 /* A, Z, AA, ZZ, AAA */
    if (run_range(25,3)) return 2;                   /* Z -> AA */
    if (run_range(695,30)) return 3;                 /* ZZ -> AAA */
    if (run_range(37,BS_LANES*5U+17U)) return 4;     /* non-aligned start */
    if (run_range(length4+675,BS_LANES*8U+3U)) return 5; /* long carry */
    if (run_range(length6+12345,BS_LANES*9U+1U)) return 6;
    if (run_range(V8_TOTAL_CANDIDATES-13,13)) return 7;

    if (v8_bs_counter_init(&invalid,V8_TOTAL_CANDIDATES,1)) return 10;
    if (v8_bs_counter_init(&invalid,0,0)) return 11;
    if (v8_bs_counter_init(&invalid,V8_TOTAL_CANDIDATES-1,2)) return 12;
    return 0;
}
