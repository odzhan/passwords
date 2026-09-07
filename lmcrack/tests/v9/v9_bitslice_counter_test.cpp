#include <cstdint>

#include "v9_bitslice_counter.h"

static unsigned int plane_lane(bs_vec value,size_t lane)
{
    uint8_t packed[BS_BYTES]; bs_store(packed,value);
    return (packed[lane>>3]>>(lane&7U))&1U;
}

static unsigned int counter_digit(const v9_bitslice_counter *counter,
                                  unsigned int position,size_t lane)
{
    unsigned int value=0;
    for (unsigned int bit=0;bit<V9_DIGIT_BITS;bit++)
      value|=plane_lane(counter->digit[position][bit],lane)<<bit;
    return value;
}

static int validate_batch(const v9_bitslice_counter *counter)
{
    for (size_t lane=0;lane<counter->count;lane++) {
      uint8_t expected[V9_MAX_PASSWORD_LENGTH]; unsigned int length;
      if (!v9_cbn_to_digits(counter->current_cbn+lane,expected,&length) ||
          length!=counter->length) return 1;
      for (unsigned int p=0;p<length;p++)
        if (counter_digit(counter,p,lane)!=expected[p]) return 2;
      for (unsigned int p=length;p<V9_MAX_PASSWORD_LENGTH;p++)
        if (counter_digit(counter,p,lane)!=0) return 3;
    }
    return 0;
}

static int run_range(uint64_t start,uint64_t count)
{
    v9_bitslice_counter counter; uint64_t processed=0;
    if (!v9_bs_counter_init(&counter,start,count)) return 1;
    for (;;) {
      if (validate_batch(&counter)) return 2;
      processed+=counter.count;
      if (!v9_bs_counter_advance(&counter)) break;
    }
    return processed!=count || counter.remaining!=0 || counter.count!=0;
}

int main(void)
{
    v9_bitslice_counter invalid;
    if (run_range(0,2500)) return 1;                   /* 9->A, Z->00, ZZ->000 */
    if (run_range(8,5)) return 2;                      /* 9 -> A */
    if (run_range(34,5)) return 3;                     /* Z -> 00 */
    if (run_range(1325,20)) return 4;                  /* ZZ -> 000 */
    if (run_range(37,BS_LANES*5U+17U)) return 5;       /* unaligned start/tail */
    if (run_range(v9_length_block_start(5)+1295,
                  BS_LANES*8U+3U)) return 6;           /* long carry */
    if (run_range(v9_length_block_start(7)+1234567,
                  BS_LANES*9U+1U)) return 7;
    if (run_range(V9_TOTAL_CANDIDATES-13,13)) return 8;
    if (v9_bs_counter_init(&invalid,V9_TOTAL_CANDIDATES,1) ||
        v9_bs_counter_init(&invalid,0,0) ||
        v9_bs_counter_init(&invalid,V9_TOTAL_CANDIDATES-1,2)) return 9;
    return 0;
}
