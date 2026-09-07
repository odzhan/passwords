#include <cstdint>
#include <cstring>

#include "bitslice_transpose.h"
#include "v11_key_planes.h"

static unsigned int plane_lane(bs_vec value,size_t lane)
{
    uint8_t packed[BS_BYTES]; bs_store(packed,value);
    return (packed[lane>>3]>>(lane&7U))&1U;
}

static unsigned int digit_lane(const v11_bitslice_counter *counter,
                               unsigned int position,size_t lane)
{
    unsigned int value=0;
    for (unsigned int bit=0;bit<V11_DIGIT_BITS;bit++)
      value|=plane_lane(counter->digit[position][bit],lane)<<bit;
    return value;
}

static int compare_planes(const bs_vec *a,const bs_vec *b)
{
    uint8_t aa[BS_BYTES],bb[BS_BYTES];
    for (unsigned int plane=0;plane<V11_LM_KEY_PLANES;plane++) {
      bs_store(aa,a[plane]); bs_store(bb,b[plane]);
      if (std::memcmp(aa,bb,sizeof(aa))!=0) return 0;
    }
    return 1;
}

static int run_range(uint64_t start,uint64_t count)
{
    v11_bitslice_counter counter; uint64_t processed=0;
    if (!v11_bs_counter_init(&counter,start,count)) return 1;
    for (;;) {
      bs_candidate_batch reference; bs_vec direct[56],transposed[56];
      reference.count=counter.count;
      for (size_t lane=0;lane<counter.count;lane++) {
        unsigned int length;
        if (!v11_cbn_to_digits(counter.current_cbn+lane,
                               reference.index[lane],&length) ||
            length!=counter.length) return 2;
        reference.length[lane]=(uint8_t)length;
        for (unsigned int position=0;position<length;position++)
          if (digit_lane(&counter,position,lane)!=reference.index[lane][position])
            return 3;
      }
      if (!v11_bs_make_key_planes(&counter,direct) ||
          !bs_transpose_passwords(&reference,V11_ALPHABET,
                                  V11_ALPHABET_LENGTH,transposed) ||
          !compare_planes(direct,transposed)) return 4;
      processed+=counter.count;
      if (!v11_bs_counter_advance(&counter)) break;
    }
    return processed!=count || counter.remaining!=0 || counter.count!=0;
}

static int exhaustive_symbols(void)
{
    for (unsigned int digit=0;digit<V11_ALPHABET_LENGTH;digit++) {
      v11_bitslice_counter counter; bs_vec direct[56],expected[56];
      bs_candidate_batch batch;
      batch.count=1; batch.length[0]=1; batch.index[0][0]=(uint8_t)digit;
      if (!v11_bs_counter_init(&counter,digit,1) ||
          !v11_bs_make_key_planes(&counter,direct) ||
          !bs_transpose_passwords(&batch,V11_ALPHABET,
                                  V11_ALPHABET_LENGTH,expected) ||
          !compare_planes(direct,expected)) return 1+(int)digit;
    }
    return 0;
}

int main(void)
{
    if (exhaustive_symbols()) return 1;
    if (run_range(0,BS_LANES*3U+17U) ||
        run_range(67,BS_LANES+7U) ||
        run_range(v11_length_block_start(3)-5U,BS_LANES*2U+11U) ||
        run_range(v11_length_block_start(6)+12345U,BS_LANES*4U+3U) ||
        run_range(V11_TOTAL_CANDIDATES-13U,13U)) return 2;
    v11_bitslice_counter invalid; bs_vec planes[56];
    if (v11_bs_counter_init(&invalid,V11_TOTAL_CANDIDATES,1) ||
        v11_bs_counter_init(&invalid,0,0)) return 3;
    std::memset(&invalid,0,sizeof(invalid));
    if (v11_bs_make_key_planes(&invalid,planes)) return 4;
    return 0;
}
