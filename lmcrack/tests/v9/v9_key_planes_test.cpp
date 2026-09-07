#include <cstdint>
#include <cstring>

#include "bitslice_transpose.h"
#include "v9_key_planes.h"

static void load_counter(v9_bitslice_counter *counter,
                         const bs_candidate_batch *batch)
{
    std::memset(counter,0,sizeof(*counter));
    counter->count=batch->count; counter->length=batch->length[0];
    for (unsigned int p=0;p<V9_MAX_PASSWORD_LENGTH;p++)
      for (unsigned int bit=0;bit<V9_DIGIT_BITS;bit++) {
        uint8_t packed[BS_BYTES]; std::memset(packed,0,sizeof(packed));
        for (size_t lane=0;lane<batch->count;lane++)
          if (p<batch->length[lane] && ((batch->index[lane][p]>>bit)&1U))
            packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
        counter->digit[p][bit]=bs_load(packed);
      }
}

static int compare_planes(const bs_vec *actual,const bs_vec *expected)
{
    uint8_t a[BS_BYTES],e[BS_BYTES];
    for (unsigned int plane=0;plane<V9_LM_KEY_PLANES;plane++) {
      bs_store(a,actual[plane]); bs_store(e,expected[plane]);
      if (std::memcmp(a,e,sizeof(a))!=0) return 1+(int)plane;
    }
    return 0;
}

static int exhaustive_symbols(void)
{
    bs_candidate_batch batch; v9_bitslice_counter counter;
    bs_vec actual[V9_LM_KEY_PLANES],expected[BS_KEY_PLANES];
    batch.count=BS_LANES;
    for (unsigned int position=0;position<V9_MAX_PASSWORD_LENGTH;position++)
      for (unsigned int digit=0;digit<V9_ALPHABET_LENGTH;digit++) {
        for (size_t lane=0;lane<batch.count;lane++) {
          batch.length[lane]=V9_MAX_PASSWORD_LENGTH;
          for (unsigned int p=0;p<V9_MAX_PASSWORD_LENGTH;p++)
            batch.index[lane][p]=(uint8_t)(p==position?digit:
              ((lane+p*11U)%V9_ALPHABET_LENGTH));
        }
        load_counter(&counter,&batch);
        if (!v9_bs_make_key_planes(&counter,actual) ||
            !bs_transpose_passwords(&batch,V9_ALPHABET,
                                    V9_ALPHABET_LENGTH,expected)) return 1;
        if (compare_planes(actual,expected)) return 2;
      }
    return 0;
}

static int compare_range(uint64_t start,uint64_t count)
{
    v9_bitslice_counter counter;
    if (!v9_bs_counter_init(&counter,start,count)) return 1;
    for (;;) {
      bs_candidate_batch batch; bs_vec actual[56],expected[56];
      batch.count=counter.count;
      for (size_t lane=0;lane<batch.count;lane++) {
        unsigned int length;
        if (!v9_cbn_to_digits(counter.current_cbn+lane,batch.index[lane],
                              &length)) return 2;
        batch.length[lane]=(uint8_t)length;
      }
      if (!v9_bs_make_key_planes(&counter,actual) ||
          !bs_transpose_passwords(&batch,V9_ALPHABET,36,expected) ||
          compare_planes(actual,expected)) return 3;
      if (!v9_bs_counter_advance(&counter)) break;
    }
    return 0;
}

int main(void)
{
    v9_bitslice_counter invalid; bs_vec planes[56];
    if (exhaustive_symbols()) return 1;
    if (compare_range(0,2000) || compare_range(1325,BS_LANES+19U) ||
        compare_range(v9_length_block_start(6)+12345,BS_LANES*3U+1U) ||
        compare_range(V9_TOTAL_CANDIDATES-13,13)) return 2;
    std::memset(&invalid,0,sizeof(invalid));
    if (v9_bs_make_key_planes(NULL,planes) ||
        v9_bs_make_key_planes(&invalid,planes)) return 3;
    invalid.length=8;
    if (v9_bs_make_key_planes(&invalid,planes)) return 4;
    return 0;
}
