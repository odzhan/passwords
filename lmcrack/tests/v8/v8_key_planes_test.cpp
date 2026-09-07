#include <cstdint>
#include <cstring>

#include "bitslice_transpose.h"
#include "v8_key_planes.h"

static const char uppercase_alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void load_counter_digits(v8_bitslice_counter *counter,
                                const bs_candidate_batch *batch)
{
    std::memset(counter,0,sizeof(*counter));
    counter->count=batch->count;
    counter->length=batch->length[0];
    for (unsigned int position=0;position<V8_MAX_PASSWORD_LENGTH;position++) {
      for (unsigned int bit=0;bit<V8_DIGIT_BITS;bit++) {
        uint8_t packed[BS_BYTES];
        std::memset(packed,0,sizeof(packed));
        for (size_t lane=0;lane<batch->count;lane++)
          if (position<batch->length[lane] &&
              ((batch->index[lane][position]>>bit)&1U))
            packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
        counter->digit[position][bit]=bs_load(packed);
      }
    }
}

static int compare_planes(const bs_vec actual[V8_LM_KEY_PLANES],
                          const bs_vec expected[BS_KEY_PLANES])
{
    uint8_t a[BS_BYTES],e[BS_BYTES];
    for (unsigned int plane=0;plane<V8_LM_KEY_PLANES;plane++) {
      bs_store(a,actual[plane]);
      bs_store(e,expected[plane]);
      if (std::memcmp(a,e,sizeof(a))!=0) return 1+(int)plane;
    }
    return 0;
}

static int exhaustive_letters(void)
{
    bs_candidate_batch batch;
    v8_bitslice_counter counter;
    bs_vec actual[V8_LM_KEY_PLANES],expected[BS_KEY_PLANES];

    batch.count=BS_LANES;
    for (unsigned int position=0;position<V8_MAX_PASSWORD_LENGTH;position++) {
      for (unsigned int digit=0;digit<V8_ALPHABET_LENGTH;digit++) {
        for (size_t lane=0;lane<batch.count;lane++) {
          batch.length[lane]=V8_MAX_PASSWORD_LENGTH;
          for (unsigned int p=0;p<V8_MAX_PASSWORD_LENGTH;p++)
            batch.index[lane][p]=(uint8_t)((p==position)?digit:
              ((lane+p*7U)%V8_ALPHABET_LENGTH));
        }
        load_counter_digits(&counter,&batch);
        if (!v8_bs_make_key_planes(&counter,actual)) return 1;
        if (!bs_transpose_passwords(&batch,uppercase_alphabet,
                                    V8_ALPHABET_LENGTH,expected)) return 2;
        int result=compare_planes(actual,expected);
        if (result) return 100+(int)(position*26U+digit)*100+result;
      }
    }
    return 0;
}

static int compare_range(uint64_t start,uint64_t count)
{
    v8_bitslice_counter counter;
    if (!v8_bs_counter_init(&counter,start,count)) return 1;
    for (;;) {
      bs_candidate_batch batch;
      bs_vec actual[V8_LM_KEY_PLANES],expected[BS_KEY_PLANES];
      batch.count=counter.count;
      for (size_t lane=0;lane<batch.count;lane++) {
        unsigned int length=0;
        if (!v8_cbn_to_digits(counter.current_cbn+lane,batch.index[lane],
                              &length)) return 2;
        batch.length[lane]=(uint8_t)length;
      }
      if (!v8_bs_make_key_planes(&counter,actual)) return 3;
      if (!bs_transpose_passwords(&batch,uppercase_alphabet,
                                  V8_ALPHABET_LENGTH,expected)) return 4;
      int result=compare_planes(actual,expected);
      if (result) return 100+result;
      if (!v8_bs_counter_advance(&counter)) break;
    }
    return 0;
}

int main(void)
{
    v8_bitslice_counter invalid;
    bs_vec planes[V8_LM_KEY_PLANES];

    if (V8_LM_KEY_PLANES!=BS_KEY_PLANES) return 1;
    if (exhaustive_letters()) return 2;
    if (compare_range(0,2000)) return 3;
    if (compare_range(695,BS_LANES+19U)) return 4;
    if (compare_range(v8_length_block_start(6)+12345,BS_LANES*3U+1U)) return 5;
    if (compare_range(V8_TOTAL_CANDIDATES-13,13)) return 6;

    std::memset(&invalid,0,sizeof(invalid));
    if (v8_bs_make_key_planes(NULL,planes)) return 10;
    if (v8_bs_make_key_planes(&invalid,planes)) return 11;
    invalid.length=8;
    if (v8_bs_make_key_planes(&invalid,planes)) return 12;
    return 0;
}
