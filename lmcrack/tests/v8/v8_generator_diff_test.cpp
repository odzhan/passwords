#include <cstdint>
#include <cstring>

#include "bitslice_transpose.h"
#include "v8_key_planes.h"

static const char uppercase_alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ";

typedef struct {
    bs_candidate_generator generator;
    bs_candidate_batch batch;
    size_t lane;
} v7_stream;

static int v7_stream_init(v7_stream *stream,uint64_t start,uint64_t count)
{
    uint8_t digits[V8_MAX_PASSWORD_LENGTH];
    int initial[V8_MAX_PASSWORD_LENGTH];
    unsigned int length=0;
    if (!v8_cbn_to_digits(start,digits,&length)) return 0;
    for (unsigned int i=0;i<V8_MAX_PASSWORD_LENGTH;i++)
      initial[i]=(i<length)?digits[i]:-1;
    std::memset(stream,0,sizeof(*stream));
    stream->lane=BS_LANES;
    return bs_candidate_generator_init(&stream->generator,initial,(int)length,
                                       V8_ALPHABET_LENGTH,count);
}

static int v7_stream_take(v7_stream *stream,uint8_t output[V8_MAX_PASSWORD_LENGTH],
                          unsigned int *length)
{
    if (stream->lane>=stream->batch.count) {
      if (bs_candidate_next(&stream->generator,&stream->batch)==0) return 0;
      stream->lane=0;
    }
    *length=stream->batch.length[stream->lane];
    std::memcpy(output,stream->batch.index[stream->lane],
                V8_MAX_PASSWORD_LENGTH);
    stream->lane++;
    return 1;
}

static unsigned int plane_lane(bs_vec value,size_t lane)
{
    uint8_t packed[BS_BYTES];
    bs_store(packed,value);
    return (packed[lane>>3]>>(lane&7U))&1U;
}

static unsigned int v8_digit_lane(const v8_bitslice_counter *counter,
                                  unsigned int position,size_t lane)
{
    unsigned int value=0;
    for (unsigned int bit=0;bit<V8_DIGIT_BITS;bit++)
      value|=plane_lane(counter->digit[position][bit],lane)<<bit;
    return value;
}

static int compare_key_planes(const bs_vec actual[V8_LM_KEY_PLANES],
                              const bs_vec expected[BS_KEY_PLANES])
{
    uint8_t a[BS_BYTES],b[BS_BYTES];
    for (unsigned int plane=0;plane<V8_LM_KEY_PLANES;plane++) {
      bs_store(a,actual[plane]);
      bs_store(b,expected[plane]);
      if (std::memcmp(a,b,sizeof(a))!=0) return 1+(int)plane;
    }
    return 0;
}

static int run_case(uint64_t start,uint64_t count)
{
    v8_bitslice_counter v8;
    v7_stream v7;
    uint64_t processed=0;
    if (!v8_bs_counter_init(&v8,start,count)) return 1;
    if (!v7_stream_init(&v7,start,count)) return 2;

    for (;;) {
      bs_candidate_batch reference;
      bs_vec direct[V8_LM_KEY_PLANES],transposed[BS_KEY_PLANES];
      reference.count=v8.count;

      for (size_t lane=0;lane<v8.count;lane++) {
        unsigned int length=0;
        if (!v7_stream_take(&v7,reference.index[lane],&length)) return 3;
        reference.length[lane]=(uint8_t)length;
        if (length!=v8.length) return 4;
        for (unsigned int position=0;position<length;position++)
          if (v8_digit_lane(&v8,position,lane)!=reference.index[lane][position])
            return 5;
      }

      if (!v8_bs_make_key_planes(&v8,direct)) return 6;
      if (!bs_transpose_passwords(&reference,uppercase_alphabet,
                                  V8_ALPHABET_LENGTH,transposed)) return 7;
      int plane_result=compare_key_planes(direct,transposed);
      if (plane_result) return 100+plane_result;

      processed+=v8.count;
      if (!v8_bs_counter_advance(&v8)) break;
    }

    if (processed!=count || v8.remaining!=0 || v8.count!=0) return 8;
    if (v7.generator.remaining!=0 || v7.lane!=v7.batch.count) return 9;
    return 0;
}

int main(void)
{
    const uint64_t l3=v8_length_block_start(3);
    const uint64_t l5=v8_length_block_start(5);
    const uint64_t l7=v8_length_block_start(7);
    const uint64_t four_digit_carry=25U+25U*26U+25U*26U*26U+
                                    25U*26U*26U*26U;

    if (run_case(0,BS_LANES*3U+17U)) return 1;
    if (run_case(25,BS_LANES+3U)) return 2;             /* Z -> AA */
    if (run_case(695,BS_LANES*2U+19U)) return 3;        /* ZZ -> AAA */
    if (run_case(l3+674,BS_LANES*4U+1U)) return 4;      /* two-digit carry */
    if (run_case(l5+four_digit_carry-3,BS_LANES*5U+7U)) return 5;
    if (run_case(l7+1234567,BS_LANES*7U+31U)) return 6;
    if (run_case(V8_TOTAL_CANDIDATES-(BS_LANES+13U),BS_LANES+13U)) return 7;
    return 0;
}
