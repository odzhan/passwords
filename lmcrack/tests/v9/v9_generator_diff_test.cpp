#include <cstdint>
#include <cstring>

#include "bitslice_transpose.h"
#include "v9_key_planes.h"

typedef struct {
    bs_candidate_generator generator;
    bs_candidate_batch batch;
    size_t lane;
} v7_stream;

static int v7_stream_init(v7_stream *stream,uint64_t start,uint64_t count)
{
    uint8_t digits[7]; int initial[7]; unsigned int length;
    if (!v9_cbn_to_digits(start,digits,&length)) return 0;
    for (unsigned int i=0;i<7;i++) initial[i]=i<length?digits[i]:-1;
    std::memset(stream,0,sizeof(*stream)); stream->lane=BS_LANES;
    return bs_candidate_generator_init(&stream->generator,initial,(int)length,
                                       V9_ALPHABET_LENGTH,count);
}

static int v7_take(v7_stream *stream,uint8_t output[7],unsigned int *length)
{
    if (stream->lane>=stream->batch.count) {
      if (!bs_candidate_next(&stream->generator,&stream->batch)) return 0;
      stream->lane=0;
    }
    *length=stream->batch.length[stream->lane];
    std::memcpy(output,stream->batch.index[stream->lane],7);
    stream->lane++;
    return 1;
}

static unsigned int plane_lane(bs_vec value,size_t lane)
{
    uint8_t packed[BS_BYTES]; bs_store(packed,value);
    return (packed[lane>>3]>>(lane&7U))&1U;
}

static unsigned int digit_lane(const v9_bitslice_counter *counter,
                               unsigned int position,size_t lane)
{
    unsigned int value=0;
    for (unsigned int bit=0;bit<V9_DIGIT_BITS;bit++)
      value|=plane_lane(counter->digit[position][bit],lane)<<bit;
    return value;
}

static int compare_planes(const bs_vec *a,const bs_vec *b)
{
    uint8_t aa[BS_BYTES],bb[BS_BYTES];
    for (unsigned int plane=0;plane<56;plane++) {
      bs_store(aa,a[plane]); bs_store(bb,b[plane]);
      if (std::memcmp(aa,bb,sizeof(aa))!=0) return 0;
    }
    return 1;
}

static int run_case(uint64_t start,uint64_t count)
{
    v9_bitslice_counter v9; v7_stream v7; uint64_t processed=0;
    if (!v9_bs_counter_init(&v9,start,count) || !v7_stream_init(&v7,start,count))
      return 1;
    for (;;) {
      bs_candidate_batch reference; bs_vec direct[56],transposed[56];
      reference.count=v9.count;
      for (size_t lane=0;lane<v9.count;lane++) {
        unsigned int length;
        if (!v7_take(&v7,reference.index[lane],&length) || length!=v9.length)
          return 2;
        reference.length[lane]=(uint8_t)length;
        for (unsigned int p=0;p<length;p++)
          if (digit_lane(&v9,p,lane)!=reference.index[lane][p]) return 3;
      }
      if (!v9_bs_make_key_planes(&v9,direct) ||
          !bs_transpose_passwords(&reference,V9_ALPHABET,36,transposed) ||
          !compare_planes(direct,transposed)) return 4;
      processed+=v9.count;
      if (!v9_bs_counter_advance(&v9)) break;
    }
    if (processed!=count || v9.remaining!=0 || v9.count!=0 ||
        v7.generator.remaining!=0 || v7.lane!=v7.batch.count) return 5;
    return 0;
}

int main(void)
{
    uint64_t four_digit_carry=0,power=1;
    for (unsigned int i=0;i<4;i++) { four_digit_carry+=35U*power; power*=36U; }
    if (run_case(0,BS_LANES*3U+17U)) return 1;
    if (run_case(35,BS_LANES+3U)) return 2;
    if (run_case(1325,BS_LANES*2U+19U)) return 3;
    if (run_case(v9_length_block_start(3)+1294,BS_LANES*4U+1U)) return 4;
    if (run_case(v9_length_block_start(5)+four_digit_carry-3,
                 BS_LANES*5U+7U)) return 5;
    if (run_case(v9_length_block_start(7)+1234567,BS_LANES*7U+31U)) return 6;
    if (run_case(V9_TOTAL_CANDIDATES-(BS_LANES+13U),BS_LANES+13U)) return 7;
    return 0;
}
