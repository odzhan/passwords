#include <cstdint>
#include <cstring>
#include "bitslice_transpose.h"

static uint8_t plane_lane(const bs_vec &plane, size_t lane)
{
    uint8_t packed[BS_BYTES];
    bs_store(packed,plane);
    return (uint8_t)((packed[lane>>3]>>(lane&7U))&1U);
}

static int run_case(const char *alphabet, unsigned alpha, uint64_t start,
                    uint64_t count)
{
    int initial[BS_MAX_PWD];
    uint64_t value=start, power=alpha;
    int length;
    for (int i=0;i<(int)BS_MAX_PWD;i++) initial[i]=-1;
    for (length=1;value>=power;length++) { value-=power; power*=alpha; }
    for (int i=0;i<length;i++) { initial[i]=(int)(value%alpha); value/=alpha; }

    bs_candidate_generator generator;
    bs_candidate_batch batch;
    bs_vec planes[BS_KEY_PLANES];
    if (!bs_candidate_generator_init(&generator,initial,length,alpha,count)) return 1;
    while (bs_candidate_next(&generator,&batch)!=0) {
      if (!bs_transpose_passwords(&batch,alphabet,alpha,planes)) return 2;
      for (size_t lane=0;lane<BS_LANES;lane++) {
        for (size_t byte=0;byte<BS_MAX_PWD;byte++) {
          uint8_t reconstructed=0;
          for (unsigned bit=0;bit<8;bit++)
            reconstructed|=(uint8_t)(plane_lane(planes[byte*8+bit],lane)<<bit);
          uint8_t expected=0;
          if (lane<batch.count && byte<batch.length[lane])
            expected=(uint8_t)alphabet[batch.index[lane][byte]];
          if (reconstructed!=expected) return 3;
        }
      }
    }
    return 0;
}

int main(void)
{
    // Arbitrary bytes, every length, empty/full/tail batches, and nonuniform lanes.
    char alphabet[128];
    for(unsigned i=0;i<128;i++) alphabet[i]=(char)(i*197U);
    uint32_t seed=12345;
    for(size_t count=0;count<=BS_LANES;count++) {
      bs_candidate_batch batch={}; batch.count=count;
      for(size_t lane=0;lane<count;lane++) {
        batch.length[lane]=(uint8_t)(lane%8);
        for(unsigned pos=0;pos<7;pos++) {
          seed=seed*1664525U+1013904223U;
          batch.index[lane][pos]=(uint8_t)((seed>>16)&127);
        }
      }
      bs_vec reference[56],actual[56];
      if(!bs_transpose_passwords_reference(&batch,alphabet,128,reference) ||
         !bs_transpose_passwords(&batch,alphabet,128,actual)) return 4;
      if(std::memcmp(reference,actual,sizeof(actual))) return 5;
    }
    if (run_case("Az9",3,0,BS_LANES+7)) return 1;
    if (run_case("ABCDEFGHIJKLMNOPQRSTUVWXYZ",26,25,BS_LANES-3)) return 2;
    if (run_case("!~",2,2+4+8-1,5)) return 3;
    return 0;
}
