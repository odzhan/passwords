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
    if (run_case("Az9",3,0,BS_LANES+7)) return 1;
    if (run_case("ABCDEFGHIJKLMNOPQRSTUVWXYZ",26,25,BS_LANES-3)) return 2;
    if (run_case("!~",2,2+4+8-1,5)) return 3;
    return 0;
}
