#include <cstdint>
#include <cstring>
#include "bitslice_batch.h"

static bs_vec make_match(size_t a,size_t b)
{
    uint8_t packed[BS_BYTES];memset(packed,0,sizeof(packed));
    if(a<BS_LANES)packed[a>>3]|=(uint8_t)(1U<<(a&7U));
    if(b<BS_LANES)packed[b>>3]|=(uint8_t)(1U<<(b&7U));
    return bs_load(packed);
}

int main(void)
{
    int initial[BS_MAX_PWD]={1,2,0,0,0,0,0};
    int recovered[BS_MAX_PWD],length;
    bs_candidate_generator gen;bs_candidate_batch batch;
    size_t count=BS_LANES>5?BS_LANES-3:BS_LANES;
    if(!bs_candidate_generator_init(&gen,initial,2,3,count))return 1;
    bs_candidate_next(&gen,&batch);
    if(bs_first_match_lane(make_match(0,count-1),count)!=0)return 2;
    if(bs_first_match_lane(make_match(count-1,BS_LANES),count)!=count-1)return 3;
    if(bs_first_match_lane(make_match(count,BS_LANES),count)!=BS_LANES)return 4;
    size_t lane=count/2;
    if(!bs_recover_candidate(&batch,lane,recovered,&length))return 5;
    if(length!=batch.length[lane])return 6;
    for(int i=0;i<(int)BS_MAX_PWD;i++) {
      int expected=i<length?(int)batch.index[lane][i]:-1;
      if(recovered[i]!=expected)return 7;
    }
    if(bs_recover_candidate(&batch,count,recovered,&length))return 8;
    {
      uint8_t bytes[BS_BYTES];
      bs_store(bytes,bs_valid_lane_mask(count));
      for(size_t i=0;i<BS_LANES;i++)
        if(((bytes[i>>3]>>(i&7U))&1U)!=(unsigned)(i<count))return 9;
    }
    {
      bs_candidate_generator progress_gen;bs_candidate_batch progress_batch;
      uint64_t requested=(uint64_t)BS_LANES*2U+13U,total=0;
      if(!bs_candidate_generator_init(&progress_gen,initial,2,3,requested))return 10;
      size_t n;
      while((n=bs_candidate_next(&progress_gen,&progress_batch))!=0)total+=n;
      if(total!=requested||progress_gen.remaining!=0)return 11;
    }
    return 0;
}
