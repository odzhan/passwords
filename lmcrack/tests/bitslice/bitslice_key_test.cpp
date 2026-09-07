#include <cstdint>
#include <cstring>
#include "bitslice_key.h"

static unsigned lane_bit(const bs_vec &v,size_t lane)
{
    uint8_t bytes[BS_BYTES]; bs_store(bytes,v);
    return (bytes[lane>>3]>>(lane&7U))&1U;
}

static uint64_t scalar_round_key(const uint8_t pwd[7],unsigned round)
{
    uint8_t key[8]={0}; unsigned stream=0;
    for (unsigned kb=0;kb<8;kb++) {
      for (unsigned bit=0;bit<7;bit++,stream++) {
        unsigned value=(pwd[stream>>3]>>(7U-(stream&7U)))&1U;
        key[kb]|=(uint8_t)(value<<(7U-bit));
      }
    }
    uint8_t cd[56],next[56];
    for(unsigned i=0;i<56;i++) {
      unsigned p=bs_pc1[i]-1U;
      cd[i]=(key[p>>3]>>(7U-(p&7U)))&1U;
    }
    for(unsigned r=0;r<=round;r++) {
      unsigned s=bs_key_shifts[r];
      for(unsigned i=0;i<28;i++){next[i]=cd[(i+s)%28];next[28+i]=cd[28+(i+s)%28];}
      memcpy(cd,next,sizeof(cd));
    }
    uint64_t result=0;
    for(unsigned i=0;i<48;i++) result=(result<<1)|cd[bs_pc2[i]-1U];
    return result;
}

int main(void)
{
    const char alphabet[]="Az09!?";
    int initial[BS_MAX_PWD]={0,0,0,0,0,0,0};
    bs_candidate_generator gen; bs_candidate_batch batch;
    bs_vec password[BS_KEY_PLANES]; bs_key_schedule schedule;
    if(!bs_candidate_generator_init(&gen,initial,7,6,BS_LANES-3)) return 1;
    bs_candidate_next(&gen,&batch);
    if(!bs_transpose_passwords(&batch,alphabet,6,password)) return 2;
    bs_make_key_schedule(password,&schedule);
    for(size_t lane=0;lane<batch.count;lane++) {
      uint8_t pwd[7];
      for(unsigned i=0;i<7;i++) pwd[i]=(uint8_t)alphabet[batch.index[lane][i]];
      for(unsigned r=0;r<16;r++) {
        uint64_t got=0;
        for(unsigned bit=0;bit<48;bit++) got=(got<<1)|lane_bit(schedule.plane[r][bit],lane);
        if(got!=scalar_round_key(pwd,r)) return 3;
      }
    }
    return 0;
}
