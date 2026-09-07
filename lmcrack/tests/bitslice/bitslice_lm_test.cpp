#include <cstdint>
#include <cstring>
#include "des.h"
#include "bitslice_des.h"
#include "bitslice_block.h"

static int index_from_cbn(int index[BS_MAX_PWD],uint64_t cbn,unsigned alpha)
{
    uint64_t power=alpha;int length;
    for(int i=0;i<(int)BS_MAX_PWD;i++)index[i]=-1;
    for(length=1;cbn>=power;length++){cbn-=power;power*=alpha;}
    for(int i=0;i<length;i++){index[i]=(int)(cbn%alpha);cbn/=alpha;}
    return length;
}

static uint8_t output_lane(const bs_vec output[64],size_t lane,unsigned byte)
{
    uint8_t value=0,packed[BS_BYTES];
    for(unsigned bit=0;bit<8;bit++) {
      bs_store(packed,output[byte*8U+bit]);
      value=(uint8_t)((value<<1)|((packed[lane>>3]>>(lane&7U))&1U));
    }
    return value;
}

static int run_case(const char *alphabet,unsigned alpha,uint64_t start,uint64_t count)
{
    int initial[BS_MAX_PWD];int length=index_from_cbn(initial,start,alpha);
    bs_candidate_generator generator;bs_candidate_batch batch;
    bs_vec password[56],output[64];bs_key_schedule schedule;bs_block_state state;
    const uint8_t plaintext[8]={'K','G','S','!','@','#','$','%'};
    if(!bs_candidate_generator_init(&generator,initial,length,alpha,count))return 1;
    while(bs_candidate_next(&generator,&batch)!=0) {
      if(!bs_transpose_passwords(&batch,alphabet,alpha,password))return 2;
      bs_make_key_schedule(password,&schedule);
      if(!bs_copy_lm_plaintext_state(&state))return 3;
      bs_des_rounds(state.left,state.right,&schedule);
      bs_final_permutation(state.left,state.right,output);
      for(size_t lane=0;lane<batch.count;lane++) {
        uint8_t pwd[8]={0},deskey[8],expected[8];DES_key_schedule scalar_schedule;
        for(unsigned i=0;i<batch.length[lane];i++)pwd[i]=(uint8_t)alphabet[batch.index[lane][i]];
        DES_str_to_key(pwd,deskey);
        DES_set_key((DES_cblock*)deskey,&scalar_schedule);
        DES_ecb_encrypt((const_DES_cblock*)plaintext,(DES_cblock*)expected,&scalar_schedule,DES_ENCRYPT);
        for(unsigned byte=0;byte<8;byte++)if(output_lane(output,lane,byte)!=expected[byte])return 4;

        bs_vec match=bs_match_valid_block(output,expected,batch.count);
        size_t found=bs_first_match_lane(match,batch.count);
        if(found>=batch.count)return 5;
      }
    }
    return 0;
}

int main(void)
{
    bs_sbox_init();
    bs_init_lm_plaintext_state();
    {
      uint64_t start=0,power=2;
      for(unsigned length=1;length<=7;length++) {
        if(run_case("AB",2,start,7U))return (int)(10U+length);
        start+=power;power*=2U;
      }
    }
    if(run_case("AB",2,0,BS_LANES+9U))return 1;
    if(run_case("ABC",3,2,BS_LANES*2U+1U))return 2;
    if(run_case("ABCDEFGHIJKLMNOPQRSTUVWXYZ",26,25,BS_LANES+3U))return 3;
    if(run_case("Az09!?",6,6U+36U+216U-2U,11U))return 4;
    return 0;
}
