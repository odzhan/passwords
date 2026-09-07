#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "des.h"
#include "destool_runner.h"

static void encrypt_candidate(const uint8_t plaintext[8],const uint8_t *key,
                              unsigned int length,uint8_t ciphertext[8])
{
    uint8_t padded[7]={0};
    DES_cblock des_key,input,output;
    DES_key_schedule schedule;
    memcpy(padded,key,length);
    memcpy(input,plaintext,8);
    DES_str_to_key(padded,des_key);
    DES_set_key(&des_key,&schedule);
    DES_ecb_encrypt(&input,&output,&schedule,1);
    memcpy(ciphertext,output,8);
}

struct progress_state { unsigned int calls; uint64_t final_tested; bool final; };
static void progress(uint64_t tested,uint64_t,double,bool final,void *context)
{
    progress_state *state=(progress_state *)context;
    state->calls++;
    if (final) { state->final=true; state->final_tested=tested; }
}

int main(void)
{
    destool_search_spec search;
    const uint8_t plaintext[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    uint8_t expected[7];
    memcpy(search.plaintext,plaintext,8);
    assert(destool_cbn_to_key(777,2,3,expected));
    encrypt_candidate(plaintext,expected,3,search.ciphertext);
    search.alphabet_id=2; search.radix=10; search.key_length=3;
    search.thread_count=7; search.start_cbn=0; search.end_cbn=1000;
    progress_state state={0,0,false};
    destool_result result=destool_run_search(search,progress,&state);
    assert(result.outcome==DESTOOL_FOUND);
    assert(result.recovered_length==3 && memcmp(result.recovered_key,expected,3)==0);
    assert(result.tested>0 && result.tested<=1000);
    assert(state.calls>=1 && state.final && state.final_tested==result.tested);

    uint8_t outside[7];
    assert(destool_cbn_to_key(999,2,3,outside));
    encrypt_candidate(plaintext,outside,3,search.ciphertext);
    search.thread_count=3; search.start_cbn=0; search.end_cbn=997;
    result=destool_run_search(search,NULL,NULL);
    assert(result.outcome==DESTOOL_EXHAUSTED && result.tested==997);

    search.thread_count=0;
    result=destool_run_search(search,NULL,NULL);
    assert(result.outcome==DESTOOL_INVALID_INPUT);
    return 0;
}
