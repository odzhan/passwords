#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "des.h"
#include "destool_worker.h"

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

static void run_found(unsigned int alphabet,unsigned int length,uint64_t start,
                      uint64_t count,uint64_t target_cbn)
{
    destool_search_spec search;
    destool_shared_state shared;
    destool_worker_job job;
    const uint8_t plaintext[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    uint8_t target_key[7];
    memcpy(search.plaintext,plaintext,8);
    assert(destool_cbn_to_key(target_cbn,alphabet,length,target_key));
    encrypt_candidate(plaintext,target_key,length,search.ciphertext);
    search.alphabet_id=alphabet;
    search.radix=destool_alphabet_radix(alphabet);
    search.key_length=length;
    search.thread_count=1;
    search.start_cbn=start;
    search.end_cbn=start+count;
    job.search=&search;job.shared=&shared;job.worker_index=0;
    job.start_cbn=start;job.end_cbn=start+count;
    bs_sbox_init();
    destool_worker_run(&job);
    assert(shared.found.load(std::memory_order_acquire));
    assert(!shared.failed.load(std::memory_order_acquire));
    assert(shared.recovered_length==length);
    assert(memcmp(shared.recovered_key,target_key,length)==0);
    assert(shared.tested.load(std::memory_order_relaxed)>=target_cbn-start+1U);
    assert(shared.tested.load(std::memory_order_relaxed)<=count);
}

int main(void)
{
    run_found(2,3,0,BS_LANES,0);
    run_found(3,3,100,BS_LANES,100+BS_LANES/2U);
    run_found(5,4,1000,BS_LANES,1000+BS_LANES-1U);
    run_found(7,4,2000,BS_LANES+7U,2000+BS_LANES+6U);
    run_found(1,2,0,BS_LANES,BS_LANES/3U);

    {
      destool_search_spec search;
      destool_shared_state shared;
      destool_worker_job job;
      const uint8_t plaintext[8]={0};
      uint8_t outside[7];
      assert(destool_cbn_to_key(BS_LANES+10U,2,3,outside));
      memcpy(search.plaintext,plaintext,8);
      encrypt_candidate(plaintext,outside,3,search.ciphertext);
      search.alphabet_id=2;search.radix=10;search.key_length=3;
      search.thread_count=1;search.start_cbn=0;search.end_cbn=BS_LANES;
      job.search=&search;job.shared=&shared;job.start_cbn=0;job.end_cbn=BS_LANES;
      destool_worker_run(&job);
      assert(!shared.found.load() && !shared.failed.load());
      assert(shared.tested.load()==BS_LANES);
    }
    {
      destool_shared_state shared;
      destool_worker_job invalid;
      invalid.shared=&shared;
      destool_worker_run(&invalid);
      assert(shared.failed.load() && shared.stop.load());
    }
    return 0;
}
