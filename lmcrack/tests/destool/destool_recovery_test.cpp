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

static void recover(unsigned int alphabet,uint64_t target,unsigned int threads,
                    const uint8_t plaintext[8])
{
    destool_search_spec search;
    uint8_t expected[7];
    uint64_t size=0;
    assert(destool_keyspace_size(alphabet,2,&size));
    assert(target<size && destool_cbn_to_key(target,alphabet,2,expected));
    memcpy(search.plaintext,plaintext,8);
    encrypt_candidate(plaintext,expected,2,search.ciphertext);
    search.alphabet_id=alphabet;
    search.radix=destool_alphabet_radix(alphabet);
    search.key_length=2;
    search.thread_count=threads;
    search.start_cbn=0;
    search.end_cbn=size;
    const destool_result result=destool_run_search(search,NULL,NULL);
    assert(result.outcome==DESTOOL_FOUND);
    assert(result.recovered_length==2);
    assert(memcmp(result.recovered_key,expected,2)==0);
    assert(result.tested>0 && result.tested<=size);
}

int main(void)
{
    const uint8_t zero[8]={0};
    const uint8_t high[8]={0x80,0xff,0x00,0x7f,0xa5,0x5a,0xc3,0x3c};
    for (unsigned int alphabet=1;alphabet<=7;alphabet++) {
      uint64_t size=0;
      assert(destool_keyspace_size(alphabet,2,&size));
      recover(alphabet,0,1,zero);
      recover(alphabet,size/2U,3,high);
      recover(alphabet,size-1U,7,(alphabet&1U)?zero:high);
    }

    /* Find and recover a case whose ciphertext itself contains both a zero
       byte and a high-bit byte, rather than only exercising them in plaintext. */
    {
      destool_search_spec binary_search;
      uint8_t binary_key[7],binary_ciphertext[8];
      uint64_t binary_cbn=0;
      bool located=false;
      for (;binary_cbn<1000 && !located;binary_cbn++) {
        bool has_zero=false,has_high=false;
        assert(destool_cbn_to_key(binary_cbn,2,3,binary_key));
        encrypt_candidate(high,binary_key,3,binary_ciphertext);
        for (size_t i=0;i<8;i++) {
          has_zero|=binary_ciphertext[i]==0;
          has_high|=(binary_ciphertext[i]&0x80U)!=0;
        }
        located=has_zero && has_high;
      }
      assert(located);
      binary_cbn--;
      memcpy(binary_search.plaintext,high,8);
      memcpy(binary_search.ciphertext,binary_ciphertext,8);
      binary_search.alphabet_id=2; binary_search.radix=10;
      binary_search.key_length=3; binary_search.thread_count=3;
      binary_search.start_cbn=0; binary_search.end_cbn=1000;
      const destool_result binary_result=destool_run_search(binary_search,NULL,NULL);
      assert(binary_result.outcome==DESTOOL_FOUND);
      assert(memcmp(binary_result.recovered_key,binary_key,3)==0);
    }

    /* Exact exhaustion over an uneven three-way partition. */
    destool_search_spec search;
    uint8_t outside[7];
    memcpy(search.plaintext,high,8);
    assert(destool_cbn_to_key(999,2,3,outside));
    encrypt_candidate(high,outside,3,search.ciphertext);
    search.alphabet_id=2; search.radix=10; search.key_length=3;
    search.thread_count=3; search.start_cbn=0; search.end_cbn=997;
    const destool_result result=destool_run_search(search,NULL,NULL);
    assert(result.outcome==DESTOOL_EXHAUSTED);
    assert(result.tested==997);
    return 0;
}
