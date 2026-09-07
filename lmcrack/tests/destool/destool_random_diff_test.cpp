#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "des.h"
#include "destool_runner.h"

static uint64_t random_state=UINT64_C(0x6a09e667f3bcc909);
static uint64_t next_random(void)
{
    random_state^=random_state<<13;
    random_state^=random_state>>7;
    random_state^=random_state<<17;
    return random_state;
}

static void scalar_encrypt(const uint8_t plaintext[8],const uint8_t *material,
                           unsigned int length,uint8_t ciphertext[8])
{
    uint8_t padded[7]={0};
    DES_cblock key,input,output;
    DES_key_schedule schedule;
    memcpy(padded,material,length);
    memcpy(input,plaintext,8);
    DES_str_to_key(padded,key);
    DES_set_key(&key,&schedule);
    DES_ecb_encrypt(&input,&output,&schedule,1);
    memcpy(ciphertext,output,8);
}

static uint8_t output_byte(const bs_vec output[64],size_t lane,size_t byte)
{
    uint8_t value=0,packed[BS_BYTES];
    for (size_t bit=0;bit<8;bit++) {
      bs_store(packed,output[byte*8U+bit]);
      value=(uint8_t)((value<<1)|((packed[lane>>3]>>(lane&7U))&1U));
    }
    return value;
}

static void compare_batch(unsigned int alphabet,unsigned int length,
                          uint64_t start,size_t count,
                          const uint8_t plaintext[8])
{
    destool_bitslice_counter counter;
    bs_vec key_planes[BS_KEY_PLANES],output[64];
    bs_block_state state;
    assert(destool_bs_counter_init(&counter,alphabet,length,start,count));
    assert(destool_bs_make_key_planes(&counter,key_planes));
    assert(bs_prepare_plaintext_state(plaintext,&state));
    assert(bs_fixed_encrypt_state(&state,key_planes));
    assert(bs_final_permutation(state.left,state.right,output));
    for (size_t lane=0;lane<count;lane++) {
      uint8_t material[7],expected[8];
      assert(destool_cbn_to_key(start+lane,alphabet,length,material));
      scalar_encrypt(plaintext,material,length,expected);
      for (size_t byte=0;byte<8;byte++)
        assert(output_byte(output,lane,byte)==expected[byte]);
    }
}

static void compare_worker(unsigned int alphabet,unsigned int length,
                           uint64_t start,uint64_t count,uint64_t target_offset,
                           const uint8_t plaintext[8])
{
    destool_search_spec search;
    uint8_t expected[7];
    assert(target_offset<count);
    assert(destool_cbn_to_key(start+target_offset,alphabet,length,expected));
    memcpy(search.plaintext,plaintext,8);
    scalar_encrypt(plaintext,expected,length,search.ciphertext);
    search.alphabet_id=alphabet;
    search.radix=destool_alphabet_radix(alphabet);
    search.key_length=length;
    search.thread_count=1;
    search.start_cbn=start;
    search.end_cbn=start+count;
    const destool_result result=destool_run_search(search,NULL,NULL);
    const uint64_t expected_tested=
      ((target_offset/(uint64_t)BS_LANES)+1U)*(uint64_t)BS_LANES<count?
      ((target_offset/(uint64_t)BS_LANES)+1U)*(uint64_t)BS_LANES:count;
    assert(result.outcome==DESTOOL_FOUND);
    assert(result.recovered_length==length);
    assert(memcmp(result.recovered_key,expected,length)==0);
    assert(result.tested==expected_tested);
}

int main(void)
{
    bs_sbox_init();
    for (unsigned int alphabet=1;alphabet<=7;alphabet++) {
      for (unsigned int iteration=0;iteration<16;iteration++) {
        const unsigned int length=1U+(unsigned int)(next_random()%7U);
        uint64_t size=0;
        assert(destool_keyspace_size(alphabet,length,&size));
        const size_t limit=(size_t)(size<BS_LANES?size:BS_LANES);
        const size_t count=1U+(size_t)(next_random()%limit);
        const uint64_t start=next_random()%(size-count+1U);
        uint8_t plaintext[8];
        for (size_t i=0;i<8;i++) plaintext[i]=(uint8_t)next_random();
        compare_batch(alphabet,length,start,count,plaintext);
      }

      /* Cross a SIMD boundary and verify the worker's batch-granular but exact
         tested count against the documented accounting rule. */
      const unsigned int length=alphabet==2?4U:3U;
      uint64_t size=0;
      assert(destool_keyspace_size(alphabet,length,&size));
      const uint64_t count=size<(uint64_t)BS_LANES*2U+9U?size:
        (uint64_t)BS_LANES*2U+9U;
      uint8_t plaintext[8];
      for (size_t i=0;i<8;i++) plaintext[i]=(uint8_t)next_random();
      compare_worker(alphabet,length,0,count,count-1U,plaintext);
    }
    return 0;
}
