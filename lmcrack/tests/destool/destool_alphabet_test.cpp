#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "destool_alphabet.h"

static void test_symbols(unsigned int alphabet_id)
{
    const unsigned int radix=destool_alphabet_radix(alphabet_id);
    for (unsigned int digit=0;digit<radix;digit++) {
      uint8_t value=0;
      unsigned int recovered=UINT32_MAX;
      assert(destool_digit_to_byte(alphabet_id,digit,&value));
      assert(destool_byte_to_digit(alphabet_id,value,&recovered));
      assert(recovered==digit);
    }
    uint8_t ignored;
    assert(!destool_digit_to_byte(alphabet_id,radix,&ignored));
}

static void test_length(unsigned int alphabet_id,unsigned int length)
{
    uint64_t size=0,roundtrip=0;
    uint8_t key[DESTOOL_MAX_KEY_BYTES];
    assert(destool_keyspace_size(alphabet_id,length,&size));
    const uint64_t cases[]={0,1,size/2,size-2,size-1};
    for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
      assert(destool_cbn_to_key(cases[i],alphabet_id,length,key));
      assert(destool_key_to_cbn(key,alphabet_id,length,&roundtrip));
      assert(roundtrip==cases[i]);
      for (unsigned int position=length;position<DESTOOL_MAX_KEY_BYTES;position++)
        assert(key[position]==0);
    }
    assert(!destool_cbn_to_key(size,alphabet_id,length,key));

    const unsigned int radix=destool_alphabet_radix(alphabet_id);
    if (length>1) {
      assert(destool_cbn_to_key(radix-1U,alphabet_id,length,key));
      unsigned int digit0=0,digit1=0;
      assert(destool_byte_to_digit(alphabet_id,key[0],&digit0));
      assert(destool_byte_to_digit(alphabet_id,key[1],&digit1));
      assert(digit0==radix-1U && digit1==0);
      assert(destool_cbn_to_key(radix,alphabet_id,length,key));
      assert(destool_byte_to_digit(alphabet_id,key[0],&digit0));
      assert(destool_byte_to_digit(alphabet_id,key[1],&digit1));
      assert(digit0==0 && digit1==1);
    }
}

int main(void)
{
    static const unsigned int expected_radix[8]={0,256,10,26,26,36,36,62};
    for (unsigned int alphabet=1;alphabet<=7;alphabet++) {
      assert(destool_alphabet_radix(alphabet)==expected_radix[alphabet]);
      test_symbols(alphabet);
      for (unsigned int length=1;length<=DESTOOL_MAX_KEY_BYTES;length++)
        test_length(alphabet,length);
    }
    assert(destool_alphabet_radix(0)==0 && destool_alphabet_radix(8)==0);
    uint64_t size;
    uint8_t key[DESTOOL_MAX_KEY_BYTES]={0};
    assert(!destool_keyspace_size(0,1,&size));
    assert(!destool_keyspace_size(1,0,&size));
    assert(!destool_keyspace_size(1,8,&size));
    assert(!destool_key_to_cbn(key,2,1,NULL));
    unsigned int invalid_digit=0;
    assert(!destool_byte_to_digit(2,(uint8_t)'A',&invalid_digit));
    return 0;
}
