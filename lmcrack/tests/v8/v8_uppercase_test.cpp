#include <cstdint>
#include <cstring>

#include "v8_uppercase.h"

static int expect_password(uint64_t cbn,const char *expected)
{
    uint8_t digits[V8_MAX_PASSWORD_LENGTH];
    unsigned int length=0;
    uint64_t recovered=UINT64_MAX;
    size_t expected_length=std::strlen(expected);

    if (!v8_cbn_to_digits(cbn,digits,&length)) return 1;
    if (length!=expected_length) return 2;
    for (unsigned int i=0;i<length;i++)
      if (digits[i]!=(uint8_t)(expected[i]-'A')) return 3;
    for (unsigned int i=length;i<V8_MAX_PASSWORD_LENGTH;i++)
      if (digits[i]!=UINT8_MAX) return 4;
    if (!v8_digits_to_cbn(digits,length,&recovered) || recovered!=cbn)
      return 5;
    return 0;
}

static int test_range(uint64_t start,uint64_t count)
{
    for (uint64_t offset=0;offset<count;offset++) {
      uint8_t digits[V8_MAX_PASSWORD_LENGTH];
      unsigned int length=0;
      uint64_t recovered=UINT64_MAX;
      if (!v8_cbn_to_digits(start+offset,digits,&length)) return 1;
      if (!v8_digits_to_cbn(digits,length,&recovered)) return 2;
      if (recovered!=start+offset) return 3;
    }
    return 0;
}

int main(void)
{
    static const struct { uint64_t cbn; const char *password; } cases[]={
      {0,"A"},{25,"Z"},{26,"AA"},{27,"BA"},{51,"ZA"},{52,"AB"},
      {701,"ZZ"},{702,"AAA"},{V8_TOTAL_CANDIDATES-1,"ZZZZZZZ"}
    };
    uint64_t block_start=0,block_size=V8_ALPHABET_LENGTH;

    if (V8_TOTAL_CANDIDATES!=UINT64_C(8353082582)) return 1;
    for (unsigned int i=0;i<sizeof(cases)/sizeof(cases[0]);i++)
      if (expect_password(cases[i].cbn,cases[i].password)) return 10+(int)i;

    /* Independently verify the first and last CBN in every length block. */
    for (unsigned int length=1;length<=V8_MAX_PASSWORD_LENGTH;length++) {
      uint8_t digits[V8_MAX_PASSWORD_LENGTH];
      unsigned int actual_length=0;
      if (v8_length_block_start(length)!=block_start) return 30+(int)length;
      if (!v8_cbn_to_digits(block_start,digits,&actual_length) ||
          actual_length!=length) return 40+(int)length;
      for (unsigned int i=0;i<length;i++) if (digits[i]!=0) return 50+(int)length;
      if (!v8_cbn_to_digits(block_start+block_size-1,digits,&actual_length) ||
          actual_length!=length) return 60+(int)length;
      for (unsigned int i=0;i<length;i++) if (digits[i]!=25) return 70+(int)length;
      block_start+=block_size;
      block_size*=V8_ALPHABET_LENGTH;
    }
    if (block_start!=V8_TOTAL_CANDIDATES) return 80;

    /* Non-aligned thread starts, partial batches, and boundary crossings. */
    if (test_range(37,17)) return 81;
    if (test_range(63,67)) return 82;
    if (test_range(127,131)) return 83;
    if (test_range(255,259)) return 84;
    if (test_range(695,19)) return 85; /* crosses ZZ -> AAA */
    if (test_range(V8_TOTAL_CANDIDATES-13,13)) return 86;

    {
      uint8_t digits[V8_MAX_PASSWORD_LENGTH]={0};
      unsigned int length=0;
      uint64_t cbn=0;
      if (v8_cbn_to_digits(V8_TOTAL_CANDIDATES,digits,&length)) return 90;
      if (v8_length_block_start(0)!=UINT64_MAX ||
          v8_length_block_start(8)!=UINT64_MAX) return 91;
      digits[0]=26;
      if (v8_digits_to_cbn(digits,1,&cbn)) return 92;
      if (v8_digits_to_cbn(digits,0,&cbn) ||
          v8_digits_to_cbn(digits,8,&cbn)) return 93;
    }
    return 0;
}
