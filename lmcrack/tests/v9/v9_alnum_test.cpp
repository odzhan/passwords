#include <cstdint>
#include <cstring>

#include "v9_alnum.h"

static unsigned int symbol_index(char value)
{
    return value>='0' && value<='9'?(unsigned int)(value-'0'):
           (unsigned int)(value-'A')+10U;
}

static int expect_password(uint64_t cbn,const char *expected)
{
    uint8_t digits[V9_MAX_PASSWORD_LENGTH];
    unsigned int length=0;
    uint64_t recovered=UINT64_MAX;
    size_t expected_length=std::strlen(expected);
    if (!v9_cbn_to_digits(cbn,digits,&length) || length!=expected_length)
      return 1;
    for (unsigned int i=0;i<length;i++)
      if (digits[i]!=symbol_index(expected[i])) return 2;
    for (unsigned int i=length;i<V9_MAX_PASSWORD_LENGTH;i++)
      if (digits[i]!=UINT8_MAX) return 3;
    return !v9_digits_to_cbn(digits,length,&recovered) || recovered!=cbn;
}

static int test_range(uint64_t start,uint64_t count)
{
    for (uint64_t offset=0;offset<count;offset++) {
      uint8_t digits[V9_MAX_PASSWORD_LENGTH];
      unsigned int length;
      uint64_t recovered;
      if (!v9_cbn_to_digits(start+offset,digits,&length) ||
          !v9_digits_to_cbn(digits,length,&recovered) ||
          recovered!=start+offset) return 1;
    }
    return 0;
}

int main(void)
{
    static const struct { uint64_t cbn; const char *password; } cases[]={
      {0,"0"},{9,"9"},{10,"A"},{35,"Z"},{36,"00"},{37,"10"},
      {71,"Z0"},{72,"01"},{1331,"ZZ"},{1332,"000"},
      {V9_TOTAL_CANDIDATES-1,"ZZZZZZZ"}
    };
    uint64_t block_start=0,block_size=V9_ALPHABET_LENGTH;
    if (V9_TOTAL_CANDIDATES!=UINT64_C(80603140212)) return 1;
    for (unsigned int i=0;i<sizeof(cases)/sizeof(cases[0]);i++)
      if (expect_password(cases[i].cbn,cases[i].password)) return 10+(int)i;

    for (unsigned int length=1;length<=V9_MAX_PASSWORD_LENGTH;length++) {
      uint8_t digits[V9_MAX_PASSWORD_LENGTH];
      unsigned int actual;
      if (v9_length_block_start(length)!=block_start) return 30+(int)length;
      if (!v9_cbn_to_digits(block_start,digits,&actual) || actual!=length)
        return 40+(int)length;
      for (unsigned int i=0;i<length;i++) if (digits[i]!=0) return 50+(int)length;
      if (!v9_cbn_to_digits(block_start+block_size-1,digits,&actual) ||
          actual!=length) return 60+(int)length;
      for (unsigned int i=0;i<length;i++) if (digits[i]!=35) return 70+(int)length;
      block_start+=block_size;
      block_size*=V9_ALPHABET_LENGTH;
    }
    if (block_start!=V9_TOTAL_CANDIDATES) return 80;
    if (test_range(37,17) || test_range(127,131) || test_range(1325,19) ||
        test_range(V9_TOTAL_CANDIDATES-13,13)) return 81;

    {
      uint8_t digits[V9_MAX_PASSWORD_LENGTH]={0};
      unsigned int length;
      uint64_t cbn;
      if (v9_cbn_to_digits(V9_TOTAL_CANDIDATES,digits,&length)) return 90;
      if (v9_length_block_start(0)!=UINT64_MAX ||
          v9_length_block_start(8)!=UINT64_MAX) return 91;
      digits[0]=36;
      if (v9_digits_to_cbn(digits,1,&cbn) ||
          v9_digits_to_cbn(digits,0,&cbn) ||
          v9_digits_to_cbn(digits,8,&cbn)) return 92;
    }
    return 0;
}
