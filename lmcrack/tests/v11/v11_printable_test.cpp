#include <cstdint>
#include <cstring>

#include "v11_printable.h"

static int expect_password(uint64_t cbn,const char *expected)
{
    uint8_t digits[V11_MAX_PASSWORD_LENGTH]; unsigned int length=0;
    uint64_t recovered=UINT64_MAX;
    const size_t expected_length=std::strlen(expected);
    if (!v11_cbn_to_digits(cbn,digits,&length) || length!=expected_length)
      return 1;
    for (unsigned int i=0;i<length;i++)
      if (V11_ALPHABET[digits[i]]!=expected[i]) return 2;
    for (unsigned int i=length;i<V11_MAX_PASSWORD_LENGTH;i++)
      if (digits[i]!=UINT8_MAX) return 3;
    return !v11_digits_to_cbn(digits,length,&recovered) || recovered!=cbn;
}

int main(void)
{
    static const struct { uint64_t cbn; const char *password; } cases[]={
      {0,"0"},{9,"9"},{10,"A"},{35,"Z"},{36," "},{37,"!"},
      {51,"/"},{52,":"},{58,"@"},{59,"["},{64,"`"},{65,"{"},{68,"~"},
      {69,"00"},{70,"10"},{V11_TOTAL_CANDIDATES-1,"~~~~~~~"}
    };
    if (sizeof(V11_ALPHABET)-1U!=V11_ALPHABET_LENGTH ||
        V11_TOTAL_CANDIDATES!=UINT64_C(7555858447479)) return 1;
    for (unsigned int i=0;i<sizeof(cases)/sizeof(cases[0]);i++)
      if (expect_password(cases[i].cbn,cases[i].password)) return 10+(int)i;
    uint64_t start=0,power=V11_ALPHABET_LENGTH;
    for (unsigned int length=1;length<=V11_MAX_PASSWORD_LENGTH;length++) {
      if (v11_length_block_start(length)!=start) return 40+(int)length;
      start+=power; power*=V11_ALPHABET_LENGTH;
    }
    if (start!=V11_TOTAL_CANDIDATES) return 50;
    uint8_t invalid[7]={69}; uint64_t cbn; unsigned int invalid_length=0;
    if (v11_digits_to_cbn(invalid,1,&cbn) ||
        v11_cbn_to_digits(V11_TOTAL_CANDIDATES,invalid,&invalid_length))
      return 51;
    return 0;
}
