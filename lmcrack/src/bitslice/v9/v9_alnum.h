#ifndef LMCRACK_V9_ALNUM_H
#define LMCRACK_V9_ALNUM_H

#include <stddef.h>
#include <stdint.h>

#define V9_ALPHABET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define V9_ALPHABET_LENGTH 36U
#define V9_MAX_PASSWORD_LENGTH 7U
#define V9_TOTAL_CANDIDATES UINT64_C(80603140212)

static inline uint64_t v9_length_block_start(unsigned int length)
{
    uint64_t start=0,power=V9_ALPHABET_LENGTH;
    if (length<1U || length>V9_MAX_PASSWORD_LENGTH) return UINT64_MAX;
    for (unsigned int current=1;current<length;current++) {
      start+=power;
      power*=V9_ALPHABET_LENGTH;
    }
    return start;
}

static inline int v9_cbn_to_digits(uint64_t cbn,
    uint8_t digits[V9_MAX_PASSWORD_LENGTH],unsigned int *length)
{
    uint64_t local=cbn,block_size=V9_ALPHABET_LENGTH;
    unsigned int result_length=1;
    if (digits==NULL || length==NULL || cbn>=V9_TOTAL_CANDIDATES) return 0;
    while (local>=block_size && result_length<V9_MAX_PASSWORD_LENGTH) {
      local-=block_size;
      block_size*=V9_ALPHABET_LENGTH;
      result_length++;
    }
    if (local>=block_size) return 0;
    for (unsigned int i=0;i<V9_MAX_PASSWORD_LENGTH;i++) digits[i]=UINT8_MAX;
    for (unsigned int i=0;i<result_length;i++) {
      digits[i]=(uint8_t)(local%V9_ALPHABET_LENGTH);
      local/=V9_ALPHABET_LENGTH;
    }
    *length=result_length;
    return 1;
}

static inline int v9_digits_to_cbn(
    const uint8_t digits[V9_MAX_PASSWORD_LENGTH],unsigned int length,
    uint64_t *cbn)
{
    uint64_t value,power=1;
    if (digits==NULL || cbn==NULL || length<1U ||
        length>V9_MAX_PASSWORD_LENGTH) return 0;
    value=v9_length_block_start(length);
    for (unsigned int i=0;i<length;i++) {
      if (digits[i]>=V9_ALPHABET_LENGTH) return 0;
      value+=(uint64_t)digits[i]*power;
      power*=V9_ALPHABET_LENGTH;
    }
    if (value>=V9_TOTAL_CANDIDATES) return 0;
    *cbn=value;
    return 1;
}

#endif
