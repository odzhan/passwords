#ifndef LMCRACK_V8_UPPERCASE_H
#define LMCRACK_V8_UPPERCASE_H

#include <stddef.h>
#include <stdint.h>

#define V8_ALPHABET_LENGTH 26U
#define V8_MAX_PASSWORD_LENGTH 7U
#define V8_TOTAL_CANDIDATES UINT64_C(8353082582)
#define V8_ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

/*
 * v8 uses the same zero-based sequence as cracker::cbn2idx():
 *
 *   0=A, 25=Z, 26=AA, 701=ZZ, 702=AAA
 *
 * Character position zero is the least-significant base-26 digit and changes
 * fastest.  These helpers are for range initialization and match recovery;
 * the steady-state v8 generator will advance candidates directly in planes.
 */
static inline uint64_t v8_length_block_start(unsigned int length)
{
    uint64_t start=0;
    uint64_t power=V8_ALPHABET_LENGTH;
    if (length<1U || length>V8_MAX_PASSWORD_LENGTH) return UINT64_MAX;
    for (unsigned int current=1;current<length;current++) {
      start+=power;
      power*=V8_ALPHABET_LENGTH;
    }
    return start;
}

static inline int v8_cbn_to_digits(uint64_t cbn,
    uint8_t digits[V8_MAX_PASSWORD_LENGTH],unsigned int *length)
{
    uint64_t local=cbn;
    uint64_t block_size=V8_ALPHABET_LENGTH;
    unsigned int result_length=1;

    if (digits==NULL || length==NULL || cbn>=V8_TOTAL_CANDIDATES) return 0;
    while (local>=block_size && result_length<V8_MAX_PASSWORD_LENGTH) {
      local-=block_size;
      block_size*=V8_ALPHABET_LENGTH;
      result_length++;
    }
    if (local>=block_size) return 0;

    for (unsigned int position=0;position<V8_MAX_PASSWORD_LENGTH;position++)
      digits[position]=UINT8_MAX;
    for (unsigned int position=0;position<result_length;position++) {
      digits[position]=(uint8_t)(local%V8_ALPHABET_LENGTH);
      local/=V8_ALPHABET_LENGTH;
    }
    *length=result_length;
    return 1;
}

static inline int v8_digits_to_cbn(
    const uint8_t digits[V8_MAX_PASSWORD_LENGTH],unsigned int length,
    uint64_t *cbn)
{
    uint64_t value,power=1;
    if (digits==NULL || cbn==NULL || length<1U ||
        length>V8_MAX_PASSWORD_LENGTH) return 0;

    value=v8_length_block_start(length);
    for (unsigned int position=0;position<length;position++) {
      if (digits[position]>=V8_ALPHABET_LENGTH) return 0;
      value+=(uint64_t)digits[position]*power;
      power*=V8_ALPHABET_LENGTH;
    }
    if (value>=V8_TOTAL_CANDIDATES) return 0;
    *cbn=value;
    return 1;
}

#endif
