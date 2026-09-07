#ifndef LMCRACK_V9_BITSLICE_COUNTER_H
#define LMCRACK_V9_BITSLICE_COUNTER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bitslice_vec.h"
#include "v9_alnum.h"

#define V9_DIGIT_BITS 6U

#if defined(_MSC_VER)
#define V9_COUNTER_FORCE_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define V9_COUNTER_FORCE_INLINE inline __attribute__((always_inline))
#else
#define V9_COUNTER_FORCE_INLINE inline
#endif

typedef struct {
    bs_vec digit[V9_MAX_PASSWORD_LENGTH][V9_DIGIT_BITS];
    uint64_t current_cbn;
    uint64_t block_end_cbn;
    uint64_t remaining;
    size_t count;
    unsigned int length;
} v9_bitslice_counter;

static V9_COUNTER_FORCE_INLINE bs_vec v9_bs_constant_bit(unsigned int bit)
{
    return bit?bs_ones():bs_zero();
}

static V9_COUNTER_FORCE_INLINE bs_vec v9_bs_full_adder(
    bs_vec a,bs_vec b,bs_vec carry,bs_vec *sum)
{
    bs_vec a_xor_b=bs_xor(a,b);
    *sum=bs_xor(a_xor_b,carry);
    return bs_or(bs_and(a,b),bs_and(carry,a_xor_b));
}

/* Add a scalar digit and lane carry, then reduce the result modulo 36. */
static V9_COUNTER_FORCE_INLINE bs_vec v9_bs_add_base36_digit(
    bs_vec value[V9_DIGIT_BITS],unsigned int scalar_digit,bs_vec carry_in)
{
    bs_vec binary_sum[V9_DIGIT_BITS],reduced[V9_DIGIT_BITS];
    bs_vec carry=carry_in;
    for (unsigned int bit=0;bit<V9_DIGIT_BITS;bit++)
      carry=v9_bs_full_adder(value[bit],
        v9_bs_constant_bit((scalar_digit>>bit)&1U),carry,&binary_sum[bit]);

    /* For a six-bit value, x >= 36 iff x5 && (x4 || x3 || x2). */
    bs_vec at_least_36=bs_or(carry,
      bs_and(binary_sum[5],bs_or(binary_sum[4],
             bs_or(binary_sum[3],binary_sum[2]))));

    /* Conditional subtraction of 36 is addition of 28 modulo 64. */
    carry=bs_zero();
    for (unsigned int bit=0;bit<V9_DIGIT_BITS;bit++) {
      bs_vec addend=(bit==2U || bit==3U || bit==4U)?at_least_36:bs_zero();
      carry=v9_bs_full_adder(binary_sum[bit],addend,carry,&reduced[bit]);
    }
    for (unsigned int bit=0;bit<V9_DIGIT_BITS;bit++) value[bit]=reduced[bit];
    return at_least_36;
}

static inline void v9_bs_add_constant(v9_bitslice_counter *counter,
                                      unsigned int amount)
{
    bs_vec carry=bs_zero();
    for (unsigned int position=0;position<counter->length;position++) {
      unsigned int scalar_digit=amount%V9_ALPHABET_LENGTH;
      amount/=V9_ALPHABET_LENGTH;
      carry=v9_bs_add_base36_digit(counter->digit[position],scalar_digit,carry);
    }
}

static inline int v9_bs_counter_load(v9_bitslice_counter *counter,
    uint64_t start_cbn,uint64_t remaining)
{
    uint8_t first[V9_MAX_PASSWORD_LENGTH];
    uint64_t powers[V9_MAX_PASSWORD_LENGTH];
    uint64_t block_start,block_size=1,available;
    unsigned int length=0;
    if (counter==NULL || remaining==0 || start_cbn>=V9_TOTAL_CANDIDATES ||
        remaining>V9_TOTAL_CANDIDATES-start_cbn) return 0;
    if (!v9_cbn_to_digits(start_cbn,first,&length)) return 0;

    block_start=v9_length_block_start(length);
    for (unsigned int i=0;i<length;i++) block_size*=V9_ALPHABET_LENGTH;
    powers[0]=1;
    for (unsigned int i=1;i<V9_MAX_PASSWORD_LENGTH;i++)
      powers[i]=powers[i-1]*V9_ALPHABET_LENGTH;

    counter->current_cbn=start_cbn;
    counter->block_end_cbn=block_start+block_size;
    counter->remaining=remaining;
    counter->length=length;
    available=counter->block_end_cbn-start_cbn;
    if (available>remaining) available=remaining;
    counter->count=(size_t)((available<BS_LANES)?available:BS_LANES);

    for (unsigned int position=0;position<V9_MAX_PASSWORD_LENGTH;position++)
      for (unsigned int bit=0;bit<V9_DIGIT_BITS;bit++) {
        uint8_t packed[BS_BYTES];
        memset(packed,0,sizeof(packed));
        if (position<length) {
          uint64_t local=start_cbn-block_start;
          for (size_t lane=0;lane<counter->count;lane++) {
            unsigned int digit=(unsigned int)(((local+lane)/powers[position])%
                                               V9_ALPHABET_LENGTH);
            if ((digit>>bit)&1U) packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
          }
        }
        counter->digit[position][bit]=bs_load(packed);
      }
    return 1;
}

static inline int v9_bs_counter_init(v9_bitslice_counter *counter,
    uint64_t start_cbn,uint64_t candidate_count)
{
    if (counter==NULL) return 0;
    memset(counter,0,sizeof(*counter));
    return v9_bs_counter_load(counter,start_cbn,candidate_count);
}

static inline int v9_bs_counter_advance(v9_bitslice_counter *counter)
{
    uint64_t step,available;
    if (counter==NULL || counter->count==0 ||
        counter->count>counter->remaining) return 0;
    step=(uint64_t)counter->count;
    counter->current_cbn+=step;
    counter->remaining-=step;
    if (counter->remaining==0) { counter->count=0; return 0; }
    if (counter->current_cbn==counter->block_end_cbn)
      return v9_bs_counter_load(counter,counter->current_cbn,counter->remaining);
    if (step!=BS_LANES || counter->current_cbn>counter->block_end_cbn) {
      counter->count=0; return 0;
    }
    v9_bs_add_constant(counter,(unsigned int)step);
    available=counter->block_end_cbn-counter->current_cbn;
    if (available>counter->remaining) available=counter->remaining;
    counter->count=(size_t)((available<BS_LANES)?available:BS_LANES);
    return 1;
}

#undef V9_COUNTER_FORCE_INLINE

#endif
