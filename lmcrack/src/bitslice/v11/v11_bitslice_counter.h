#ifndef LMCRACK_V11_BITSLICE_COUNTER_H
#define LMCRACK_V11_BITSLICE_COUNTER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bitslice_vec.h"
#include "v11_printable.h"

#define V11_DIGIT_BITS 7U

#if defined(_MSC_VER)
#define V11_COUNTER_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define V11_COUNTER_INLINE inline __attribute__((always_inline))
#else
#define V11_COUNTER_INLINE inline
#endif

typedef struct {
    bs_vec digit[V11_MAX_PASSWORD_LENGTH][V11_DIGIT_BITS];
    uint64_t current_cbn;
    uint64_t block_end_cbn;
    uint64_t remaining;
    size_t count;
    unsigned int length;
} v11_bitslice_counter;

static V11_COUNTER_INLINE bs_vec v11_bs_constant_bit(unsigned int bit)
{
    return bit?bs_ones():bs_zero();
}

static V11_COUNTER_INLINE bs_vec v11_bs_full_adder(
    bs_vec a,bs_vec b,bs_vec carry,bs_vec *sum)
{
    const bs_vec a_xor_b=bs_xor(a,b);
    *sum=bs_xor(a_xor_b,carry);
    return bs_or(bs_and(a,b),bs_and(carry,a_xor_b));
}

static V11_COUNTER_INLINE bs_vec v11_bs_add_base69_digit(
    bs_vec value[V11_DIGIT_BITS],unsigned int scalar_digit,bs_vec carry_in)
{
    bs_vec sum[V11_DIGIT_BITS],reduced[V11_DIGIT_BITS];
    bs_vec carry=carry_in;
    for (unsigned int bit=0;bit<V11_DIGIT_BITS;bit++)
      carry=v11_bs_full_adder(value[bit],
        v11_bs_constant_bit((scalar_digit>>bit)&1U),carry,&sum[bit]);

    /* Compare the seven-bit sum with 69 (0b1000101). */
    bs_vec equal=bs_ones(),greater=bs_zero();
    for (unsigned int offset=0;offset<V11_DIGIT_BITS;offset++) {
      const unsigned int bit=V11_DIGIT_BITS-1U-offset;
      if ((V11_ALPHABET_LENGTH>>bit)&1U) equal=bs_and(equal,sum[bit]);
      else {
        greater=bs_or(greater,bs_and(equal,sum[bit]));
        equal=bs_and(equal,bs_not(sum[bit]));
      }
    }
    const bs_vec reduce=bs_or(carry,bs_or(greater,equal));

    /* Conditional subtraction of 69 is addition of 59 modulo 128. */
    carry=bs_zero();
    for (unsigned int bit=0;bit<V11_DIGIT_BITS;bit++) {
      const bs_vec addend=((59U>>bit)&1U)?reduce:bs_zero();
      carry=v11_bs_full_adder(sum[bit],addend,carry,&reduced[bit]);
    }
    for (unsigned int bit=0;bit<V11_DIGIT_BITS;bit++) value[bit]=reduced[bit];
    return reduce;
}

static inline void v11_bs_add_constant(v11_bitslice_counter *counter,
                                        unsigned int amount)
{
    bs_vec carry=bs_zero();
    for (unsigned int position=0;position<counter->length;position++) {
      const unsigned int scalar_digit=amount%V11_ALPHABET_LENGTH;
      amount/=V11_ALPHABET_LENGTH;
      carry=v11_bs_add_base69_digit(counter->digit[position],scalar_digit,carry);
    }
}

static inline int v11_bs_counter_load(v11_bitslice_counter *counter,
    uint64_t start_cbn,uint64_t remaining)
{
    uint8_t first[V11_MAX_PASSWORD_LENGTH];
    uint64_t powers[V11_MAX_PASSWORD_LENGTH];
    uint64_t block_start,block_size=1,available;
    unsigned int length=0;
    if (counter==NULL || remaining==0 || start_cbn>=V11_TOTAL_CANDIDATES ||
        remaining>V11_TOTAL_CANDIDATES-start_cbn) return 0;
    if (!v11_cbn_to_digits(start_cbn,first,&length)) return 0;
    block_start=v11_length_block_start(length);
    for (unsigned int i=0;i<length;i++) block_size*=V11_ALPHABET_LENGTH;
    powers[0]=1;
    for (unsigned int i=1;i<V11_MAX_PASSWORD_LENGTH;i++)
      powers[i]=powers[i-1]*V11_ALPHABET_LENGTH;

    counter->current_cbn=start_cbn;
    counter->block_end_cbn=block_start+block_size;
    counter->remaining=remaining;
    counter->length=length;
    available=counter->block_end_cbn-start_cbn;
    if (available>remaining) available=remaining;
    counter->count=(size_t)(available<BS_LANES?available:BS_LANES);
    for (unsigned int position=0;position<V11_MAX_PASSWORD_LENGTH;position++)
      for (unsigned int bit=0;bit<V11_DIGIT_BITS;bit++) {
        uint8_t packed[BS_BYTES];
        memset(packed,0,sizeof(packed));
        if (position<length) {
          const uint64_t local=start_cbn-block_start;
          for (size_t lane=0;lane<counter->count;lane++) {
            const unsigned int digit=(unsigned int)(((local+lane)/
              powers[position])%V11_ALPHABET_LENGTH);
            if ((digit>>bit)&1U)
              packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
          }
        }
        counter->digit[position][bit]=bs_load(packed);
      }
    return 1;
}

static inline int v11_bs_counter_init(v11_bitslice_counter *counter,
    uint64_t start_cbn,uint64_t candidate_count)
{
    if (counter==NULL) return 0;
    memset(counter,0,sizeof(*counter));
    return v11_bs_counter_load(counter,start_cbn,candidate_count);
}

static inline int v11_bs_counter_advance(v11_bitslice_counter *counter)
{
    uint64_t step,available;
    if (counter==NULL || counter->count==0 ||
        counter->count>counter->remaining) return 0;
    step=(uint64_t)counter->count;
    counter->current_cbn+=step;
    counter->remaining-=step;
    if (counter->remaining==0) { counter->count=0; return 0; }
    if (counter->current_cbn==counter->block_end_cbn)
      return v11_bs_counter_load(counter,counter->current_cbn,counter->remaining);
    if (step!=BS_LANES || counter->current_cbn>counter->block_end_cbn) {
      counter->count=0; return 0;
    }
    v11_bs_add_constant(counter,(unsigned int)step);
    available=counter->block_end_cbn-counter->current_cbn;
    if (available>counter->remaining) available=counter->remaining;
    counter->count=(size_t)(available<BS_LANES?available:BS_LANES);
    return 1;
}

#undef V11_COUNTER_INLINE

#endif
