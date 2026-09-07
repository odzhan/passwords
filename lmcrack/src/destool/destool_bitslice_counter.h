#ifndef DESTOOL_BITSLICE_COUNTER_H
#define DESTOOL_BITSLICE_COUNTER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bitslice_vec.h"
#include "destool_alphabet.h"

#define DESTOOL_MAX_DIGIT_BITS 8U

#if defined(_MSC_VER)
#define DESTOOL_COUNTER_INLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define DESTOOL_COUNTER_INLINE inline __attribute__((always_inline))
#else
#define DESTOOL_COUNTER_INLINE inline
#endif

struct destool_bitslice_counter {
    bs_vec digit[DESTOOL_MAX_KEY_BYTES][DESTOOL_MAX_DIGIT_BITS];
    uint64_t current_cbn;
    uint64_t remaining;
    size_t count;
    unsigned int alphabet_id;
    unsigned int radix;
    unsigned int digit_bits;
    unsigned int length;
};

static DESTOOL_COUNTER_INLINE bs_vec destool_bs_constant_bit(unsigned int bit)
{
    return bit?bs_ones():bs_zero();
}

static DESTOOL_COUNTER_INLINE bs_vec destool_bs_full_adder(
    bs_vec a,bs_vec b,bs_vec carry,bs_vec *sum)
{
    const bs_vec a_xor_b=bs_xor(a,b);
    *sum=bs_xor(a_xor_b,carry);
    return bs_or(bs_and(a,b),bs_and(carry,a_xor_b));
}

template <unsigned int Radix,unsigned int Bits>
static DESTOOL_COUNTER_INLINE bs_vec destool_bs_add_digit(
    bs_vec value[DESTOOL_MAX_DIGIT_BITS],unsigned int scalar_digit,
    bs_vec carry_in)
{
    bs_vec sum[DESTOOL_MAX_DIGIT_BITS],reduced[DESTOOL_MAX_DIGIT_BITS];
    bs_vec carry=carry_in;
    for (unsigned int bit=0;bit<Bits;bit++)
      carry=destool_bs_full_adder(value[bit],
        destool_bs_constant_bit((scalar_digit>>bit)&1U),carry,&sum[bit]);

    bs_vec reduce=carry;
    if (Radix!=(1U<<Bits)) {
      bs_vec equal=bs_ones(),greater=bs_zero();
      for (unsigned int offset=0;offset<Bits;offset++) {
        const unsigned int bit=Bits-1U-offset;
        if ((Radix>>bit)&1U) equal=bs_and(equal,sum[bit]);
        else {
          greater=bs_or(greater,bs_and(equal,sum[bit]));
          equal=bs_and(equal,bs_not(sum[bit]));
        }
      }
      reduce=bs_or(reduce,bs_or(greater,equal));
    }

    carry=bs_zero();
    const unsigned int correction=((1U<<Bits)-Radix)&((1U<<Bits)-1U);
    for (unsigned int bit=0;bit<Bits;bit++) {
      const bs_vec addend=((correction>>bit)&1U)?reduce:bs_zero();
      carry=destool_bs_full_adder(sum[bit],addend,carry,&reduced[bit]);
    }
    for (unsigned int bit=0;bit<Bits;bit++) value[bit]=reduced[bit];
    return reduce;
}

template <unsigned int Radix,unsigned int Bits>
static inline void destool_bs_add_constant(destool_bitslice_counter *counter,
                                            unsigned int amount)
{
    bs_vec carry=bs_zero();
    for (unsigned int position=0;position<counter->length;position++) {
      const unsigned int scalar_digit=amount%Radix;
      amount/=Radix;
      carry=destool_bs_add_digit<Radix,Bits>(
        counter->digit[position],scalar_digit,carry);
    }
}

static inline unsigned int destool_digit_bits(unsigned int radix)
{
    switch (radix) {
      case 10: return 4;
      case 26: return 5;
      case 36: case 62: return 6;
      case 256: return 8;
      default: return 0;
    }
}

static inline bool destool_bs_counter_load(destool_bitslice_counter *counter,
    uint64_t start_cbn,uint64_t remaining)
{
    uint64_t powers[DESTOOL_MAX_KEY_BYTES];
    if (counter==NULL || remaining==0) return false;
    powers[0]=1;
    for (unsigned int position=1;position<DESTOOL_MAX_KEY_BYTES;position++)
      powers[position]=powers[position-1]*counter->radix;
    counter->current_cbn=start_cbn;
    counter->remaining=remaining;
    counter->count=(size_t)(remaining<BS_LANES?remaining:BS_LANES);
    for (unsigned int position=0;position<DESTOOL_MAX_KEY_BYTES;position++)
      for (unsigned int bit=0;bit<DESTOOL_MAX_DIGIT_BITS;bit++) {
        uint8_t packed[BS_BYTES];
        memset(packed,0,sizeof(packed));
        if (position<counter->length && bit<counter->digit_bits) {
          for (size_t lane=0;lane<counter->count;lane++) {
            const unsigned int digit=(unsigned int)(((start_cbn+lane)/
              powers[position])%counter->radix);
            if ((digit>>bit)&1U)
              packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
          }
        }
        counter->digit[position][bit]=bs_load(packed);
      }
    return true;
}

static inline bool destool_bs_counter_init(destool_bitslice_counter *counter,
    unsigned int alphabet_id,unsigned int length,uint64_t start_cbn,
    uint64_t candidate_count)
{
    uint64_t size;
    if (counter==NULL || candidate_count==0 ||
        !destool_keyspace_size(alphabet_id,length,&size) || start_cbn>=size ||
        candidate_count>size-start_cbn) return false;
    memset(counter,0,sizeof(*counter));
    counter->alphabet_id=alphabet_id;
    counter->radix=destool_alphabet_radix(alphabet_id);
    counter->digit_bits=destool_digit_bits(counter->radix);
    counter->length=length;
    return counter->digit_bits!=0 &&
      destool_bs_counter_load(counter,start_cbn,candidate_count);
}

static inline bool destool_bs_counter_advance(destool_bitslice_counter *counter)
{
    if (counter==NULL || counter->count==0 ||
        counter->count>counter->remaining) return false;
    const uint64_t step=(uint64_t)counter->count;
    counter->current_cbn+=step;
    counter->remaining-=step;
    if (counter->remaining==0) { counter->count=0; return false; }
    if (step!=BS_LANES) { counter->count=0; return false; }
    switch (counter->radix) {
      case 10: destool_bs_add_constant<10,4>(counter,(unsigned int)step); break;
      case 26: destool_bs_add_constant<26,5>(counter,(unsigned int)step); break;
      case 36: destool_bs_add_constant<36,6>(counter,(unsigned int)step); break;
      case 62: destool_bs_add_constant<62,6>(counter,(unsigned int)step); break;
      case 256: destool_bs_add_constant<256,8>(counter,(unsigned int)step); break;
      default: counter->count=0; return false;
    }
    counter->count=(size_t)(counter->remaining<BS_LANES?
                            counter->remaining:BS_LANES);
    return true;
}

#undef DESTOOL_COUNTER_INLINE

#endif
