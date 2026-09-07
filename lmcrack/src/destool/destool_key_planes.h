#ifndef DESTOOL_KEY_PLANES_H
#define DESTOOL_KEY_PLANES_H

#include "bitslice_transpose.h"
#include "destool_bitslice_counter.h"

static inline bs_vec destool_bs_ge_constant(
    const bs_vec digit[DESTOOL_MAX_DIGIT_BITS],unsigned int bits,
    unsigned int constant,bs_vec valid)
{
    bs_vec equal=valid,greater=bs_zero();
    for (unsigned int offset=0;offset<bits;offset++) {
      const unsigned int bit=bits-1U-offset;
      if ((constant>>bit)&1U) equal=bs_and(equal,digit[bit]);
      else {
        greater=bs_or(greater,bs_and(equal,digit[bit]));
        equal=bs_and(equal,bs_not(digit[bit]));
      }
    }
    return bs_or(greater,equal);
}

static inline bool destool_bs_make_key_planes(
    const destool_bitslice_counter *counter,bs_vec planes[BS_KEY_PLANES])
{
    if (counter==NULL || planes==NULL || counter->alphabet_id<1U ||
        counter->alphabet_id>7U || counter->length<1U ||
        counter->length>DESTOOL_MAX_KEY_BYTES || counter->count>BS_LANES ||
        counter->radix!=destool_alphabet_radix(counter->alphabet_id) ||
        counter->digit_bits!=destool_digit_bits(counter->radix)) return false;

    for (unsigned int plane=0;plane<BS_KEY_PLANES;plane++)
      planes[plane]=bs_zero();
    const bs_vec valid=bs_valid_lane_mask(counter->count);

    for (unsigned int position=0;position<counter->length;position++) {
      const bs_vec *digit=counter->digit[position];
      if (counter->alphabet_id==1U) {
        for (unsigned int bit=0;bit<8;bit++)
          planes[position*8U+bit]=bs_and(digit[bit],valid);
        continue;
      }

      /* Keep the v9-compatible radix-36 path as a compact fixed circuit.
         This avoids the generic category arrays and loop below in the most
         directly comparable hot path. */
      if (counter->alphabet_id==5U) {
        const bs_vec letter=bs_and(valid,bs_or(bs_or(digit[5],digit[4]),
          bs_and(digit[3],bs_or(digit[2],digit[1]))));
        bs_vec carry=bs_zero();
        for (unsigned int bit=0;bit<8;bit++) {
          const bs_vec value=bit<6U?digit[bit]:bs_zero();
          const bs_vec addend=(bit<=2U)?letter:
            ((bit==4U || bit==5U)?valid:bs_zero());
          bs_vec sum;
          carry=destool_bs_full_adder(value,addend,carry,&sum);
          planes[position*8U+bit]=bs_and(sum,valid);
        }
        continue;
      }

      bs_vec category[3]={valid,bs_zero(),bs_zero()};
      unsigned int offset[3]={0,0,0};
      unsigned int categories=1;
      switch (counter->alphabet_id) {
        case 2: offset[0]=0x30U; break;
        case 3: offset[0]=0x41U; break;
        case 4: offset[0]=0x61U; break;
        case 5: case 6: {
          const bs_vec letters=destool_bs_ge_constant(
            digit,counter->digit_bits,10U,valid);
          category[0]=bs_and(valid,bs_not(letters));
          category[1]=letters;
          offset[0]=0x30U;
          offset[1]=counter->alphabet_id==5U?0x37U:0x57U;
          categories=2;
          break;
        }
        case 7: {
          const bs_vec at_least_10=destool_bs_ge_constant(
            digit,counter->digit_bits,10U,valid);
          const bs_vec at_least_36=destool_bs_ge_constant(
            digit,counter->digit_bits,36U,valid);
          category[0]=bs_and(valid,bs_not(at_least_10));
          category[1]=bs_and(at_least_10,bs_not(at_least_36));
          category[2]=at_least_36;
          offset[0]=0x30U;
          offset[1]=0x57U;
          offset[2]=0x1dU;
          categories=3;
          break;
        }
        default: return false;
      }

      bs_vec carry=bs_zero();
      for (unsigned int bit=0;bit<8;bit++) {
        bs_vec addend=bs_zero();
        for (unsigned int category_index=0;category_index<categories;
             category_index++)
          if ((offset[category_index]>>bit)&1U)
            addend=bs_or(addend,category[category_index]);
        const bs_vec value=bit<counter->digit_bits?digit[bit]:bs_zero();
        bs_vec sum;
        carry=destool_bs_full_adder(value,addend,carry,&sum);
        planes[position*8U+bit]=bs_and(sum,valid);
      }
    }
    return true;
}

#endif
