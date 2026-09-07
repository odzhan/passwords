#ifndef LMCRACK_V9_KEY_PLANES_H
#define LMCRACK_V9_KEY_PLANES_H

#include "v9_bitslice_counter.h"

#define V9_LM_KEY_PLANES 56U

static inline int v9_bs_make_key_planes(const v9_bitslice_counter *counter,
                                        bs_vec planes[V9_LM_KEY_PLANES])
{
    if (counter==NULL || planes==NULL || counter->length<1U ||
        counter->length>V9_MAX_PASSWORD_LENGTH || counter->count>BS_LANES)
      return 0;
    for (unsigned int plane=0;plane<V9_LM_KEY_PLANES;plane++)
      planes[plane]=bs_zero();

    bs_vec valid=bs_valid_lane_mask(counter->count);
    for (unsigned int position=0;position<counter->length;position++) {
      const bs_vec *digit=counter->digit[position];
      /* d >= 10 for the valid domain 0..35. */
      bs_vec letter=bs_and(valid,bs_or(bs_or(digit[5],digit[4]),
        bs_and(digit[3],bs_or(digit[2],digit[1]))));
      bs_vec carry=bs_zero();
      for (unsigned int bit=0;bit<8;bit++) {
        bs_vec value=bit<V9_DIGIT_BITS?digit[bit]:bs_zero();
        /* Digits add 0x30; letters add 0x37. */
        bs_vec addend=(bit<=2U)?letter:
                      ((bit==4U || bit==5U)?valid:bs_zero());
        bs_vec sum;
        carry=v9_bs_full_adder(value,addend,carry,&sum);
        planes[position*8U+bit]=bs_and(sum,valid);
      }
    }
    return 1;
}

#endif
