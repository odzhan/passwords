#ifndef LMCRACK_V11_KEY_PLANES_H
#define LMCRACK_V11_KEY_PLANES_H

#include "v11_bitslice_counter.h"

#define V11_LM_KEY_PLANES 56U

static inline bs_vec v11_bs_ge_constant(const bs_vec digit[V11_DIGIT_BITS],
                                         unsigned int constant,bs_vec valid)
{
    bs_vec equal=valid,greater=bs_zero();
    for (unsigned int offset=0;offset<V11_DIGIT_BITS;offset++) {
      const unsigned int bit=V11_DIGIT_BITS-1U-offset;
      if ((constant>>bit)&1U) equal=bs_and(equal,digit[bit]);
      else {
        greater=bs_or(greater,bs_and(equal,digit[bit]));
        equal=bs_and(equal,bs_not(digit[bit]));
      }
    }
    return bs_or(greater,equal);
}

static inline int v11_bs_make_key_planes(const v11_bitslice_counter *counter,
                                          bs_vec planes[V11_LM_KEY_PLANES])
{
    if (counter==NULL || planes==NULL || counter->length<1U ||
        counter->length>V11_MAX_PASSWORD_LENGTH || counter->count>BS_LANES)
      return 0;
    for (unsigned int plane=0;plane<V11_LM_KEY_PLANES;plane++)
      planes[plane]=bs_zero();

    const bs_vec valid=bs_valid_lane_mask(counter->count);
    for (unsigned int position=0;position<counter->length;position++) {
      const bs_vec *digit=counter->digit[position];
      const bs_vec ge10=v11_bs_ge_constant(digit,10U,valid);
      const bs_vec ge36=v11_bs_ge_constant(digit,36U,valid);
      const bs_vec ge52=v11_bs_ge_constant(digit,52U,valid);
      const bs_vec ge59=v11_bs_ge_constant(digit,59U,valid);
      const bs_vec ge65=v11_bs_ge_constant(digit,65U,valid);
      bs_vec category[6];
      category[0]=bs_and(valid,bs_not(ge10));
      category[1]=bs_and(ge10,bs_not(ge36));
      category[2]=bs_and(ge36,bs_not(ge52));
      category[3]=bs_and(ge52,bs_not(ge59));
      category[4]=bs_and(ge59,bs_not(ge65));
      category[5]=ge65;
      /* digit + offset produces 0-9, A-Z, space/!../, :..@, [..`, {..~. */
      static const unsigned int offsets[6]={0x30U,0x37U,0xfcU,
                                             0x06U,0x20U,0x3aU};
      bs_vec carry=bs_zero();
      for (unsigned int bit=0;bit<8;bit++) {
        bs_vec addend=bs_zero();
        for (unsigned int i=0;i<6;i++)
          if ((offsets[i]>>bit)&1U) addend=bs_or(addend,category[i]);
        const bs_vec value=bit<V11_DIGIT_BITS?digit[bit]:bs_zero();
        bs_vec sum;
        carry=v11_bs_full_adder(value,addend,carry,&sum);
        planes[position*8U+bit]=bs_and(sum,valid);
      }
    }
    return 1;
}

#endif
