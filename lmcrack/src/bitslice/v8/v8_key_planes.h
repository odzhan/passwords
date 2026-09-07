#ifndef LMCRACK_V8_KEY_PLANES_H
#define LMCRACK_V8_KEY_PLANES_H

#include <stddef.h>
#include <stdint.h>

#include "v8_bitslice_counter.h"

#define V8_LM_KEY_PLANES 56U

/*
 * Convert the seven five-bit base-26 digits directly to the 56 LSB-first
 * password planes used by the bitsliced LM/DES key mapping.
 *
 * For digit d in [0,25], uppercase ASCII is 0x41+d.  Bit 6 is therefore
 * always one, bits 7 and 5 are zero, and bits 4:0 are a five-bit increment of
 * d.  Invalid SIMD lanes and character positions beyond the current password
 * length are emitted as zero.
 */
static inline int v8_bs_make_key_planes(const v8_bitslice_counter *counter,
                                        bs_vec planes[V8_LM_KEY_PLANES])
{
    if (counter==NULL || planes==NULL || counter->length<1U ||
        counter->length>V8_MAX_PASSWORD_LENGTH || counter->count>BS_LANES)
      return 0;

    for (unsigned int plane=0;plane<V8_LM_KEY_PLANES;plane++)
      planes[plane]=bs_zero();

    bs_vec valid=bs_valid_lane_mask(counter->count);
    for (unsigned int position=0;position<counter->length;position++) {
      bs_vec carry=valid; /* add one to map digit zero to ASCII 'A' */
      for (unsigned int bit=0;bit<V8_DIGIT_BITS;bit++) {
        bs_vec digit=counter->digit[position][bit];
        planes[position*8U+bit]=bs_and(bs_xor(digit,carry),valid);
        carry=bs_and(digit,carry);
      }
      planes[position*8U+6U]=valid;
    }
    return 1;
}

#endif
