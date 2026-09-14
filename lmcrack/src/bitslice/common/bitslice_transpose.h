#ifndef LMCRACK_BITSLICE_TRANSPOSE_H
#define LMCRACK_BITSLICE_TRANSPOSE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bitslice_batch.h"

#define BS_KEY_PLANES 56U

/* Plane byte*8+bit contains that LSB-first bit from every candidate lane. */
static inline int bs_transpose_passwords_reference(const bs_candidate_batch *batch,
    const char *alphabet, size_t alphabet_length, bs_vec planes[BS_KEY_PLANES])
{
    uint8_t packed[BS_BYTES];
    size_t plane, lane;
    if (batch==NULL || alphabet==NULL || planes==NULL ||
        alphabet_length==0 || alphabet_length>128 || batch->count>BS_LANES)
      return 0;

    for (plane=0; plane<BS_KEY_PLANES; plane++) {
      size_t byte_index=plane>>3;
      unsigned int bit=(unsigned int)(plane&7U);
      memset(packed,0,sizeof(packed));
      for (lane=0; lane<batch->count; lane++) {
        uint8_t value=0;
        if (byte_index<batch->length[lane]) {
          unsigned int index=batch->index[lane][byte_index];
          if (index>=alphabet_length) return 0;
          value=(uint8_t)alphabet[index];
        }
        if ((value>>bit)&1U) packed[lane>>3]|=(uint8_t)(1U<<(lane&7U));
      }
      planes[plane]=bs_load(packed);
    }
    return 1;
}

/* Transpose eight bytes into eight LSB-first bit columns using three swaps.
 * Explicit shifts avoid host-endian and alignment dependencies. */
static inline int bs_transpose_passwords(const bs_candidate_batch *batch,
    const char *alphabet, size_t alphabet_length, bs_vec planes[BS_KEY_PLANES])
{
#if defined(LMCRACK_REFERENCE_TRANSPOSE)
    return bs_transpose_passwords_reference(batch,alphabet,alphabet_length,planes);
#else
    if (batch==NULL || alphabet==NULL || planes==NULL ||
        alphabet_length==0 || alphabet_length>128 || batch->count>BS_LANES)
      return 0;
    for (size_t position=0;position<BS_MAX_PWD;position++) {
      uint8_t packed[8][BS_BYTES]={};
      for (size_t base=0;base<batch->count;base+=8) {
        uint64_t value=0;
        for (size_t row=0;row<8 && base+row<batch->count;row++) {
          const size_t lane=base+row;
          if (position<batch->length[lane]) {
            const unsigned index=batch->index[lane][position];
            if (index>=alphabet_length) return 0;
            value|=(uint64_t)(uint8_t)alphabet[index]<<(row*8);
          }
        }
        uint64_t swap=(value^(value>>7))&UINT64_C(0x00aa00aa00aa00aa);
        value^=swap^(swap<<7);
        swap=(value^(value>>14))&UINT64_C(0x0000cccc0000cccc);
        value^=swap^(swap<<14);
        swap=(value^(value>>28))&UINT64_C(0x00000000f0f0f0f0);
        value^=swap^(swap<<28);
        for (unsigned bit=0;bit<8;bit++)
          packed[bit][base/8]=(uint8_t)(value>>(bit*8));
      }
      for (unsigned bit=0;bit<8;bit++) planes[position*8+bit]=bs_load(packed[bit]);
    }
    return 1;
#endif
}

#endif
