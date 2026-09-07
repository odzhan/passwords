#ifndef LMCRACK_BITSLICE_TRANSPOSE_H
#define LMCRACK_BITSLICE_TRANSPOSE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bitslice_batch.h"

#define BS_KEY_PLANES 56U

/* Plane byte*8+bit contains that LSB-first bit from every candidate lane. */
static inline int bs_transpose_passwords(const bs_candidate_batch *batch,
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

#endif
