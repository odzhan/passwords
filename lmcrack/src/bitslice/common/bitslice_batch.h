#ifndef LMCRACK_BITSLICE_BATCH_H
#define LMCRACK_BITSLICE_BATCH_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "bitslice_vec.h"

#define BS_MAX_PWD 7U

typedef struct {
    uint8_t index[BS_LANES][BS_MAX_PWD];
    uint8_t length[BS_LANES];
    size_t count;
} bs_candidate_batch;

typedef struct {
    uint8_t index[BS_MAX_PWD];
    uint8_t length;
    uint16_t alphabet_length;
    uint64_t remaining;
} bs_candidate_generator;

static inline int bs_candidate_generator_init(bs_candidate_generator *g,
    const int index[BS_MAX_PWD], int length, unsigned int alphabet_length,
    uint64_t count)
{
    unsigned int i;
    if (g == NULL || index == NULL || length < 1 || length > (int)BS_MAX_PWD ||
        alphabet_length < 1 || alphabet_length > 128) return 0;

    memset(g, 0, sizeof(*g));
    g->length=(uint8_t)length;
    g->alphabet_length=(uint16_t)alphabet_length;
    g->remaining=count;
    for (i=0; i<(unsigned int)length; i++) {
        if (index[i] < 0 || (unsigned int)index[i] >= alphabet_length) return 0;
        g->index[i]=(uint8_t)index[i];
    }
    return 1;
}

static inline void bs_candidate_advance(bs_candidate_generator *g)
{
    unsigned int i;
    for (i=0; i<g->length; i++) {
        if (++g->index[i] < g->alphabet_length) return;
        g->index[i]=0;
    }
    if (g->length < BS_MAX_PWD) {
        g->length++;
        g->index[g->length-1]=0;
    }
}

static inline size_t bs_candidate_next(bs_candidate_generator *g,
    bs_candidate_batch *batch)
{
    size_t lane, count;
    if (g == NULL || batch == NULL) return 0;
    count=(g->remaining < BS_LANES) ? (size_t)g->remaining : (size_t)BS_LANES;
    batch->count=count;

    for (lane=0; lane<count; lane++) {
        batch->length[lane]=g->length;
        memcpy(batch->index[lane],g->index,BS_MAX_PWD);
        bs_candidate_advance(g);
    }
    g->remaining-=count;
    return count;
}

static inline size_t bs_first_match_lane_reference(bs_vec match,size_t valid_lanes)
{
    uint8_t packed[BS_BYTES];
    size_t lane;
    if (valid_lanes>BS_LANES) valid_lanes=BS_LANES;
    bs_store(packed,match);
    for (lane=0;lane<valid_lanes;lane++)
      if ((packed[lane>>3]>>(lane&7U))&1U) return lane;
    return (size_t)BS_LANES;
}

static inline size_t bs_first_match_lane(bs_vec match,size_t valid_lanes)
{
#if defined(LMCRACK_REFERENCE_LANE_SCAN)
    return bs_first_match_lane_reference(match,valid_lanes);
#else
    if (valid_lanes==0 || !bs_any(match)) return BS_LANES;
    if (valid_lanes>BS_LANES) valid_lanes=BS_LANES;
    uint8_t packed[BS_BYTES];
    bs_store(packed,match);
    for (size_t base=0;base<valid_lanes;base+=64) {
      // Explicit little-endian packing preserves lane order on every backend.
      uint64_t word=0;
      for (unsigned byte=0;byte<8;byte++)
        word|=(uint64_t)packed[base/8+byte]<<(byte*8);
      if (word!=0) {
#if defined(__GNUC__) || defined(__clang__)
        const size_t bit=(size_t)__builtin_ctzll(word);
#else
        size_t bit=0;
        while ((word&1U)==0) { word>>=1; bit++; }
#endif
        const size_t lane=base+bit;
        return lane<valid_lanes?lane:BS_LANES;
      }
    }
    return BS_LANES;
#endif
}

static inline int bs_recover_candidate(const bs_candidate_batch *batch,
    size_t lane,int output[BS_MAX_PWD],int *length)
{
    size_t i;
    if (batch==NULL || output==NULL || length==NULL ||
        lane>=batch->count || lane>=BS_LANES) return 0;
    *length=(int)batch->length[lane];
    for (i=0;i<BS_MAX_PWD;i++)
      output[i]=(i<batch->length[lane])?(int)batch->index[lane][i]:-1;
    return 1;
}

#endif
