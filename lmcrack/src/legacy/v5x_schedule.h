#ifndef LMCRACK_V5X_SCHEDULE_H
#define LMCRACK_V5X_SCHEDULE_H
#include <stdint.h>
#include <immintrin.h>

/* count is 1..3. Each input schedule has 32 words; output holds 96 words.
 * Four vector chunks per schedule share prefix loads across candidates. */
static inline void lm5x_merge3(const uint32_t *prefix,const uint32_t *pairs,
                              uint32_t merged[96],unsigned count)
{
    for(unsigned word=0;word<32;word+=8) {
      const __m256i common=_mm256_loadu_si256((const __m256i*)(prefix+word));
      for(unsigned stream=0;stream<count;stream++) {
        const __m256i pair=_mm256_loadu_si256((const __m256i*)(pairs+stream*32+word));
        _mm256_storeu_si256((__m256i*)(merged+stream*32+word),_mm256_or_si256(common,pair));
      }
    }
}
#endif
