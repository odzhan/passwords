/**
  Copyright © 2015 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#undef LOAD_DATA_tmp
#undef LOAD_DATA
#undef DES_F
#undef DES_SET_KEY

#define LOAD_DATA_tmp(a,b,c,d,e,f) LOAD_DATA(a,b,c,d,e,f,g)
#define LOAD_DATA(R,S,u,t,E0,E1,tmp) \
        u=R^(k1[S  ] | k2[S  ]); \
        t=R^(k1[S+1] | k2[S+1]);

#define DES_F(LL,R,S) {\
        LOAD_DATA_tmp(R,S,u,t,E0,E1); \
        t=ROTATE(t,4); \
        LL^=des_SPtrans[0][(u>> 2L)&0x3f]^ \
            des_SPtrans[2][(u>>10L)&0x3f]^ \
            des_SPtrans[4][(u>>18L)&0x3f]^ \
            des_SPtrans[6][(u>>26L)&0x3f]^ \
            des_SPtrans[1][(t>> 2L)&0x3f]^ \
            des_SPtrans[3][(t>>10L)&0x3f]^ \
            des_SPtrans[5][(t>>18L)&0x3f]^ \
            des_SPtrans[7][(t>>26L)&0x3f]; }
            
// create DES subkeys using precomputed schedules
// using AVX2 is slightly faster than SSE2, but not by much.
#if defined(AVX512) || defined(__AVX512F__)
#include <immintrin.h>

#define DES_SET_KEY(idx) { \
    __m512i *d = (__m512i*)&ks1[idx-1]; \
    if (c->pwd_idx[idx-1] < 0) { \
      if (idx == 7) { \
        for (int i = 0; i < 2; i++) { \
          _mm512_storeu_si512(&d[i], _mm512_setzero_si512()); \
        } \
      } else { \
        __m512i *p = (__m512i*)&ks1[idx]; \
        for (int i = 0; i < 2; i++) { \
          _mm512_storeu_si512(&d[i], _mm512_loadu_si512(&p[i])); \
        } \
      } \
    } else { \
      __m512i *s = (__m512i*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
      if (idx == 7) { \
        for (int i = 0; i < 2; i++) { \
          _mm512_storeu_si512(&d[i], _mm512_loadu_si512(&s[i])); \
        } \
      } else { \
        __m512i *p = (__m512i*)&ks1[idx]; \
        for (int i = 0; i < 2; i++) { \
          __m512i pv = _mm512_loadu_si512(&p[i]); \
          __m512i sv = _mm512_loadu_si512(&s[i]); \
          _mm512_storeu_si512(&d[i], _mm512_or_si512(pv, sv)); \
        } \
      } \
    } \
}
#elif defined(AVX2) || defined(__AVX2__) || defined(AVX)
#include <immintrin.h>

#define DES_SET_KEY(idx) { \
    __m256i *d = (__m256i*)&ks1[idx-1]; \
    if (c->pwd_idx[idx-1] < 0) { \
      if (idx == 7) { \
        for (int i = 0; i < 4; i++) { \
          _mm256_storeu_si256(&d[i], _mm256_setzero_si256()); \
        } \
      } else { \
        __m256i *p = (__m256i*)&ks1[idx]; \
        for (int i = 0; i < 4; i++) { \
          _mm256_storeu_si256(&d[i], _mm256_loadu_si256(&p[i])); \
        } \
      } \
    } else { \
      __m256i *s = (__m256i*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
      if (idx == 7) { \
        for (int i = 0; i < 4; i++) { \
          _mm256_storeu_si256(&d[i], _mm256_loadu_si256(&s[i])); \
        } \
      } else { \
        __m256i *p = (__m256i*)&ks1[idx]; \
        for (int i = 0; i < 4; i++) { \
          __m256i pv = _mm256_loadu_si256(&p[i]); \
          __m256i sv = _mm256_loadu_si256(&s[i]); \
          _mm256_storeu_si256(&d[i], _mm256_or_si256(pv, sv)); \
        } \
      } \
    } \
}
#elif defined(SSE2) || defined(__SSE2__) || defined(SSE)
#include <emmintrin.h>

#define DES_SET_KEY(idx) { \
    __m128i *d = (__m128i*)&ks1[idx-1]; \
    if (c->pwd_idx[idx-1] < 0) { \
      if (idx == 7) { \
        for (int i = 0; i < 8; i++) { \
          _mm_storeu_si128(&d[i], _mm_setzero_si128()); \
        } \
      } else { \
        __m128i *p = (__m128i*)&ks1[idx]; \
        for (int i = 0; i < 8; i++) { \
          _mm_storeu_si128(&d[i], _mm_loadu_si128(&p[i])); \
        } \
      } \
    } else { \
      __m128i *s = (__m128i*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
      if (idx == 7) { \
        for (int i = 0; i < 8; i++) { \
          _mm_storeu_si128(&d[i], _mm_loadu_si128(&s[i])); \
        } \
      } else { \
        __m128i *p = (__m128i*)&ks1[idx]; \
        for (int i = 0; i < 8; i++) { \
          __m128i pv = _mm_loadu_si128(&p[i]); \
          __m128i sv = _mm_loadu_si128(&s[i]); \
          _mm_storeu_si128(&d[i], _mm_or_si128(pv, sv)); \
        } \
      } \
    } \
}
#else
#define DES_SET_KEY(idx) { \
    uint32_t *d = (uint32_t*)&ks1[idx-1]; \
    if (c->pwd_idx[idx-1] < 0) { \
      if (idx == 7) { \
        for (int i = 0; i < 32; i++) d[i] = 0; \
      } else { \
        uint32_t *p = (uint32_t*)&ks1[idx]; \
        for (int i = 0; i < 32; i++) d[i] = p[i]; \
      } \
    } else { \
      uint32_t *s = (uint32_t*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
      if (idx == 7) { \
        for (int i = 0; i < 32; i++) d[i] = s[i]; \
      } else { \
        uint32_t *p = (uint32_t*)&ks1[idx]; \
        for (int i = 0; i < 32; i++) d[i] = p[i] | s[i]; \
      } \
    } \
}
#endif

static bool crack_lm4(void *param) {
    uint32_t         h[2], l, r, t, u, *k1, *k2;
    DES_key_schedule (*ks_tbl)[256] = NULL;
    std::vector<DES_key_schedule> ks_tbl_local;
    DES_key_schedule ks1[MAX_PWD];
    DES_key_schedule *ks2_tbl = NULL;
    std::vector<DES_key_schedule> ks2_local;
    uint8_t          pwd[MAX_PWD];
    crack_opt_t      *c=(crack_opt_t*)param;
    DES_key_schedule *p;
    DES_cblock       key;
    size_t           i, j;
    size_t           alpha_len;
    size_t           pair_count, start_offset, pair_base;
    uint64_t         cbn;
    
    alpha_len = (size_t)c->alpha_len;

    if (c->pwd_idx[1] < 0) {
      return crack_lm3(param);
    }

    if (c->ks_tbl_alpha != NULL) {
      ks_tbl = (DES_key_schedule (*)[256])c->ks_tbl_alpha;
    } else {
      ks_tbl_local.resize(7 * 256);
      ks_tbl = (DES_key_schedule (*)[256])ks_tbl_local.data();
      DES_init_keys2(c->alphabet, ks_tbl);
    }
    
    if (alpha_len == 0) return false;

    pair_count = alpha_len * alpha_len;
    if (c->ks_pairs != NULL && c->ks_pairs_len >= pair_count) {
      ks2_tbl = c->ks_pairs;
    } else {
      ks2_local.resize(pair_count);
      ks2_tbl = ks2_local.data();
      p = ks2_tbl;
      // create key schedules for every two character password
      for (i = 0; i < alpha_len; i++) {
        memset(pwd, 0, sizeof(pwd));
        pwd[0] = (uint8_t)c->alphabet[i];
        for (j = 0; j < alpha_len; j++) {
          pwd[1] = (uint8_t)c->alphabet[j];
          DES_str_to_key(pwd, (uint8_t*)&key);
          DES_set_key(&key, p);
          p++;
        }
      }
    }

    if (c->pwd_idx[0] < 0 || c->pwd_idx[1] < 0) return false;
    start_offset = ((size_t)c->pwd_idx[0] * alpha_len) + (size_t)c->pwd_idx[1];
    if (start_offset >= pair_count) return false;

    memset(ks1, 0, sizeof(ks1));

    // perform initial permutation on ciphertext/hash
    h[0] = c->hash.w[0];
    h[1] = c->hash.w[1];
    IP(h[0], h[1]);
    h[0] = ROTATE(h[0], 29) & 0xffffffffL;
    h[1] = ROTATE(h[1], 29) & 0xffffffffL;

    // set the initial key schedules based on pwd_idx
    for (int i=MAX_PWD; i>0; i--) {
      // if not set, skip it
      if (c->pwd_idx[i-1]<0) continue;
      // set key schedule for this index
      DES_SET_KEY(i);
    }

    k1 = (uint32_t*)&ks1[2];
    k2 = (uint32_t*)ks2_tbl;
    k2 += start_offset * 32;
    pair_base = start_offset;
    cbn = (uint64_t)(pair_count - start_offset);
    
    goto compute_lm;

    do {
      DES_SET_KEY(7);
      do {
        DES_SET_KEY(6);
        do {
          DES_SET_KEY(5);
          do {
            DES_SET_KEY(4);
            do {
              DES_SET_KEY(3);
              k2 = (uint32_t*)ks2_tbl;
              pair_base = 0;
              cbn = (uint64_t)pair_count;
compute_lm:
              for(i=0;i<cbn;i++) {
                // permuted plaintext
                r = 0x2400B807; l = 0xAA190747;

                // encrypt
                DES_F(l, r,  0); 
                DES_F(r, l,  2); DES_F(l, r,  4); 
                DES_F(r, l,  6); DES_F(l, r,  8); 
                DES_F(r, l, 10); DES_F(l, r, 12); 
                DES_F(r, l, 14); DES_F(l, r, 16); 
                DES_F(r, l, 18); DES_F(l, r, 20); 
                DES_F(r, l, 22); DES_F(l, r, 24); 
                DES_F(r, l, 26); DES_F(l, r, 28); 
                
                if (h[0] == l) {
                  DES_F(r, l, 30);
                  if (h[1] == r) {
                    // yay, we found it.
                    size_t pair_idx = pair_base + i;
                    c->pwd_idx[0] = (int)(pair_idx / alpha_len);
                    c->pwd_idx[1] = (int)(pair_idx % alpha_len);
                    c->found = true;
                    return true;
                  }
                }
                k2+=32;
              }
              c->complete.fetch_add(cbn, std::memory_order_relaxed);
              {
                uint64_t remaining = c->total_cbn.fetch_sub(
                  cbn, std::memory_order_relaxed);
                if (remaining <= cbn) return false;
              }
              if (c->stopped) return false;
                
            } while (++c->pwd_idx[2] < c->alpha_len);
            c->pwd_idx[2] = 0;
          } while (++c->pwd_idx[3] < c->alpha_len);
          c->pwd_idx[3] = 0;
        } while (++c->pwd_idx[4] < c->alpha_len);
        c->pwd_idx[4] = 0;
      } while (++c->pwd_idx[5] < c->alpha_len);
      c->pwd_idx[5] = 0;
    } while (++c->pwd_idx[6] < c->alpha_len);
    return false;
}

