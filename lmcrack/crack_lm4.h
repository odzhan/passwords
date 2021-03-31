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
#if defined(AVX)
#include <immintrin.h>

#define DES_SET_KEY(idx) { \
    __m256i *s = (__m256i*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
    __m256i *p = (__m256i*)&ks1[idx]; \
    __m256i *d = (__m256i*)&ks1[idx-1]; \
    if(idx==7) { \
      for(int i=0;i<4;i++) d[i] = s[i]; \
    } else { \
      for(int i=0;i<4;i++) d[i] = _mm256_or_si256(p[i], s[i]); \
    } \
}
#elif defined(SSE)
#include <emmintrin.h>

#define DES_SET_KEY(idx) { \
    __m128i *s = (__m128i*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
    __m128i *p = (__m128i*)&ks1[idx]; \
    __m128i *d = (__m128i*)&ks1[idx-1]; \
    if(idx==7) { \
      for(int i=0;i<8;i++) d[i] = s[i]; \
    } else { \
      for(int i=0;i<8;i++) d[i] = _mm_or_si128(p[i], s[i]); \
    } \
}
#else
#define DES_SET_KEY(idx) { \
    uint32_t *s = (uint32_t*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
    uint32_t *p = (uint32_t*)&ks1[idx]; \
    uint32_t *d = (uint32_t*)&ks1[idx-1]; \
    if(idx==7) { \
      for(int i=0;i<32;i++) d[i] = s[i]; \
    } else { \
      for(int i=0;i<32;i++) d[i] = p[i] | s[i]; \
    } \
}
#endif

static bool crack_lm4(void *param) {
    uint32_t         h[2], l, r, t, u, *k1, *k2;
    DES_key_schedule ks_tbl[MAX_PWD][256];
    DES_key_schedule ks1[MAX_PWD];
    DES_key_schedule ks2[69*69];
    uint8_t          pwd[MAX_PWD];
    crack_opt_t      *c=(crack_opt_t*)param;
    DES_key_schedule *p;
    DES_cblock       key;
    int              i, j, cbn;
    
    cbn = c->alpha_len;
       
    // create key schedules for alphabet
    DES_init_keys2(c->alphabet, ks_tbl);
    
    p=&ks2[0];
    
    // create key schedules for every two character password
    for(i=0;i<c->alpha_len;i++) {
      memset(pwd, 0, sizeof(pwd));
      pwd[0] = c->alphabet[i];
      for(j=0;j<c->alpha_len;j++) {
        pwd[1] = c->alphabet[j];
        DES_str_to_key(pwd, (uint8_t*)&key);
        DES_set_key(&key, p);
        p++;
      }
    }
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
    k2 = (uint32_t*)&ks2[0];
    
    k2 += ((c->pwd_idx[0] * c->alpha_len) + c->pwd_idx[1]) * 32;
    cbn = c->alpha_len * c->alpha_len;
    
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
              k2 = (uint32_t*)&ks2[0];
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
                    c->pwd_idx[0] = (i / c->alpha_len);
                    c->pwd_idx[1] = (i % c->alpha_len);
                    c->found = true;
                    return true;
                  }
                }
                k2+=32;
              }
              c->complete += cbn;
              c->total_cbn -= cbn;
              if ((int64_t)c->total_cbn<0) return false;
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

