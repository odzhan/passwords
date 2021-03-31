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
         

#define DES_F(x,y,z) D_ENCRYPT(x,y,z)
         
// create DES subkeys using precomputed schedules
// using AVX2 is slightly faster than SSE2, but not by much.
#if defined(AVX)
#include <immintrin.h>

#define DES_SET_KEY(idx) { \
    __m256i *s = (__m256i*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
    __m256i *p = (__m256i*)&ks[idx]; \
    __m256i *d = (__m256i*)&ks[idx-1]; \
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
    __m128i *p = (__m128i*)&ks[idx]; \
    __m128i *d = (__m128i*)&ks[idx-1]; \
    if(idx==7) { \
      for(int i=0;i<8;i++) d[i] = s[i]; \
    } else { \
      for(int i=0;i<8;i++) d[i] = _mm_or_si128(p[i], s[i]); \
    } \
}
#else
#define DES_SET_KEY(idx) { \
    uint32_t *s = (uint32_t*)&ks_tbl[idx-1][c->pwd_idx[idx-1]]; \
    uint32_t *p = (uint32_t*)&ks[idx]; \
    uint32_t *d = (uint32_t*)&ks[idx-1]; \
    if(idx==7) { \
      for(int i=0;i<32;i++) d[i] = s[i]; \
    } else { \
      for(int i=0;i<32;i++) d[i] = p[i] | s[i]; \
    } \
}
#endif

static bool crack_lm3(void *param) {
    uint32_t         h[2], l, r, t, u, *s;
    DES_key_schedule ks_tbl[7][256];
    DES_key_schedule ks[7];
    crack_opt_t      *c=(crack_opt_t*)param;
    
    // precompute key schedules for alphabet
    DES_init_keys2(c->alphabet, ks_tbl);
        
    // perform initial permutation on ciphertext/hash
    h[0] = c->hash.w[0];
    h[1] = c->hash.w[1];
    IP(h[0], h[1]);
    h[0] = ROTATE(h[0], 29) & 0xffffffffL;
    h[1] = ROTATE(h[1], 29) & 0xffffffffL;

    // set the initial key schedules based on pwd_idx
    for (int i=7; i>0; i--) {
      // if not set, skip it
      if (c->pwd_idx[i-1]<0) continue;
      // set key schedule for this index
      DES_SET_KEY(i);
    }

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
              do {
                DES_SET_KEY(2);
                do {
                  DES_SET_KEY(1);
compute_lm:
                  // permuted plaintext
                  r = 0x2400B807; l = 0xAA190747;

                  s = (uint32_t*)&ks[0];

                  // encrypt
                  DES_F(l, r,  0); DES_F(r, l,  2);
                  DES_F(l, r,  4); DES_F(r, l,  6);     
                  DES_F(l, r,  8); DES_F(r, l, 10);    
                  DES_F(l, r, 12); DES_F(r, l, 14);   
                  DES_F(l, r, 16); DES_F(r, l, 18);    
                  DES_F(l, r, 20); DES_F(r, l, 22);    
                  DES_F(l, r, 24); DES_F(r, l, 26);    
                  DES_F(l, r, 28);   

                  c->complete++;

                  // do we have one half of the LM hash?
                  if (h[0] == l) {
                    // apply the last round
                    DES_F(r, l, 30);
                    // do we have the full hash?
                    if (h[1] == r) {
                      // ok, we found the key
                      c->found = true;
                      return true;
                    }
                  }

                  if (--c->total_cbn == 0) return false;
                  if (c->stopped) return false;

                } while (++c->pwd_idx[0] < c->alpha_len);
                c->pwd_idx[0] = 0;
              } while (++c->pwd_idx[1] < c->alpha_len);
              c->pwd_idx[1] = 0;
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

