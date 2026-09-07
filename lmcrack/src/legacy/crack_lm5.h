/** Two-stream variant of crack_lm4. */

#if defined(LMCRACK_PAIR64)
#define DES_F5(LL,R,S,K,U,T) { \
    U=(R)^(k1[S]|K[S]); T=(R)^(k1[(S)+1]|K[(S)+1]); \
    T=ROTATE(T,4); \
    LL^=des_pair64_T13[((U>>2)&0x3fU)|((U>>4)&0xfc0U)]^ \
        des_pair64_T57[((U>>18)&0x3fU)|((U>>20)&0xfc0U)]^ \
        des_pair64_T24[((T>>2)&0x3fU)|((T>>4)&0xfc0U)]^ \
        des_pair64_T68[((T>>18)&0x3fU)|((T>>20)&0xfc0U)]; }
#elif defined(LMCRACK_PAIR256)
#define DES_F5(LL,R,S,K,U,T) { \
    U=(R)^(k1[S]|K[S]); T=(R)^(k1[(S)+1]|K[(S)+1]); \
    T=ROTATE(T,4); \
    LL^=des_pair_T13[(U&0xfcfcU)>>2]^ \
        des_pair_T57[((U>>16)&0xfcfcU)>>2]^ \
        des_pair_T24[(T&0xfcfcU)>>2]^ \
        des_pair_T68[((T>>16)&0xfcfcU)>>2]; }
#else
#define DES_F5(LL,R,S,K,U,T) { \
    U=(R)^(k1[S]|K[S]); T=(R)^(k1[(S)+1]|K[(S)+1]); \
    T=ROTATE(T,4); \
    LL^=des_SPtrans[0][(U>>2)&0x3f]^des_SPtrans[2][(U>>10)&0x3f]^ \
        des_SPtrans[4][(U>>18)&0x3f]^des_SPtrans[6][(U>>26)&0x3f]^ \
        des_SPtrans[1][(T>>2)&0x3f]^des_SPtrans[3][(T>>10)&0x3f]^ \
        des_SPtrans[5][(T>>18)&0x3f]^des_SPtrans[7][(T>>26)&0x3f]; }
#endif

#define DES_ENCRYPT15_5(L,R,K,U,T) { \
    DES_F5(L,R,0,K,U,T); DES_F5(R,L,2,K,U,T); \
    DES_F5(L,R,4,K,U,T); DES_F5(R,L,6,K,U,T); \
    DES_F5(L,R,8,K,U,T); DES_F5(R,L,10,K,U,T); \
    DES_F5(L,R,12,K,U,T); DES_F5(R,L,14,K,U,T); \
    DES_F5(L,R,16,K,U,T); DES_F5(R,L,18,K,U,T); \
    DES_F5(L,R,20,K,U,T); DES_F5(R,L,22,K,U,T); \
    DES_F5(L,R,24,K,U,T); DES_F5(R,L,26,K,U,T); \
    DES_F5(L,R,28,K,U,T); }

static bool crack_lm5(void *param) {
    uint32_t h[2], l0, r0, t0, u0, l1, r1, t1, u1, *k1, *k2;
    DES_key_schedule (*ks_tbl)[256] = NULL;
    std::vector<DES_key_schedule> ks_tbl_local;
    DES_key_schedule ks1[MAX_PWD];
    DES_key_schedule *ks2_tbl = NULL;
    std::vector<DES_key_schedule> ks2_local;
    uint8_t pwd[MAX_PWD];
    crack_opt_t *c=(crack_opt_t*)param;
    DES_key_schedule *p;
    DES_cblock key;
    size_t i, j, alpha_len, pair_count, start_offset, pair_base;
    uint64_t cbn;

    alpha_len = (size_t)c->alpha_len;
    if (c->pwd_idx[1] < 0) return crack_lm3(param);

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
      for (i=0; i<alpha_len; i++) {
        memset(pwd, 0, sizeof(pwd));
        pwd[0] = (uint8_t)c->alphabet[i];
        for (j=0; j<alpha_len; j++) {
          pwd[1] = (uint8_t)c->alphabet[j];
          DES_str_to_key(pwd, (uint8_t*)&key);
          DES_set_key(&key, p++);
        }
      }
    }

    if (c->pwd_idx[0] < 0 || c->pwd_idx[1] < 0) return false;
    start_offset = ((size_t)c->pwd_idx[0] * alpha_len) + (size_t)c->pwd_idx[1];
    if (start_offset >= pair_count) return false;

    memset(ks1, 0, sizeof(ks1));
    h[0] = c->hash.w[0]; h[1] = c->hash.w[1];
    IP(h[0], h[1]);
    h[0] = ROTATE(h[0], 29) & 0xffffffffL;
    h[1] = ROTATE(h[1], 29) & 0xffffffffL;

    for (int n=MAX_PWD; n>0; n--) {
      if (c->pwd_idx[n-1] >= 0) DES_SET_KEY(n);
    }

    k1 = (uint32_t*)&ks1[2];
    k2 = (uint32_t*)ks2_tbl + start_offset * 32;
    pair_base = start_offset;
    cbn = (uint64_t)(pair_count - start_offset);
    goto compute_lm5;

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
compute_lm5:
              for (i=0; i+1<(size_t)cbn; i+=2) {
                uint32_t *ka = k2;
                uint32_t *kb = k2 + 32;
                r0=0x2400B807; l0=0xAA190747;
                r1=0x2400B807; l1=0xAA190747;

                /* Keep two independent dependency chains in flight. */
                DES_F5(l0,r0,0,ka,u0,t0); DES_F5(l1,r1,0,kb,u1,t1);
                DES_F5(r0,l0,2,ka,u0,t0); DES_F5(r1,l1,2,kb,u1,t1);
                DES_F5(l0,r0,4,ka,u0,t0); DES_F5(l1,r1,4,kb,u1,t1);
                DES_F5(r0,l0,6,ka,u0,t0); DES_F5(r1,l1,6,kb,u1,t1);
                DES_F5(l0,r0,8,ka,u0,t0); DES_F5(l1,r1,8,kb,u1,t1);
                DES_F5(r0,l0,10,ka,u0,t0); DES_F5(r1,l1,10,kb,u1,t1);
                DES_F5(l0,r0,12,ka,u0,t0); DES_F5(l1,r1,12,kb,u1,t1);
                DES_F5(r0,l0,14,ka,u0,t0); DES_F5(r1,l1,14,kb,u1,t1);
                DES_F5(l0,r0,16,ka,u0,t0); DES_F5(l1,r1,16,kb,u1,t1);
                DES_F5(r0,l0,18,ka,u0,t0); DES_F5(r1,l1,18,kb,u1,t1);
                DES_F5(l0,r0,20,ka,u0,t0); DES_F5(l1,r1,20,kb,u1,t1);
                DES_F5(r0,l0,22,ka,u0,t0); DES_F5(r1,l1,22,kb,u1,t1);
                DES_F5(l0,r0,24,ka,u0,t0); DES_F5(l1,r1,24,kb,u1,t1);
                DES_F5(r0,l0,26,ka,u0,t0); DES_F5(r1,l1,26,kb,u1,t1);
                DES_F5(l0,r0,28,ka,u0,t0); DES_F5(l1,r1,28,kb,u1,t1);

                if (h[0]==l0) { DES_F5(r0,l0,30,ka,u0,t0); if (h[1]==r0) { j=pair_base+i; goto found_lm5; } }
                if (h[0]==l1) { DES_F5(r1,l1,30,kb,u1,t1); if (h[1]==r1) { j=pair_base+i+1; goto found_lm5; } }
                k2 += 64;
              }
              if (i<(size_t)cbn) {
                r0=0x2400B807; l0=0xAA190747;
                DES_ENCRYPT15_5(l0,r0,k2,u0,t0);
                if (h[0]==l0) { DES_F5(r0,l0,30,k2,u0,t0); if (h[1]==r0) { j=pair_base+i; goto found_lm5; } }
                k2 += 32;
              }
              c->complete.fetch_add(cbn, std::memory_order_relaxed);
              {
                uint64_t remaining=c->total_cbn.fetch_sub(cbn,std::memory_order_relaxed);
                if (remaining<=cbn) return false;
              }
              if (c->stopped) return false;
            } while (++c->pwd_idx[2] < c->alpha_len);
            c->pwd_idx[2]=0;
          } while (++c->pwd_idx[3] < c->alpha_len);
          c->pwd_idx[3]=0;
        } while (++c->pwd_idx[4] < c->alpha_len);
        c->pwd_idx[4]=0;
      } while (++c->pwd_idx[5] < c->alpha_len);
      c->pwd_idx[5]=0;
    } while (++c->pwd_idx[6] < c->alpha_len);
    return false;

found_lm5:
    c->pwd_idx[0]=(int)(j/alpha_len);
    c->pwd_idx[1]=(int)(j%alpha_len);
    c->found=true;
    return true;
}

#undef DES_ENCRYPT15_5
#undef DES_F5
