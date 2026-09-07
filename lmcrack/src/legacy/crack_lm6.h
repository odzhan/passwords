/** Batch-materialized key-schedule variant of crack_lm4. */

#if defined(LMCRACK_PAIR64)
#define DES_F6(LL,R,S) { \
    u=(R)^sk[S]; t=(R)^sk[(S)+1]; t=ROTATE(t,4); \
    LL^=des_pair64_T13[((u>>2)&0x3fU)|((u>>4)&0xfc0U)]^ \
        des_pair64_T57[((u>>18)&0x3fU)|((u>>20)&0xfc0U)]^ \
        des_pair64_T24[((t>>2)&0x3fU)|((t>>4)&0xfc0U)]^ \
        des_pair64_T68[((t>>18)&0x3fU)|((t>>20)&0xfc0U)]; }
#elif defined(LMCRACK_PAIR256)
#define DES_F6(LL,R,S) { \
    u=(R)^sk[S]; t=(R)^sk[(S)+1]; t=ROTATE(t,4); \
    LL^=des_pair_T13[(u&0xfcfcU)>>2]^des_pair_T57[((u>>16)&0xfcfcU)>>2]^ \
        des_pair_T24[(t&0xfcfcU)>>2]^des_pair_T68[((t>>16)&0xfcfcU)>>2]; }
#else
#define DES_F6(LL,R,S) { \
    u=(R)^sk[S]; t=(R)^sk[(S)+1]; t=ROTATE(t,4); \
    LL^=des_SPtrans[0][(u>>2)&0x3f]^des_SPtrans[2][(u>>10)&0x3f]^ \
        des_SPtrans[4][(u>>18)&0x3f]^des_SPtrans[6][(u>>26)&0x3f]^ \
        des_SPtrans[1][(t>>2)&0x3f]^des_SPtrans[3][(t>>10)&0x3f]^ \
        des_SPtrans[5][(t>>18)&0x3f]^des_SPtrans[7][(t>>26)&0x3f]; }
#endif

static inline void lm6_merge_schedules(DES_key_schedule *dst,
    const DES_key_schedule *prefix, const DES_key_schedule *pairs,
    size_t count)
{
#if defined(LMCRACK_NEON)
    const uint32_t *a=(const uint32_t*)prefix;
    for (size_t n=0; n<count; n++) {
      uint32_t *d=(uint32_t*)&dst[n];
      const uint32_t *b=(const uint32_t*)&pairs[n];
      for (size_t j=0; j<32; j+=4)
        vst1q_u32(d+j, vorrq_u32(vld1q_u32(a+j), vld1q_u32(b+j)));
    }
#else
    const uint32_t *a=(const uint32_t*)prefix;
    for (size_t n=0; n<count; n++) {
      uint32_t *d=(uint32_t*)&dst[n];
      const uint32_t *b=(const uint32_t*)&pairs[n];
      for (size_t j=0; j<32; j++) d[j]=a[j]|b[j];
    }
#endif
}

static bool crack_lm6(void *param) {
    uint32_t h[2], l, r, t, u, *sk;
    DES_key_schedule (*ks_tbl)[256]=NULL;
    std::vector<DES_key_schedule> ks_tbl_local;
    DES_key_schedule ks1[MAX_PWD];
    DES_key_schedule *ks2_tbl=NULL;
    std::vector<DES_key_schedule> ks2_local, merged;
    uint8_t pwd[MAX_PWD];
    crack_opt_t *c=(crack_opt_t*)param;
    DES_key_schedule *p;
    DES_cblock key;
    size_t i, j, alpha_len, pair_count, start_offset, pair_base;
    uint64_t cbn;

    alpha_len=(size_t)c->alpha_len;
    if (c->pwd_idx[1]<0) return crack_lm3(param);
    if (c->ks_tbl_alpha!=NULL) {
      ks_tbl=(DES_key_schedule (*)[256])c->ks_tbl_alpha;
    } else {
      ks_tbl_local.resize(7*256);
      ks_tbl=(DES_key_schedule (*)[256])ks_tbl_local.data();
      DES_init_keys2(c->alphabet,ks_tbl);
    }
    if (alpha_len==0) return false;
    pair_count=alpha_len*alpha_len;
    if (c->ks_pairs!=NULL && c->ks_pairs_len>=pair_count) {
      ks2_tbl=c->ks_pairs;
    } else {
      ks2_local.resize(pair_count); ks2_tbl=ks2_local.data(); p=ks2_tbl;
      for (i=0;i<alpha_len;i++) {
        memset(pwd,0,sizeof(pwd)); pwd[0]=(uint8_t)c->alphabet[i];
        for (j=0;j<alpha_len;j++) {
          pwd[1]=(uint8_t)c->alphabet[j];
          DES_str_to_key(pwd,(uint8_t*)&key); DES_set_key(&key,p++);
        }
      }
    }
    if (c->pwd_idx[0]<0 || c->pwd_idx[1]<0) return false;
    start_offset=(size_t)c->pwd_idx[0]*alpha_len+(size_t)c->pwd_idx[1];
    if (start_offset>=pair_count) return false;
    merged.resize(pair_count);
    memset(ks1,0,sizeof(ks1));
    h[0]=c->hash.w[0]; h[1]=c->hash.w[1]; IP(h[0],h[1]);
    h[0]=ROTATE(h[0],29)&0xffffffffL; h[1]=ROTATE(h[1],29)&0xffffffffL;
    for (int n=MAX_PWD;n>0;n--) if (c->pwd_idx[n-1]>=0) DES_SET_KEY(n);

    pair_base=start_offset; cbn=(uint64_t)(pair_count-start_offset);
    goto compute_lm6;
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
              pair_base=0; cbn=(uint64_t)pair_count;
compute_lm6:
              lm6_merge_schedules(merged.data()+pair_base,&ks1[2],
                                  ks2_tbl+pair_base,(size_t)cbn);
              sk=(uint32_t*)&merged[pair_base];
              for (i=0;i<(size_t)cbn;i++) {
                r=0x2400B807; l=0xAA190747;
                DES_F6(l,r,0); DES_F6(r,l,2); DES_F6(l,r,4); DES_F6(r,l,6);
                DES_F6(l,r,8); DES_F6(r,l,10); DES_F6(l,r,12); DES_F6(r,l,14);
                DES_F6(l,r,16); DES_F6(r,l,18); DES_F6(l,r,20); DES_F6(r,l,22);
                DES_F6(l,r,24); DES_F6(r,l,26); DES_F6(l,r,28);
                if (h[0]==l) {
                  DES_F6(r,l,30);
                  if (h[1]==r) {
                    size_t pair_idx=pair_base+i;
                    c->pwd_idx[0]=(int)(pair_idx/alpha_len);
                    c->pwd_idx[1]=(int)(pair_idx%alpha_len);
                    c->found=true; return true;
                  }
                }
                sk+=32;
              }
              c->complete.fetch_add(cbn,std::memory_order_relaxed);
              {
                uint64_t remaining=c->total_cbn.fetch_sub(cbn,std::memory_order_relaxed);
                if (remaining<=cbn) return false;
              }
              if (c->stopped) return false;
            } while (++c->pwd_idx[2]<c->alpha_len);
            c->pwd_idx[2]=0;
          } while (++c->pwd_idx[3]<c->alpha_len);
          c->pwd_idx[3]=0;
        } while (++c->pwd_idx[4]<c->alpha_len);
        c->pwd_idx[4]=0;
      } while (++c->pwd_idx[5]<c->alpha_len);
      c->pwd_idx[5]=0;
    } while (++c->pwd_idx[6]<c->alpha_len);
    return false;
}

#undef DES_F6
