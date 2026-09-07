#include <atomic>
#include <cstdint>
#include <cstring>

typedef union { uint8_t b[32]; uint32_t w[8]; uint64_t q[4]; } hash_t;
typedef struct {
    uint64_t start_cbn,end_cbn;
    std::atomic<uint64_t> complete,total_cbn;
    std::atomic<bool> found,stopped;
    int pwd_idx[256],pwd_len,alpha_len;
    char alphabet[128];
    hash_t hash;
} crack_opt_t;

#include "crack_lm9.h"

static void initialize(crack_opt_t *o,const uint8_t hash[8])
{
    o->start_cbn=o->end_cbn=0; o->complete.store(0); o->total_cbn.store(0);
    o->found.store(false); o->stopped.store(false); o->pwd_len=0;
    o->alpha_len=V9_ALPHABET_LENGTH;
    std::memset(o->alphabet,0,sizeof(o->alphabet));
    std::memcpy(o->alphabet,V9_ALPHABET,V9_ALPHABET_LENGTH);
    std::memset(&o->hash,0,sizeof(o->hash)); std::memcpy(o->hash.b,hash,8);
    for (size_t i=0;i<256;i++) o->pwd_idx[i]=-1;
}

static int run_match(uint64_t start,uint64_t count,const uint8_t hash[8],
                     const uint8_t *digits,unsigned int length)
{
    crack_opt_t o; initialize(&o,hash); o.start_cbn=start; o.end_cbn=start+count;
    o.total_cbn.store(count);
    if (!crack_lm9(&o) || !o.found.load() || o.pwd_len!=(int)length) return 1;
    for (unsigned int i=0;i<length;i++) if (o.pwd_idx[i]!=digits[i]) return 2;
    if (o.complete.load()==0 || o.complete.load()>count ||
        o.total_cbn.load()+o.complete.load()!=count) return 3;
    return 0;
}

int main(void)
{
    static const uint8_t h0[8]={0x25,0xad,0x3b,0x83,0xfa,0x66,0x27,0xc7};
    static const uint8_t h9[8]={0x09,0x75,0x2a,0x32,0x93,0x83,0x1d,0x17};
    static const uint8_t hm[8]={0x45,0xbc,0xc0,0x48,0xab,0x4c,0xc4,0x2e};
    static const uint8_t hz7[8]={0xa5,0xe6,0x06,0x6d,0xe6,0x1c,0x3e,0x35};
    static const uint8_t d0[1]={0},d9[1]={9},dm[4]={0,10,9,35};
    uint8_t dz7[7]={35,35,35,35,35,35,35}; uint64_t mixed,z7;
    crack_opt_t o;
    bs_sbox_init(); bs_init_lm_plaintext_state();
    if (run_match(0,1,h0,d0,1) || run_match(0,10,h9,d9,1)) return 1;
    if (!v9_digits_to_cbn(dm,4,&mixed) ||
        run_match(mixed-(BS_LANES+7U),BS_LANES+8U,hm,dm,4)) return 2;
    if (run_match(mixed,1,hm,dm,4) ||
        run_match(mixed-BS_LANES/2U,BS_LANES/2U+1U,hm,dm,4) ||
        run_match(mixed-(BS_LANES-1U),BS_LANES,hm,dm,4)) return 6;
    if (!v9_digits_to_cbn(dz7,7,&z7) ||
        run_match(z7-(BS_LANES+3U),BS_LANES+4U,hz7,dz7,7)) return 3;

    initialize(&o,hz7); o.start_cbn=0; o.end_cbn=BS_LANES+17U;
    o.total_cbn.store(o.end_cbn);
    if (crack_lm9(&o) || o.found.load() || o.complete.load()!=o.end_cbn ||
        o.total_cbn.load()!=0) return 4;
    initialize(&o,h0); o.alphabet[0]='1'; o.start_cbn=0; o.end_cbn=1;
    o.total_cbn.store(1);
    if (crack_lm9(&o) || o.complete.load()!=0) return 5;
    return 0;
}
