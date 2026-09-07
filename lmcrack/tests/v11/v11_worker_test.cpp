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

#include "crack_lm11.h"
#include "des.h"

static void make_hash(const uint8_t *digits,unsigned int length,uint8_t hash[8])
{
    unsigned char material[7]={0};
    DES_cblock key,input={'K','G','S','!','@','#','$','%'},output;
    DES_key_schedule schedule;
    for (unsigned int i=0;i<length;i++)
      material[i]=(unsigned char)V11_ALPHABET[digits[i]];
    DES_str_to_key(material,key);
    DES_set_key(&key,&schedule);
    DES_ecb_encrypt(&input,&output,&schedule,1);
    std::memcpy(hash,output,8);
}

static void initialize(crack_opt_t *o,const uint8_t hash[8])
{
    o->start_cbn=o->end_cbn=0; o->complete.store(0); o->total_cbn.store(0);
    o->found.store(false); o->stopped.store(false); o->pwd_len=0;
    o->alpha_len=V11_ALPHABET_LENGTH;
    std::memset(o->alphabet,0,sizeof(o->alphabet));
    std::memcpy(o->alphabet,V11_ALPHABET,V11_ALPHABET_LENGTH);
    std::memset(&o->hash,0,sizeof(o->hash)); std::memcpy(o->hash.b,hash,8);
    for (size_t i=0;i<256;i++) o->pwd_idx[i]=-1;
}

static int run_match(const uint8_t *digits,unsigned int length)
{
    uint64_t target; uint8_t hash[8]; crack_opt_t o;
    if (!v11_digits_to_cbn(digits,length,&target)) return 1;
    make_hash(digits,length,hash); initialize(&o,hash);
    const uint64_t before=target<BS_LANES+7U?target:BS_LANES+7U;
    o.start_cbn=target-before; o.end_cbn=target+1U;
    o.total_cbn.store(o.end_cbn-o.start_cbn);
    if (!crack_lm11(&o) || !o.found.load() || o.pwd_len!=(int)length) return 2;
    for (unsigned int i=0;i<length;i++)
      if (o.pwd_idx[i]!=(int)digits[i]) return 3;
    return 0;
}

int main(void)
{
    const uint8_t zero[1]={0},space[1]={36},bang[1]={37},tilde[1]={68};
    const uint8_t mixed[3]={37,10,68};
    bs_sbox_init(); bs_init_lm_plaintext_state();
    if (run_match(zero,1) || run_match(space,1) || run_match(bang,1) ||
        run_match(tilde,1) || run_match(mixed,3)) return 1;
    return 0;
}
