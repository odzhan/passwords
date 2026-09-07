#include <atomic>
#include <cstdint>
#include <cstring>

typedef union {
    uint8_t b[32];
    uint32_t w[8];
    uint64_t q[4];
} hash_t;

typedef struct {
    uint64_t start_cbn,end_cbn;
    std::atomic<uint64_t> complete,total_cbn;
    std::atomic<bool> found,stopped;
    int pwd_idx[256],pwd_len;
    int alpha_len;
    char alphabet[128];
    hash_t hash;
} crack_opt_t;

#include "crack_lm8.h"

static void set_hash(crack_opt_t *options,const uint8_t hash[8])
{
    options->start_cbn=options->end_cbn=0;
    options->complete.store(0);
    options->total_cbn.store(0);
    options->found.store(false);
    options->stopped.store(false);
    options->pwd_len=0;
    std::memset(&options->hash,0,sizeof(options->hash));
    std::memcpy(options->hash.b,hash,8);
    options->alpha_len=V8_ALPHABET_LENGTH;
    std::memset(options->alphabet,0,sizeof(options->alphabet));
    std::memcpy(options->alphabet,V8_ALPHABET,V8_ALPHABET_LENGTH);
    for (size_t i=0;i<256;i++) options->pwd_idx[i]=-1;
}

static int check_password(const crack_opt_t *options,const uint8_t *digits,
                          unsigned int length)
{
    if (!options->found.load() || options->pwd_len!=(int)length) return 0;
    for (unsigned int i=0;i<length;i++)
      if (options->pwd_idx[i]!=(int)digits[i]) return 0;
    for (unsigned int i=length;i<7;i++)
      if (options->pwd_idx[i]!=-1) return 0;
    return 1;
}

static int run_match(uint64_t start,uint64_t count,const uint8_t hash[8],
                     const uint8_t *expected,unsigned int length)
{
    crack_opt_t options;
    set_hash(&options,hash);
    options.start_cbn=start;
    options.end_cbn=start+count;
    options.total_cbn.store(count);
    if (!crack_lm8(&options)) return 1;
    if (!check_password(&options,expected,length)) return 2;
    if (options.complete.load()==0 || options.complete.load()>count) return 3;
    if (options.total_cbn.load()+options.complete.load()!=count) return 4;
    return 0;
}

int main(void)
{
    static const uint8_t hash_a[8]={0x75,0x84,0x24,0x8b,0x8d,0x2c,0x9f,0x9e};
    static const uint8_t hash_z[8]={0x1d,0x91,0xa0,0x81,0xd4,0xb3,0x78,0x61};
    static const uint8_t hash_zzzzzz[8]={0x1f,0xb3,0x63,0xfe,0xb8,0x34,0xc1,0x2d};
    static const uint8_t a[1]={0},z[1]={25},zzzzzz[6]={25,25,25,25,25,25};
    crack_opt_t options;

    bs_sbox_init();
    bs_init_lm_plaintext_state();

    if (run_match(0,1,hash_a,a,1)) return 1;
    if (run_match(0,26,hash_z,z,1)) return 2;

    uint64_t target_cbn;
    uint8_t padded[7]={25,25,25,25,25,25,0};
    if (!v8_digits_to_cbn(padded,6,&target_cbn)) return 3;
    {
      uint64_t before=BS_LANES+7U;
      if (run_match(target_cbn-before,before+1U,hash_zzzzzz,zzzzzz,6)) return 4;
    }

    /* A range without the target must exhaust exactly, including its tail. */
    set_hash(&options,hash_zzzzzz);
    options.start_cbn=0;
    options.end_cbn=BS_LANES+17U;
    options.total_cbn.store(options.end_cbn);
    if (crack_lm8(&options) || options.found.load()) return 5;
    if (options.complete.load()!=options.end_cbn || options.total_cbn.load()!=0)
      return 6;

    /* Invalid worker contracts fail before processing a candidate. */
    set_hash(&options,hash_a);
    options.alphabet[0]='B';
    options.start_cbn=0;
    options.end_cbn=1;
    options.total_cbn.store(1);
    if (crack_lm8(&options) || options.complete.load()!=0) return 7;
    return 0;
}
