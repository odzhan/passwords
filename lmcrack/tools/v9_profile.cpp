#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "fixed_bitslice_des.h"
#include "fixed_bitslice_target.h"
#include "v9_key_planes.h"

static volatile uint64_t profile_sink=0;

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void consume(const bs_vec *value)
{
    uint8_t bytes[BS_BYTES]; uint64_t word=0;
    bs_store(bytes,*value); std::memcpy(&word,bytes,sizeof(word));
    profile_sink^=word;
}

template <typename Function>
static double time_batches(uint64_t iterations,Function function)
{
    std::chrono::steady_clock::time_point begin=std::chrono::steady_clock::now();
    function(iterations);
    std::chrono::steady_clock::time_point end=std::chrono::steady_clock::now();
    return std::chrono::duration<double,std::nano>(end-begin).count()/iterations;
}

static void profile_counter(uint64_t iterations)
{
    alignas(64) v9_bitslice_counter counter;
    uint64_t start=v9_length_block_start(7)+1234567U;
    v9_bs_counter_init(&counter,start,iterations*BS_LANES+1U);
    for (uint64_t i=0;i<iterations;i++) {
      consume(&counter.digit[0][0]);
      v9_bs_counter_advance(&counter);
    }
}

static void profile_key(uint64_t iterations)
{
    alignas(64) v9_bitslice_counter counter; alignas(64) bs_vec password[56];
    uint64_t start=v9_length_block_start(7)+1234567U;
    v9_bs_counter_init(&counter,start,iterations*BS_LANES+1U);
    for (uint64_t i=0;i<iterations;i++) {
      v9_bs_make_key_planes(&counter,password); consume(&password[(i%7U)*8U]);
      v9_bs_counter_advance(&counter);
    }
}

static void profile_des(uint64_t iterations)
{
    alignas(64) v9_bitslice_counter counter; alignas(64) bs_vec password[56];
    alignas(64) bs_block_state state;
    uint64_t start=v9_length_block_start(7)+1234567U;
    v9_bs_counter_init(&counter,start,iterations*BS_LANES+1U);
    for (uint64_t i=0;i<iterations;i++) {
      v9_bs_make_key_planes(&counter,password); bs_copy_lm_plaintext_state(&state);
      fixed_bs_des_rounds(state.left,state.right,password);
      consume(&state.left[i&31U]); v9_bs_counter_advance(&counter);
    }
}

static void profile_target(uint64_t iterations)
{
    static const uint8_t hash[8]={0xdb,0x66,0x09,0x12,0x53,0x98,0xc8,0x17};
    alignas(64) bs_block_state states[64]; fixed_target_state target;
    fixed_prepare_target_state(hash,&target);
    for (unsigned int i=0;i<64;i++) {
      alignas(64) v9_bitslice_counter counter; alignas(64) bs_vec password[56];
      v9_bs_counter_init(&counter,v9_length_block_start(6)+(uint64_t)i*BS_LANES,
                         BS_LANES);
      v9_bs_make_key_planes(&counter,password); bs_copy_lm_plaintext_state(&states[i]);
      fixed_bs_des_rounds(states[i].left,states[i].right,password);
    }
    for (uint64_t i=0;i<iterations;i++) {
      bs_vec match=fixed_match_target_state(states[i&63U].left,
                                            states[i&63U].right,
                                            &target,BS_LANES);
      consume(&match);
    }
}

static void profile_atomic(uint64_t iterations)
{
    std::atomic<uint64_t> progress(0);
    for (uint64_t i=0;i<iterations;i++)
      progress.fetch_add(BS_LANES,std::memory_order_relaxed);
    profile_sink^=progress.load(std::memory_order_relaxed);
}

int main(int argc,char **argv)
{
    uint64_t iterations=argc>1?std::strtoull(argv[1],NULL,10):20000U;
    if (iterations<100 || iterations*BS_LANES>UINT64_C(1000000000)) return 1;
    bs_sbox_init(); bs_init_lm_plaintext_state();
    uint64_t des_iterations=iterations/20U;
    double counter=time_batches(iterations,profile_counter);
    double key_and_counter=time_batches(iterations,profile_key);
    double des_hot_path=time_batches(des_iterations,profile_des);
    double target=time_batches(iterations*20U,profile_target);
    double atomic=time_batches(iterations*20U,profile_atomic);
    std::printf("lanes=%u ns/batch: counter=%.2f key=%.2f DES+key+counter=%.2f "
                "target=%.2f atomic=%.2f sink=%llu\n",
                (unsigned int)BS_LANES,counter,key_and_counter-counter,
                des_hot_path,target,atomic,(unsigned long long)profile_sink);
    return 0;
}
