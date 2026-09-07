#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "bitslice_fixed_des.h"
#include "bitslice_target.h"
#include "destool_key_planes.h"
#include "v9_key_planes.h"

static volatile uint64_t profile_sink=0;

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
static void consume(const bs_vec *value)
{
    uint8_t bytes[BS_BYTES];
    uint64_t word=0;
    bs_store(bytes,*value);
    std::memcpy(&word,bytes,sizeof(word));
    profile_sink^=word;
}

template <typename Function>
static double time_batches(uint64_t iterations,Function function)
{
    const std::chrono::steady_clock::time_point begin=
      std::chrono::steady_clock::now();
    function(iterations);
    const std::chrono::steady_clock::time_point end=
      std::chrono::steady_clock::now();
    return std::chrono::duration<double,std::nano>(end-begin).count()/iterations;
}

static void profile_destool_counter(uint64_t iterations)
{
    alignas(64) destool_bitslice_counter counter;
    destool_bs_counter_init(&counter,5,7,1234567U,iterations*BS_LANES+1U);
    for (uint64_t i=0;i<iterations;i++) {
      consume(&counter.digit[0][0]);
      destool_bs_counter_advance(&counter);
    }
}

static void profile_destool_mapping(uint64_t iterations)
{
    alignas(64) destool_bitslice_counter counter;
    alignas(64) bs_vec key[BS_KEY_PLANES];
    destool_bs_counter_init(&counter,5,7,1234567U,iterations*BS_LANES+1U);
    for (uint64_t i=0;i<iterations;i++) {
      destool_bs_make_key_planes(&counter,key);
      consume(&key[(i%7U)*8U]);
      destool_bs_counter_advance(&counter);
    }
}

static void profile_v9_counter(uint64_t iterations)
{
    alignas(64) v9_bitslice_counter counter;
    const uint64_t start=v9_length_block_start(7)+1234567U;
    v9_bs_counter_init(&counter,start,iterations*BS_LANES+1U);
    for (uint64_t i=0;i<iterations;i++) {
      consume(&counter.digit[0][0]);
      v9_bs_counter_advance(&counter);
    }
}

static void profile_v9_mapping(uint64_t iterations)
{
    alignas(64) v9_bitslice_counter counter;
    alignas(64) bs_vec key[BS_KEY_PLANES];
    const uint64_t start=v9_length_block_start(7)+1234567U;
    v9_bs_counter_init(&counter,start,iterations*BS_LANES+1U);
    for (uint64_t i=0;i<iterations;i++) {
      v9_bs_make_key_planes(&counter,key);
      consume(&key[(i%7U)*8U]);
      v9_bs_counter_advance(&counter);
    }
}

static void prepare_key(bs_vec key[BS_KEY_PLANES])
{
    destool_bitslice_counter counter;
    destool_bs_counter_init(&counter,5,7,1234567U,BS_LANES);
    destool_bs_make_key_planes(&counter,key);
}

static void profile_des(uint64_t iterations)
{
    const uint8_t plaintext[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    alignas(64) bs_vec key[BS_KEY_PLANES];
    alignas(64) bs_block_state prepared,state;
    prepare_key(key);
    bs_prepare_plaintext_state(plaintext,&prepared);
    for (uint64_t i=0;i<iterations;i++) {
      state=prepared;
      bs_fixed_encrypt_state(&state,key);
      consume(&state.left[i&31U]);
    }
}

static void prepare_encrypted_states(bs_block_state states[64])
{
    const uint8_t plaintext[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    for (unsigned int i=0;i<64;i++) {
      destool_bitslice_counter counter;
      alignas(64) bs_vec key[BS_KEY_PLANES];
      destool_bs_counter_init(&counter,5,7,1234567U+(uint64_t)i*BS_LANES,
                              BS_LANES);
      destool_bs_make_key_planes(&counter,key);
      bs_prepare_plaintext_state(plaintext,&states[i]);
      bs_fixed_encrypt_state(&states[i],key);
    }
}

static void profile_target(uint64_t iterations)
{
    const uint8_t ciphertext[8]={0};
    alignas(64) bs_block_state states[64];
    bs_target_state target;
    prepare_encrypted_states(states);
    bs_prepare_target_state(ciphertext,&target);
    for (uint64_t i=0;i<iterations;i++) {
      bs_vec match=bs_match_target_state(states[i&63U].left,
                                         states[i&63U].right,&target,BS_LANES);
      consume(&match);
    }
}

static void profile_atomic_add(uint64_t iterations)
{
    std::atomic<uint64_t> progress(0);
    for (uint64_t i=0;i<iterations;i++)
      progress.fetch_add(BS_LANES,std::memory_order_relaxed);
    profile_sink^=progress.load(std::memory_order_relaxed);
}

static void profile_stop_poll(uint64_t iterations)
{
    std::atomic<bool> stop(false);
    uint64_t seen=0;
    for (uint64_t i=0;i<iterations;i++)
      seen+=(uint64_t)stop.load(std::memory_order_relaxed);
    profile_sink^=seen;
}

static void profile_end_to_end(uint64_t iterations)
{
    const uint8_t plaintext[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    const uint8_t ciphertext[8]={0};
    destool_bitslice_counter counter;
    bs_block_state prepared;
    bs_target_state target;
    destool_bs_counter_init(&counter,5,7,1234567U,iterations*BS_LANES+1U);
    bs_prepare_plaintext_state(plaintext,&prepared);
    bs_prepare_target_state(ciphertext,&target);
    for (uint64_t i=0;i<iterations;i++) {
      alignas(64) bs_vec key[BS_KEY_PLANES];
      alignas(64) bs_block_state state=prepared;
      destool_bs_make_key_planes(&counter,key);
      bs_fixed_encrypt_state(&state,key);
      bs_vec match=bs_match_target_state(state.left,state.right,&target,BS_LANES);
      consume(&match);
      destool_bs_counter_advance(&counter);
    }
}

int main(int argc,char **argv)
{
    const uint64_t iterations=argc>1?std::strtoull(argv[1],NULL,10):20000U;
    if (iterations<100 || iterations>(UINT64_MAX-1U)/BS_LANES) return 1;
    bs_sbox_init();
    const uint64_t des_iterations=iterations/10U<100U?100U:iterations/10U;
    const double counter=time_batches(iterations,profile_destool_counter);
    const double mapped=time_batches(iterations,profile_destool_mapping);
    const double v9_counter=time_batches(iterations,profile_v9_counter);
    const double v9_mapped=time_batches(iterations,profile_v9_mapping);
    const double des=time_batches(des_iterations,profile_des);
    const double target=time_batches(iterations*10U,profile_target);
    const double atomic=time_batches(iterations*10U,profile_atomic_add);
    const double stop=time_batches(iterations*10U,profile_stop_poll);
    const double end_to_end=time_batches(des_iterations,profile_end_to_end);
    std::printf("lanes=%u ns/batch:\n",(unsigned int)BS_LANES);
    std::printf("  destool counter=%8.2f mapping=%8.2f combined=%8.2f\n",
                counter,mapped-counter,mapped);
    std::printf("  v9      counter=%8.2f mapping=%8.2f combined=%8.2f\n",
                v9_counter,v9_mapped-v9_counter,v9_mapped);
    std::printf("  DES=%8.2f target=%8.2f atomic-add=%8.2f stop-poll=%8.2f\n",
                des,target,atomic,stop);
    std::printf("  end-to-end=%8.2f (%.2f M candidates/s) sink=%llu\n",
                end_to_end,(double)BS_LANES*1000.0/end_to_end,
                (unsigned long long)profile_sink);
    return 0;
}
