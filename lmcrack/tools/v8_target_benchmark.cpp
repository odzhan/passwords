#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "v8_direct_des.h"
#include "v8_target.h"

enum { state_count=64 };

static double benchmark(const bs_block_state states[state_count],
                        const v8_target_state *target,uint64_t iterations,
                        int staged,uint8_t result[BS_BYTES])
{
    bs_vec accumulated=bs_zero();
    std::chrono::steady_clock::time_point begin=std::chrono::steady_clock::now();
    for (uint64_t i=0;i<iterations;i++) {
      const bs_block_state *state=&states[i&(state_count-1)];
      bs_vec match=staged
        ?v8_match_target_state(state->left,state->right,target,BS_LANES)
        :v8_match_target_state_full(state->left,state->right,target,BS_LANES);
      accumulated=bs_xor(accumulated,match);
    }
    std::chrono::steady_clock::time_point end=std::chrono::steady_clock::now();
    bs_store(result,accumulated);
    return std::chrono::duration<double>(end-begin).count();
}

int main(int argc,char **argv)
{
    uint64_t iterations=argc>1?std::strtoull(argv[1],NULL,10):UINT64_C(10000000);
    static const uint8_t target_bytes[8]={0x1f,0xb3,0x63,0xfe,0xb8,0x34,0xc1,0x2d};
    bs_block_state states[state_count];
    v8_target_state target;
    uint8_t full_result[BS_BYTES],staged_result[BS_BYTES];

    bs_sbox_init();
    bs_init_lm_plaintext_state();
    if (!v8_prepare_target_state(target_bytes,&target)) return 1;
    for (unsigned int i=0;i<state_count;i++) {
      v8_bitslice_counter counter;
      bs_vec password[V8_LM_KEY_PLANES];
      if (!v8_bs_counter_init(&counter,(uint64_t)i*BS_LANES,BS_LANES) ||
          !v8_bs_make_key_planes(&counter,password) ||
          !bs_copy_lm_plaintext_state(&states[i])) return 2;
      v8_bs_des_rounds(states[i].left,states[i].right,password);
    }

    double full=benchmark(states,&target,iterations,0,full_result);
    double staged=benchmark(states,&target,iterations,1,staged_result);
    if (std::memcmp(full_result,staged_result,sizeof(full_result))!=0) return 3;
    std::printf("backend lanes: %u\nfull:   %.6f s\nstaged: %.6f s\nspeedup: %.3fx\n",
                (unsigned int)BS_LANES,full,staged,full/staged);
    return 0;
}
