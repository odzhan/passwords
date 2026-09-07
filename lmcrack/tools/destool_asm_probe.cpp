#include "bitslice_fixed_des.h"
#include "bitslice_target.h"
#include "destool_key_planes.h"

#if defined(_MSC_VER)
__declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
bs_vec destool_asm_probe(destool_bitslice_counter *counter,
                         const bs_block_state *prepared,
                         const bs_target_state *target)
{
    alignas(64) bs_vec key[BS_KEY_PLANES];
    alignas(64) bs_block_state state=*prepared;
    destool_bs_make_key_planes(counter,key);
    bs_fixed_encrypt_state(&state,key);
    const bs_vec match=bs_match_target_state(
      state.left,state.right,target,counter->count);
    destool_bs_counter_advance(counter);
    return match;
}
