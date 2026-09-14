/** SIMD bitsliced DES cracking worker. */

#include "bitslice_block.h"
#include "fixed_bitslice_des.h"
#include "fixed_bitslice_target.h"

static bool crack_lm7(void *param)
{
    crack_opt_t *c=(crack_opt_t*)param;
    bs_candidate_generator generator;
    bs_candidate_batch batch;
    bs_vec password[BS_KEY_PLANES];
    bs_block_state state;
    fixed_target_state target;
    int recovered[BS_MAX_PWD],recovered_length;
    uint64_t candidate_count=c->total_cbn.load(std::memory_order_relaxed);

    if (!bs_candidate_generator_init(&generator,c->pwd_idx,c->pwd_len,
                                     (unsigned)c->alpha_len,candidate_count) ||
        !fixed_prepare_target_state(c->hash.b,&target))
      return false;

    while (!c->stopped) {
      size_t count=bs_candidate_next(&generator,&batch);
      if (count==0) return false;
      if (!bs_transpose_passwords(&batch,c->alphabet,(size_t)c->alpha_len,password))
        return false;
      if (!bs_copy_lm_plaintext_state(&state)) return false;
      fixed_bs_des_rounds(state.left,state.right,password);

      bs_vec matches=fixed_match_target_state(state.left,state.right,
                                              &target,count);
      size_t lane=bs_first_match_lane(matches,count);
      if (lane<count) {
        if (!bs_recover_candidate(&batch,lane,recovered,&recovered_length))
          return false;
        for (int i=0;i<(int)BS_MAX_PWD;i++) c->pwd_idx[i]=recovered[i];
        c->pwd_len=recovered_length;
        c->found=true;
        return true;
      }

      c->complete.fetch_add((uint64_t)count,std::memory_order_relaxed);
      {
        uint64_t remaining=c->total_cbn.fetch_sub((uint64_t)count,
                                                   std::memory_order_relaxed);
        if (remaining<=(uint64_t)count) return false;
      }
    }
    return false;
}
