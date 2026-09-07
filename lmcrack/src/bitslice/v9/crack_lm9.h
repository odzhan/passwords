/** Fixed uppercase-alphanumeric incremental bitsliced DES worker. */

#include "bitslice_batch.h"
#include "fixed_bitslice_des.h"
#include "fixed_bitslice_target.h"
#include "v9_key_planes.h"

static bool crack_lm9(void *param)
{
    crack_opt_t *c=(crack_opt_t*)param;
    alignas(64) v9_bitslice_counter counter;
    alignas(64) bs_vec password[V9_LM_KEY_PLANES];
    alignas(64) bs_block_state state;
    fixed_target_state target;
    uint64_t candidate_count=c->total_cbn.load(std::memory_order_relaxed);

    if (c->alpha_len!=(int)V9_ALPHABET_LENGTH ||
        memcmp(c->alphabet,V9_ALPHABET,V9_ALPHABET_LENGTH+1U)!=0 ||
        candidate_count==0 || c->end_cbn<c->start_cbn ||
        candidate_count!=c->end_cbn-c->start_cbn ||
        !fixed_prepare_target_state(c->hash.b,&target) ||
        !v9_bs_counter_init(&counter,c->start_cbn,candidate_count)) return false;

    while (!c->stopped.load(std::memory_order_relaxed)) {
      size_t count=counter.count;
      uint64_t batch_start=counter.current_cbn;
      if (count==0 || !v9_bs_make_key_planes(&counter,password) ||
          !bs_copy_lm_plaintext_state(&state)) return false;
      fixed_bs_des_rounds(state.left,state.right,password);
      bs_vec matches=fixed_match_target_state(state.left,state.right,&target,count);
      size_t lane=bs_first_match_lane(matches,count);

      c->complete.fetch_add((uint64_t)count,std::memory_order_relaxed);
      uint64_t remaining=c->total_cbn.fetch_sub((uint64_t)count,
                                                 std::memory_order_relaxed);
      if (lane<count) {
        uint8_t digits[V9_MAX_PASSWORD_LENGTH]; unsigned int length;
        if (!v9_cbn_to_digits(batch_start+(uint64_t)lane,digits,&length))
          return false;
        for (size_t i=0;i<sizeof(c->pwd_idx)/sizeof(c->pwd_idx[0]);i++)
          c->pwd_idx[i]=-1;
        for (unsigned int i=0;i<length;i++) c->pwd_idx[i]=(int)digits[i];
        c->pwd_len=(int)length;
        c->found.store(true,std::memory_order_release);
        return true;
      }
      if (remaining<=(uint64_t)count) return false;
      if (!v9_bs_counter_advance(&counter)) return false;
    }
    return false;
}
