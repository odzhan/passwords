#ifndef DESTOOL_WORKER_H
#define DESTOOL_WORKER_H

#include "bitslice_fixed_des.h"
#include "bitslice_target.h"
#include "destool_key_planes.h"
#include "destool_types.h"

static inline void destool_worker_run(destool_worker_job *job)
{
    if (job==NULL || job->search==NULL || job->shared==NULL ||
        job->start_cbn>=job->end_cbn ||
        job->end_cbn>job->search->end_cbn) {
      if (job!=NULL && job->shared!=NULL) job->shared->fail();
      return;
    }

    destool_bitslice_counter counter;
    bs_block_state prepared_plaintext;
    bs_target_state prepared_target;
    const uint64_t candidate_count=job->end_cbn-job->start_cbn;
    if (!destool_bs_counter_init(&counter,job->search->alphabet_id,
          job->search->key_length,job->start_cbn,candidate_count) ||
        !bs_prepare_plaintext_state(job->search->plaintext,&prepared_plaintext) ||
        !bs_prepare_target_state(job->search->ciphertext,&prepared_target)) {
      job->shared->fail();
      return;
    }

    while (!job->shared->stop.load(std::memory_order_relaxed)) {
      const size_t count=counter.count;
      const uint64_t batch_start=counter.current_cbn;
      alignas(64) bs_vec key_planes[BS_KEY_PLANES];
      alignas(64) bs_block_state state=prepared_plaintext;
      if (count==0 || !destool_bs_make_key_planes(&counter,key_planes) ||
          !bs_fixed_encrypt_state(&state,key_planes)) {
        job->shared->fail();
        return;
      }

      const bs_vec matches=bs_match_target_state(
        state.left,state.right,&prepared_target,count);
      const size_t lane=bs_first_match_lane(matches,count);
      job->shared->tested.fetch_add((uint64_t)count,std::memory_order_relaxed);
      if (lane<count) {
        uint8_t recovered[DESTOOL_MAX_KEY_BYTES];
        if (!destool_cbn_to_key(batch_start+(uint64_t)lane,
              job->search->alphabet_id,job->search->key_length,recovered)) {
          job->shared->fail();
          return;
        }
        job->shared->publish(recovered,job->search->key_length);
        return;
      }

      if (!destool_bs_counter_advance(&counter)) return;
    }
}

#endif
