#ifndef DESTOOL_RUNNER_H
#define DESTOOL_RUNNER_H

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <thread>
#include <vector>

#include "destool_worker.h"

typedef void (*destool_progress_fn)(uint64_t tested,uint64_t total,
                                    double elapsed_seconds,bool final,
                                    void *context);

static inline destool_result destool_run_search(const destool_search_spec &search,
    destool_progress_fn progress,void *context)
{
    destool_result result;
    destool_shared_state shared;
    std::vector<destool_worker_job> jobs(search.thread_count);
    std::vector<std::thread> threads;
    std::atomic<unsigned int> finished(0);
    std::mutex finish_mutex;
    std::condition_variable finish_condition;
    const uint64_t total=search.end_cbn-search.start_cbn;
    const std::chrono::steady_clock::time_point started=std::chrono::steady_clock::now();

    if (search.thread_count==0 || search.start_cbn>=search.end_cbn) {
      result.outcome=DESTOOL_INVALID_INPUT;
      return result;
    }
    bs_sbox_init();
    try {
      threads.reserve(search.thread_count);
      for (unsigned int i=0;i<search.thread_count;i++) {
        uint64_t start=0,end=0;
        if (!destool_partition_range(search.start_cbn,search.end_cbn,i,
                                     search.thread_count,&start,&end) || start>=end) {
          shared.fail();
          break;
        }
        jobs[i].search=&search;
        jobs[i].shared=&shared;
        jobs[i].worker_index=i;
        jobs[i].start_cbn=start;
        jobs[i].end_cbn=end;
        threads.push_back(std::thread([&jobs,&finished,&finish_condition,i]() {
          destool_worker_run(&jobs[i]);
          finished.fetch_add(1U,std::memory_order_release);
          finish_condition.notify_one();
        }));
      }
    } catch (...) {
      shared.fail();
    }

    while (finished.load(std::memory_order_acquire)<threads.size()) {
      std::unique_lock<std::mutex> lock(finish_mutex);
      finish_condition.wait_for(lock,std::chrono::milliseconds(250),
        [&finished,&threads]() {
          return finished.load(std::memory_order_acquire)>=threads.size();
        });
      lock.unlock();
      if (progress!=NULL) {
        const double elapsed=std::chrono::duration<double>(
          std::chrono::steady_clock::now()-started).count();
        progress(shared.tested.load(std::memory_order_relaxed),total,elapsed,
                 false,context);
      }
    }
    for (size_t i=0;i<threads.size();i++) threads[i].join();
    result.elapsed_seconds=std::chrono::duration<double>(
      std::chrono::steady_clock::now()-started).count();
    result.tested=shared.tested.load(std::memory_order_relaxed);
    if (shared.failed.load(std::memory_order_acquire) ||
        threads.size()!=search.thread_count) {
      result.outcome=DESTOOL_INTERNAL_ERROR;
    } else if (shared.found.load(std::memory_order_acquire)) {
      std::lock_guard<std::mutex> lock(shared.result_mutex);
      result.outcome=DESTOOL_FOUND;
      result.recovered_length=shared.recovered_length;
      std::memcpy(result.recovered_key,shared.recovered_key,
                  sizeof(result.recovered_key));
    } else result.outcome=DESTOOL_EXHAUSTED;
    if (progress!=NULL) progress(result.tested,total,result.elapsed_seconds,true,context);
    return result;
}

#endif
