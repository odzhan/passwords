#ifndef DESTOOL_TYPES_H
#define DESTOOL_TYPES_H

#include <atomic>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdint.h>

#define DESTOOL_BLOCK_BYTES 8U
#define DESTOOL_MAX_KEY_BYTES 7U
#define DESTOOL_MAX_THREADS 32U

enum destool_outcome {
    DESTOOL_FOUND = 0,
    DESTOOL_EXHAUSTED = 1,
    DESTOOL_INVALID_INPUT = 2,
    DESTOOL_INTERNAL_ERROR = 3
};

struct destool_search_spec {
    uint8_t plaintext[DESTOOL_BLOCK_BYTES];
    uint8_t ciphertext[DESTOOL_BLOCK_BYTES];
    unsigned int alphabet_id;
    unsigned int radix;
    unsigned int key_length;
    unsigned int thread_count;
    uint64_t start_cbn;
    uint64_t end_cbn;

    destool_search_spec()
      : alphabet_id(0),radix(0),key_length(0),thread_count(0),
        start_cbn(0),end_cbn(0)
    {
      std::memset(plaintext,0,sizeof(plaintext));
      std::memset(ciphertext,0,sizeof(ciphertext));
    }
};

struct destool_shared_state {
    std::atomic<uint64_t> tested;
    std::atomic<bool> stop;
    std::atomic<bool> found;
    std::atomic<bool> failed;
    std::mutex result_mutex;
    uint8_t recovered_key[DESTOOL_MAX_KEY_BYTES];
    unsigned int recovered_length;

    destool_shared_state()
      : tested(0),stop(false),found(false),failed(false),recovered_length(0)
    {
      std::memset(recovered_key,0,sizeof(recovered_key));
    }

    bool publish(const uint8_t *key,unsigned int length)
    {
      if (key==NULL || length==0 || length>DESTOOL_MAX_KEY_BYTES) return false;
      std::lock_guard<std::mutex> lock(result_mutex);
      if (found.load(std::memory_order_relaxed)) return false;
      std::memcpy(recovered_key,key,length);
      std::memset(recovered_key+length,0,sizeof(recovered_key)-length);
      recovered_length=length;
      found.store(true,std::memory_order_release);
      stop.store(true,std::memory_order_release);
      return true;
    }

    void fail()
    {
      failed.store(true,std::memory_order_release);
      stop.store(true,std::memory_order_release);
    }
};

struct destool_worker_job {
    const destool_search_spec *search;
    destool_shared_state *shared;
    unsigned int worker_index;
    uint64_t start_cbn;
    uint64_t end_cbn;

    destool_worker_job()
      : search(NULL),shared(NULL),worker_index(0),start_cbn(0),end_cbn(0) {}
};

struct destool_result {
    destool_outcome outcome;
    uint8_t recovered_key[DESTOOL_MAX_KEY_BYTES];
    unsigned int recovered_length;
    uint64_t tested;
    double elapsed_seconds;

    destool_result()
      : outcome(DESTOOL_INTERNAL_ERROR),recovered_length(0),tested(0),
        elapsed_seconds(0.0)
    {
      std::memset(recovered_key,0,sizeof(recovered_key));
    }
};

static inline bool destool_checked_pow(uint64_t radix,unsigned int exponent,
                                       uint64_t *result)
{
    uint64_t value=1;
    if (result==NULL || radix<2 || exponent==0) return false;
    for (unsigned int i=0;i<exponent;i++) {
      if (value>std::numeric_limits<uint64_t>::max()/radix) return false;
      value*=radix;
    }
    *result=value;
    return true;
}

static inline bool destool_partition_range(uint64_t start,uint64_t end,
    unsigned int worker_index,unsigned int worker_count,
    uint64_t *worker_start,uint64_t *worker_end)
{
    if (worker_start==NULL || worker_end==NULL || start>end || worker_count==0 ||
        worker_index>=worker_count) return false;
    const uint64_t count=end-start;
    const uint64_t base=count/worker_count;
    const uint64_t remainder=count%worker_count;
    const uint64_t before=base*worker_index+
      (worker_index<remainder?worker_index:remainder);
    const uint64_t size=base+(worker_index<remainder?1U:0U);
    *worker_start=start+before;
    *worker_end=*worker_start+size;
    return true;
}

#endif
