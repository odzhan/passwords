#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include "bitslice_fixed_des.h"
#include "bitslice_target.h"
#include "destool_cli.h"
#include "destool_key_planes.h"

struct benchmark_options {
    unsigned int duration;
    unsigned int warmup;
    unsigned int threads;
    unsigned int alphabet;
    unsigned int length;
    benchmark_options()
      : duration(5),warmup(1),threads(destool_default_threads()),alphabet(5),
        length(7) {}
};

struct benchmark_context {
    benchmark_options options;
    uint64_t keyspace;
    bs_block_state plaintext;
    bs_target_state target;
    std::chrono::steady_clock::time_point deadline;
    std::atomic<unsigned int> ready;
    std::atomic<bool> start;
    std::atomic<bool> failed;
    std::atomic<uint64_t> tested;
    std::atomic<uint64_t> checksum;
    benchmark_context()
      : keyspace(0),ready(0),start(false),failed(false),tested(0),checksum(0) {}
};

static void usage(void)
{
    std::printf(
      "Usage: destool_benchmark [-d seconds] [-w warmup-seconds] [-t threads] "
      "[-a alphabet] [-l length]\n"
      "Defaults: -d 5 -w 1 -t <hardware> -a 5 -l 7\n");
}

static bool parse_options(int argc,char **argv,benchmark_options *options)
{
    if (options==NULL) return false;
    for (int i=1;i<argc;i++) {
      const std::string arg=argv[i];
      if (arg=="-h" || arg=="--help") { usage(); std::exit(0); }
      if (arg!="-d" && arg!="-w" && arg!="-t" && arg!="-a" && arg!="-l")
        return false;
      if (++i>=argc) return false;
      unsigned int value=0;
      if (!destool_parse_uint(argv[i],&value)) return false;
      if (arg=="-d") options->duration=value;
      else if (arg=="-w") options->warmup=value;
      else if (arg=="-t") options->threads=value;
      else if (arg=="-a") options->alphabet=value;
      else options->length=value;
    }
    return options->duration>=1U && options->duration<=3600U &&
      options->warmup<=60U && options->threads>=1U &&
      options->threads<=DESTOOL_MAX_THREADS && options->alphabet>=1U &&
      options->alphabet<=7U && options->length>=1U &&
      options->length<=DESTOOL_MAX_KEY_BYTES;
}

static void benchmark_worker(benchmark_context *context,unsigned int index)
{
    destool_bitslice_counter counter;
    const uint64_t start=(context->keyspace/context->options.threads)*index;
    if (!destool_bs_counter_init(&counter,context->options.alphabet,
          context->options.length,start,context->keyspace-start)) {
      context->failed.store(true,std::memory_order_release);
    }
    context->ready.fetch_add(1U,std::memory_order_release);
    while (!context->start.load(std::memory_order_acquire))
      std::this_thread::yield();
    if (context->failed.load(std::memory_order_acquire)) return;

    uint64_t batches=0,local_tested=0,local_checksum=0;
    for (;;) {
      alignas(64) bs_vec key[BS_KEY_PLANES];
      alignas(64) bs_block_state state=context->plaintext;
      const size_t count=counter.count;
      if (!destool_bs_make_key_planes(&counter,key) ||
          !bs_fixed_encrypt_state(&state,key)) {
        context->failed.store(true,std::memory_order_release);
        break;
      }
      const bs_vec matches=bs_match_target_state(
        state.left,state.right,&context->target,count);
      local_checksum^=(uint64_t)bs_first_match_lane(matches,count)+batches;
      local_tested+=(uint64_t)count;
      if (!destool_bs_counter_advance(&counter) &&
          !destool_bs_counter_init(&counter,context->options.alphabet,
            context->options.length,start,context->keyspace-start)) {
        context->failed.store(true,std::memory_order_release);
        break;
      }
      batches++;
      if ((batches&63U)==0U &&
          std::chrono::steady_clock::now()>=context->deadline) break;
    }
    context->tested.fetch_add(local_tested,std::memory_order_relaxed);
    context->checksum.fetch_xor(local_checksum,std::memory_order_relaxed);
}

static bool run_phase(const benchmark_options &options,unsigned int seconds,
                      uint64_t *tested,double *elapsed,uint64_t *checksum)
{
    const uint8_t plaintext[8]={0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    const uint8_t target[8]={0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    benchmark_context context;
    context.options=options;
    if (!destool_keyspace_size(options.alphabet,options.length,&context.keyspace)
        || context.keyspace<options.threads ||
        !bs_prepare_plaintext_state(plaintext,&context.plaintext) ||
        !bs_prepare_target_state(target,&context.target)) return false;
    std::vector<std::thread> threads;
    try {
      threads.reserve(options.threads);
      for (unsigned int i=0;i<options.threads;i++)
        threads.push_back(std::thread(benchmark_worker,&context,i));
    } catch (...) {
      context.failed.store(true,std::memory_order_release);
    }
    while (context.ready.load(std::memory_order_acquire)<threads.size())
      std::this_thread::yield();
    const std::chrono::steady_clock::time_point begin=
      std::chrono::steady_clock::now();
    context.deadline=begin+std::chrono::seconds(seconds);
    context.start.store(true,std::memory_order_release);
    for (size_t i=0;i<threads.size();i++) threads[i].join();
    *elapsed=std::chrono::duration<double>(
      std::chrono::steady_clock::now()-begin).count();
    *tested=context.tested.load(std::memory_order_relaxed);
    *checksum=context.checksum.load(std::memory_order_relaxed);
    return threads.size()==options.threads &&
      !context.failed.load(std::memory_order_acquire);
}

int main(int argc,char **argv)
{
    benchmark_options options;
    if (!parse_options(argc,argv,&options)) { usage(); return 2; }
    bs_sbox_init();
    std::printf("backend=%s lanes=%u alphabet=%u(%s) length=%u threads=%u "
                "warmup=%us duration=%us\n",destool_backend_name(),
                (unsigned int)BS_LANES,options.alphabet,
                destool_alphabet_name(options.alphabet),options.length,
                options.threads,options.warmup,options.duration);
    if (options.warmup>0) {
      uint64_t warmup_tested=0,warmup_checksum=0;
      double warmup_elapsed=0.0;
      if (!run_phase(options,options.warmup,&warmup_tested,&warmup_elapsed,
                     &warmup_checksum)) return 3;
      std::printf("warmup: candidates=%llu elapsed=%.3fs rate=%.2f M/s\n",
        (unsigned long long)warmup_tested,warmup_elapsed,
        (double)warmup_tested/warmup_elapsed/1000000.0);
    }
    uint64_t tested=0,checksum=0;
    double elapsed=0.0;
    if (!run_phase(options,options.duration,&tested,&elapsed,&checksum)) return 3;
    std::printf("result: candidates=%llu elapsed=%.3fs rate=%.2f M/s "
                "checksum=%llu\n",(unsigned long long)tested,elapsed,
                (double)tested/elapsed/1000000.0,(unsigned long long)checksum);
    return 0;
}
