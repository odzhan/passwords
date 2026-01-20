/**
  Copyright © 2015 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */
  
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <algorithm>
#include <functional>

#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cinttypes>

#include "des.h"

#ifndef _MSC_VER
#include <sys/time.h>
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <malloc.h>

#define CLOCK_MONOTONIC 0

#define aligned_alloc(align,size) _aligned_malloc(size,align)

int clock_gettime(int, struct timespec *spec)      //C-file part
{  __int64 wintime; GetSystemTimeAsFileTime((FILETIME*)&wintime);
   wintime      -=116444736000000000i64;  //1jan1601 to 1jan1970
   spec->tv_sec  =wintime / 10000000i64;           //seconds
   spec->tv_nsec =wintime % 10000000i64 *100;      //nano-seconds
   return 0;
}

#endif

#define MAX_PWD       7
#define HASH_STR_LEN 16
#define HASH_BIN_LEN  8

typedef union _hash_t {
    uint8_t  b[256];
    uint32_t w[256/4];
    uint64_t q[256/8];
} hash_t;

typedef bool (*crack_routine_t)(void*);

typedef struct {
    int                   id;
    crack_routine_t       crack;
    uint64_t              start_cbn, end_cbn, thread_cbn;
    std::atomic<uint64_t> complete, total_cbn;
    std::atomic<bool>     found, stopped;
    int                   pwd_idx[256], pwd_len;
    char                  start_pwd[256], end_pwd[256];
    int                   alpha_len, thread_cnt;
    char                  alphabet[128];
    DES_key_schedule       *ks_tbl_full;
    DES_key_schedule       *ks_tbl_alpha;
    DES_key_schedule       *ks_pairs;
    size_t                ks_pairs_len;
    hash_t                hash;
} crack_opt_t;

typedef struct _crack_stats_t {
    uint32_t seconds;
    uint32_t minutes;
    uint32_t hours; 
    uint32_t days;
    uint32_t percent;
    float    speed;
} crack_stats_t;

#include "crack_lm1.h"
#include "crack_lm2.h"
#include "crack_lm3.h"
#include "crack_lm4.h"

#define MAX_THREADS 32

class cracker {
  private:
    std::mutex               m;
    std::condition_variable  cv;
    std::atomic<bool>        found;
    std::string              alphabet, start_pwd, end_pwd;
    uint32_t                 cpu_cnt, thread_cnt;
    std::atomic<uint32_t>    thread_run;
    uint64_t                 start_cbn, end_cbn, total_cbn;
    std::vector<std::thread> threads;
    struct timespec          ts_start, ts_end;
    crack_opt_t              *c;
    hash_t                   hash;
    std::vector<DES_key_schedule> ks_tbl_full;
    std::vector<DES_key_schedule> ks_tbl_alpha;
    std::vector<DES_key_schedule> ks_pairs;
    std::string              ks_tbl_alpha_key;
    size_t                   ks_pairs_alpha_len;
    
    // convert string to integer
    uint64_t pwd2cbn(std::string pwd) {
        uint64_t               cbn=0, pwr=1;
        std::string::size_type pwd_len, idx, i;
        
        pwd_len = pwd.length();
        
        for (i=0; i<pwd_len; i++) {
          // get index of character in alphabet
          idx = alphabet.find(pwd.at(i));
          // not found?
          if (idx == std::string::npos) {
            return 0;
          }
          cbn += pwr * (idx + 1); 
          pwr *= alphabet.length();
        } 
        return cbn;
    }

    // convert integer to password string
    std::string cbn2pwd(uint64_t cbn) {
        uint64_t    pwr = alphabet.length();
        size_t      pwd_len, i;
        std::string pwd;
        
        // calculate the length of string
        for (pwd_len=1; cbn>=pwr; pwd_len++) {
          cbn -= pwr; 
          pwr *= alphabet.length();
        }
        
        // create string from alphabet
        for (i=0; i<pwd_len; i++) { 
          pwd.push_back(alphabet.at(cbn % alphabet.length())); 
          cbn /= alphabet.length(); 
        }
        return pwd;
    }

    // convert integer to index values
    int cbn2idx(int idx[], uint64_t cbn) {
        uint64_t pwr = alphabet.length();
        int      pwd_len, i;
        
        // set indexes to initial value
        for (i=0; i<256; i++) 
          idx[i] = ~0;
        
        // calculate the amount of index values
        for (pwd_len=1; cbn>=pwr; pwd_len++) {
          cbn -= pwr; 
          pwr *= alphabet.length();
        }
        
        // create index values
        for (i=0; i<pwd_len; i++) { 
          idx[i] = (cbn % alphabet.length()); 
          cbn /= alphabet.length(); 
        }
        return pwd_len;
    }
    
  public:
    cracker() {
        found      = false;
        cpu_cnt    = std::max(1u, std::thread::hardware_concurrency());
        thread_cnt = cpu_cnt;
        c          = NULL;
        ks_pairs_alpha_len = 0;
    }
    
    ~cracker(){
        threads.clear();
    }
    
    bool set_hash(std::string h, uint8_t out[]) {
        int len, i, x;
        
        len = h.length();
        
        // ensure correct hash length
        if (len != HASH_STR_LEN) {
          return false;
        }
        
        // ensure only hexadecimal characters
        for (i=0; i<len; i++) {
          if (isxdigit((int)h.at(i)) == 0) {
            return false; 
          }
        }
        
        // then convert to binary
        for (i=0; i<len/2; i++) {
          sscanf(&h.at(i*2), "%2x", &x);
          out[i] = (uint8_t)x;
        }
        return true;
    }
    
    // initialize the first and last passwords to try
    bool set_options(uint32_t thd_cnt, std::string h, 
      std::string s, std::string s_pwd, std::string e_pwd) 
    {
        // we don't want thread count to exceed number of cpu available
        if (thd_cnt != 0) {
          thread_cnt = std::min(thd_cnt, cpu_cnt);
        }
        if (thread_cnt == 0) thread_cnt = 1;
        start_pwd  = s_pwd;
        end_pwd    = e_pwd;
        
        // convert hash to binary
        if(!set_hash(h, hash.b)) return false;
        
        // initialize alphabet
        std::transform(s.begin(), s.end(), s.begin(),
          [](uint8_t c) -> uint8_t {return (uint8_t)toupper(c);});
        std::sort(s.begin(),s.end());
        s.erase(std::unique(s.begin(),s.end()),s.end());
        // use default if none provided
        alphabet = s.empty() ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : s;
        if (alphabet.length() >= sizeof(((crack_opt_t*)0)->alphabet)) {
          return false;
        }

        std::transform(start_pwd.begin(), start_pwd.end(), start_pwd.begin(),
          [](uint8_t c) -> uint8_t {return (uint8_t)toupper(c);});
        std::transform(end_pwd.begin(), end_pwd.end(), end_pwd.begin(),
          [](uint8_t c) -> uint8_t {return (uint8_t)toupper(c);});
        
        // if no start password, set to first character in alphabet
        if(start_pwd.empty() || start_pwd.length() > MAX_PWD) {
          start_pwd.clear();
          start_pwd.push_back(alphabet.front());
        }
        
        // if no end password, set to last character in alphabet
        if(end_pwd.empty() || end_pwd.length() > MAX_PWD) {
          end_pwd.clear();
          for(int i=0; i<MAX_PWD; i++) {
            end_pwd.push_back(alphabet.back());
          }
        }
        
        // set start combination
        start_cbn = pwd2cbn(start_pwd);
        if(start_cbn==0) return false;
        
        // set end combination
        end_cbn = pwd2cbn(end_pwd);
        if(end_cbn==0) return false;
        
        // ensure start doesn't exceed end
        if(start_cbn > end_cbn) return false;
      
        // subtract one from start
        start_cbn--;
        
        // set the total
        total_cbn = (end_cbn - start_cbn);
       
        // ensure thread_cnt doesn't exceed total_cbn
        if (total_cbn < 10000) thread_cnt=1;

        // alphabet changed; invalidate cached tables
        ks_tbl_alpha.clear();
        ks_pairs.clear();
        ks_tbl_alpha_key.clear();
        ks_pairs_alpha_len = 0;
      
        return true;
    }
    
    void get_options(crack_opt_t *opts) {
        size_t len;
        memset((void*)opts, 0, sizeof(crack_opt_t));
        
        opts->start_cbn  = start_cbn;
        opts->end_cbn    = end_cbn;
        opts->total_cbn  = total_cbn;
        opts->thread_cbn = (total_cbn/thread_cnt);
        opts->thread_cnt = thread_cnt;
        
        len = std::min(alphabet.size(), sizeof(opts->alphabet) - 1);
        memcpy(opts->alphabet, alphabet.data(), len);
        opts->alphabet[len] = '\0';

        len = std::min(start_pwd.size(), sizeof(opts->start_pwd) - 1);
        memcpy(opts->start_pwd, start_pwd.data(), len);
        opts->start_pwd[len] = '\0';

        len = std::min(end_pwd.size(), sizeof(opts->end_pwd) - 1);
        memcpy(opts->end_pwd, end_pwd.data(), len);
        opts->end_pwd[len] = '\0';
    }

    bool get_stats(crack_stats_t *s) {
        size_t        i;
        std::uint64_t x=0;
        double        e;
        
        memset(s, 0, sizeof(crack_stats_t));
        
        for (i=0; i<threads.size(); i++) {
          x += c[i].complete.load(std::memory_order_relaxed);
        }
        
        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        
        e = (((double)ts_end.tv_sec  - ts_start.tv_sec)*1000) + 
            (((double)ts_end.tv_nsec - ts_start.tv_nsec)/1000000); 
        
        if (x==0 || x>total_cbn || e<1) return false;
        
        s->percent = (((100 * (float)x) / (float)total_cbn));
        s->speed = ((float)(x / e))/1000;
        
        s->days=0; s->hours=0; s->minutes=0;
        s->seconds = (total_cbn - x) / (x / e)/1000;
        
        if(s->seconds >= 60) {
          s->minutes = (s->seconds / 60);
          s->seconds %= 60;
          if(s->minutes >= 60) {
            s->hours = s->minutes / 60;
            s->minutes %= 60;
            if(s->hours >= 24) {
              s->days = s->hours/24;
              s->hours %= 24;
            }
          }
        }
        return true;
    }
    
    void worker(crack_opt_t *opts) {  
        // try recover the password
        opts->crack(opts);      
        
        if (opts->found) {
          // we found the password
          std::lock_guard<std::mutex> lk(m);
          found=true;
        }
        // indicate we've stopped working
        opts->stopped=true;
        thread_run--;

        // notify main thread
        cv.notify_all();
    }
    
    void prepare_tables(crack_routine_t func) {
        if ((func == crack_lm2 || func == crack_lm3 || func == crack_lm4) &&
            ks_tbl_full.empty()) {
          ks_tbl_full.resize(7 * 256);
          DES_init_keys(reinterpret_cast<DES_key_schedule (*)[256]>(
              ks_tbl_full.data()));
        }

        if (func == crack_lm3 || func == crack_lm4) {
          if (ks_tbl_alpha.empty() || ks_tbl_alpha_key != alphabet) {
            ks_tbl_alpha.resize(7 * 256);
            DES_init_keys2(const_cast<char*>(alphabet.c_str()),
              reinterpret_cast<DES_key_schedule (*)[256]>(
                ks_tbl_alpha.data()));
            ks_tbl_alpha_key = alphabet;
          }
        }

        if (func == crack_lm4) {
          size_t alpha_len = alphabet.length();
          size_t pairs_len = alpha_len * alpha_len;
          if (alpha_len != 0 &&
              (ks_pairs.size() != pairs_len ||
               ks_pairs_alpha_len != alpha_len)) {
            DES_cblock key;
            uint8_t    pwd[MAX_PWD];
            size_t     i, j;

            ks_pairs.resize(pairs_len);
            ks_pairs_alpha_len = alpha_len;

            DES_key_schedule *p = ks_pairs.data();
            for (i = 0; i < alpha_len; i++) {
              memset(pwd, 0, sizeof(pwd));
              pwd[0] = (uint8_t)alphabet[i];
              for (j = 0; j < alpha_len; j++) {
                pwd[1] = (uint8_t)alphabet[j];
                DES_str_to_key(pwd, (uint8_t*)&key);
                DES_set_key(&key, p);
                p++;
              }
            }
          }
        }
    }

    // distribute jobs to each CPU
    void start(crack_routine_t func) {
        uint64_t cbn = start_cbn;
        uint64_t thd_cbn = (total_cbn / thread_cnt);
        size_t   alpha_len = alphabet.length();
        
        threads.clear();
        
        if (c!=NULL) {
          #ifdef _MSC_VER
            _aligned_free(c);
          #else
            free(c);
          #endif
          c=NULL;
        }
        thread_run = 0;
        found = false;

        prepare_tables(func);
        
        {
          size_t alloc_size = thread_cnt * sizeof(crack_opt_t);
          size_t aligned_size = (alloc_size + 31) & ~(size_t)31;
          c = (crack_opt_t*)aligned_alloc(32, aligned_size);
          if (c == NULL) {
            fprintf(stderr, "  [ allocation failed\n");
            return;
          }
        }

        // for each available cpu
        for (size_t i=0; i<thread_cnt; i++) {
          memset((void*)&c[i], 0, sizeof(crack_opt_t));
          
          c[i].id = i;
          // set cracking routine
          c[i].crack = func;
          // set alphabet
          c[i].alpha_len = (int)alpha_len;
          memset(c[i].alphabet, 0, sizeof(c[i].alphabet));
          memcpy(c[i].alphabet, alphabet.data(),
            std::min(alpha_len, sizeof(c[i].alphabet) - 1));
          // set hash
          memcpy(c[i].hash.b, hash.b, HASH_BIN_LEN);
          // set shared tables
          c[i].ks_tbl_full = ks_tbl_full.empty() ? NULL : ks_tbl_full.data();
          c[i].ks_tbl_alpha = ks_tbl_alpha.empty() ? NULL : ks_tbl_alpha.data();
          c[i].ks_pairs = ks_pairs.empty() ? NULL : ks_pairs.data();
          c[i].ks_pairs_len = ks_pairs.size();
          // set the first combination
          c[i].start_cbn = cbn;
          c[i].pwd_len = cbn2idx(c[i].pwd_idx, cbn);
          
          // set the last combination
          if ((i+1)==thread_cnt) {
            c[i].end_cbn   = cbn + (total_cbn - (thd_cbn*i));
            c[i].total_cbn = (total_cbn - (thd_cbn*i));
          } else {
            c[i].end_cbn = (cbn + thd_cbn);
            c[i].total_cbn = (c[i].end_cbn - c[i].start_cbn);
          }
          cbn = c[i].end_cbn;
        }

        for(size_t i=0; i<thread_cnt; i++) {
          threads.push_back(std::move(std::thread(&cracker::worker, this, &c[i])));
          thread_run++;
        }
        clock_gettime(CLOCK_MONOTONIC, &ts_start);
    }
    
    bool isFound(void) {
        return found;
    }
    
    bool wait(int seconds) {
        std::unique_lock<std::mutex> lk(m);
        cv.wait_for(lk, std::chrono::seconds(seconds), 
          std::bind(&cracker::isFound, this));
        lk.unlock();
        
        return found;
    }
    
    void stop(void) {
        for(size_t i=0;i<threads.size();i++) {
          c[i].stopped=1;
          threads[i].join();
        }
    }
    
    std::string get_pwd(void) {
        std::string pwd;
        
        for(size_t i=0; i<threads.size() && pwd.empty(); i++) {
          if (c[i].found) {
            for(int j=0; j<MAX_PWD; j++) {
              if(c[i].pwd_idx[j]<0) break;
              pwd.push_back(alphabet.at(c[i].pwd_idx[j]));
            }
          }
        }
        return pwd;
    }
    uint64_t threads_running(void) {
        return thread_run;
    }
};

void show_stats(cracker *c) {
    crack_stats_t s;
    #if !defined(_WIN32) && !defined(_WIN64)
      #define PREFIX "\33[2K"
    #else
      #define PREFIX ""
    #endif
  
    if(c->get_stats(&s)) {
      printf(PREFIX"\r  [ %.2fM k/s %u%% complete. "
          "ETA: %u days %02u hours %02u minutes %02u seconds",
          s.speed, s.percent, s.days, s.hours, s.minutes, s.seconds);
      fflush(stdout);
    }
}

void usage(void) {
    printf("\n\n");
    printf("  [ usage: crack_lm [options] <half LM hash>\n\n");
    printf("       -c <alphabet>  custom alphabet to use\n");
    printf("       -s <start>     start password\n");
    printf("       -e <end>       end password\n");
    printf("       -t <threads>   number of threads\n\n");
    printf("       -v1|-v2|-v3|-v4 select cracking version\n\n");
    exit(1);
}

char* getparam (int argc, char *argv[], int *i) {
    int n=*i;
    
    if (argv[n][2] != 0) {
      return &argv[n][2];
    }
    
    if ((n+1) < argc) {
      *i=n+1;
      return argv[n+1];
    }
    printf ("  [ %c%c requires parameter\n", argv[n][0], argv[n][1]);
    exit (0);
}

int main(int argc, char *argv[]) {
    cracker         c;
    crack_opt_t     opts;
    crack_routine_t lm[4]={crack_lm1,crack_lm2,crack_lm3,crack_lm4};
    bool            found=false;
    std::string     alphabet, start_pwd, end_pwd, hash, pwd;
    int             thread_cnt=0;
    uint32_t        version_mask=0;
    
    // need at least a hash
    if(argc<2) {
      usage();
    }
    
    // process arguments passed to program
    for (int i=1; i<argc; i++) {
      if (argv[i][0]=='-' || argv[i][0]=='/') {
        switch (argv[i][1]) {
          // custom alphabet
          case 'c':
            alphabet = getparam(argc, argv, &i);
            break;
          // end password
          case 'e':
            end_pwd = getparam(argc, argv, &i);
            break;
          // start password
          case 's':
            start_pwd = getparam(argc, argv, &i);
            break;
          // number of threads
          case 't':
            thread_cnt = atoi(getparam (argc, argv, &i));
            break;
          case 'v':
          case 'V':
            if (argv[i][2] >= '1' && argv[i][2] <= '4' && argv[i][3] == 0) {
              version_mask |= (1u << (argv[i][2] - '1'));
            } else {
              printf("  [ invalid version selector %s\n", argv[i]);
              usage();
            }
            break;
          case 'h':
          case '?':
            usage();
            break;
          default:
            printf ("  [ unknown option %c", argv[i][1]);
            break;
        }
      } else {
        hash = argv[i];
      }
    }
    
    // no hash?
    if(hash.empty()) {
      printf("  [ no hash specified.\n");
      usage();
    }
    
    // initialize
    if(!c.set_options(thread_cnt,hash,alphabet,start_pwd,end_pwd)) {
      printf("  [ failed to initialize parameters.\n");
      usage();
    }
    
    // display options
    c.get_options(&opts);
    
    printf ("  [ start pwd   : \"%s\"\n", opts.start_pwd);
    printf ("  [ end pwd     : \"%s\"\n", opts.end_pwd);
    printf ("  [ alphabet    : \"%s\"\n", opts.alphabet);
    printf ("  [ total pwd   : %" PRIu64 "\n",   (uint64_t)opts.total_cbn);
    printf ("  [ thread cbn  : %" PRIu64 "\n",   opts.thread_cbn);
    printf ("  [ thread cnt  : %" PRIu32 "\n\n",  opts.thread_cnt);
      
    #define CNT 4
    
    for(size_t i=0;i<CNT;i++) {
      if (version_mask != 0 && ((version_mask & (1u << i)) == 0)) {
        continue;
      }
      found=false;
      printf("  [ version %zu\n", (i+1));
      c.start(lm[i]);
      
      // wait for threads to finish
      while(!found) {
        found = c.wait(1);
        show_stats(&c);
        if(found || !c.threads_running()) break;
      }
      putchar('\n');      
      if (found) {
        pwd = c.get_pwd();
        printf("  [ found password : %s\n\n", pwd.c_str());
      } else printf("  [ password could not be found.\n\n");
      // stop any remaining threads
      c.stop();
    }
    return 0;
}
