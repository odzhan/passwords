#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "destool_cli.h"
#include "destool_runner.h"

static void print_usage(std::ostream &out)
{
    out<<"Usage:\n"
       <<"  destool <plaintext-hex> <ciphertext-hex> -a <1-7> -l <1-7>\n"
       <<"          [-t <threads>] [-s <start-key-hex>] [-e <end-key-hex>]\n\n"
       <<"Arguments are one 8-byte DES plaintext/ciphertext pair as exactly\n"
       <<"16 hexadecimal characters. Candidate material is 1-7 bytes and is\n"
       <<"expanded using the LM 7-byte-to-DES-key mapping. Range endpoints are\n"
       <<"inclusive, exact-length hexadecimal candidate bytes.\n\n"
       <<"Alphabets:\n"
       <<"  1  00-FF             2  0-9              3  A-Z\n"
       <<"  4  a-z               5  0-9,A-Z          6  0-9,a-z\n"
       <<"  7  0-9,a-z,A-Z\n\n"
       <<"Options:\n"
       <<"  -a <id>       Frozen alphabet ID (required)\n"
       <<"  -l <bytes>    Exact candidate length, 1-7 (required)\n"
       <<"  -t <threads>  Worker count, 1-32 (default: hardware concurrency)\n"
       <<"  -s <hex>      Inclusive first candidate (default: first)\n"
       <<"  -e <hex>      Inclusive last candidate (default: last)\n"
       <<"  -h, --help    Show this help\n\n"
       <<"Exit status: 0 found, 1 exhausted, 2 invalid input, 3 internal failure.\n";
}

static std::string format_duration(double seconds)
{
    if (!std::isfinite(seconds) || seconds<0.0) return "--";
    const uint64_t total=(uint64_t)(seconds+0.5);
    const uint64_t days=total/86400U;
    const uint64_t hours=(total%86400U)/3600U;
    const uint64_t minutes=(total%3600U)/60U;
    const uint64_t secs=total%60U;
    std::ostringstream out;
    out<<days<<" days "<<std::setfill('0')<<std::setw(2)<<hours
       <<" hours "<<std::setw(2)<<minutes<<" minutes "
       <<std::setw(2)<<secs<<" seconds";
    return out.str();
}

struct progress_output {
    bool printed;
    double last_update;
    progress_output():printed(false),last_update(0.0) {}
};

static void print_progress(uint64_t tested,uint64_t total,double elapsed,
                           bool final,void *context)
{
    progress_output *state=(progress_output *)context;
    const double rate=elapsed>0.0?(double)tested/elapsed:0.0;
    const double percent=total?100.0*(double)tested/(double)total:100.0;
    const uint64_t remaining=tested<total?total-tested:0;
    const double eta=rate>0.0?(double)remaining/rate:
      std::numeric_limits<double>::infinity();
    if (!final && elapsed-state->last_update<1.0) return;
#if !defined(_WIN32) && !defined(_WIN64)
    std::cout<<"\33[2K";
#endif
    std::cout<<"\r  [ "<<std::fixed<<std::setprecision(2)
             <<(rate/1000000.0)<<"M k/s "
             <<(unsigned int)(percent>100.0?100.0:percent)
             <<"% complete. ETA: "<<format_duration(eta);
    if (final) std::cout<<'\n';
    std::cout.flush();
    state->printed=true;
    state->last_update=elapsed;
}

int main(int argc,char **argv)
{
    destool_cli_options options;
    std::string error;
    if (!destool_parse_command_line(argc,argv,&options,&error)) {
      std::cerr<<"destool: "<<error<<"\n\n";
      print_usage(std::cerr);
      return DESTOOL_INVALID_INPUT;
    }
    if (options.show_help) { print_usage(std::cout); return 0; }

    destool_search_spec search;
    if (!destool_make_search_spec(options,&search,&error)) {
      std::cerr<<"destool: "<<error<<"\n";
      return DESTOOL_INVALID_INPUT;
    }
    const uint64_t total=search.end_cbn-search.start_cbn;
    std::cout<<" [ alphabet     : "<<search.alphabet_id<<" ("
             <<destool_alphabet_name(search.alphabet_id)<<")\n"
             <<" [ key length   : "<<search.key_length<<" byte(s)\n"
             <<" [ candidates   : "<<total<<"\n"
             <<" [ thread count : "<<search.thread_count<<"\n"
             <<" [ backend      : "<<destool_backend_name()<<" ("<<BS_LANES
             <<" lanes)\n";

    progress_output progress;
    const destool_result result=destool_run_search(search,print_progress,&progress);
    if (result.outcome==DESTOOL_FOUND) {
      uint8_t padded[7]={0},des_key[8];
      std::memcpy(padded,result.recovered_key,result.recovered_length);
      destool_expand_des_key(padded,des_key);
      std::cout<<" [ found key hex : "
               <<destool_format_hex(result.recovered_key,result.recovered_length)<<"\n"
               <<" [ found key text: "
               <<destool_format_escaped(result.recovered_key,result.recovered_length)<<"\n"
               <<" [ DES key hex   : "<<destool_format_hex(des_key,8)<<"\n";
    } else if (result.outcome==DESTOOL_EXHAUSTED) {
      std::cout<<" [ result        : key space exhausted\n";
    } else {
      std::cerr<<"destool: internal search failure\n";
    }
    return result.outcome;
}
