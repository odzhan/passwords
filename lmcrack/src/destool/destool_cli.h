#ifndef DESTOOL_CLI_H
#define DESTOOL_CLI_H

#include <ctype.h>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "destool_alphabet.h"

struct destool_cli_options {
    std::string plaintext_hex;
    std::string ciphertext_hex;
    unsigned int alphabet_id;
    unsigned int key_length;
    unsigned int thread_count;
    bool has_alphabet;
    bool has_length;
    bool has_threads;
    bool has_start;
    bool has_end;
    bool show_help;
    std::string start_hex;
    std::string end_hex;

    destool_cli_options()
      : alphabet_id(0),key_length(0),thread_count(0),has_alphabet(false),
        has_length(false),has_threads(false),has_start(false),has_end(false),
        show_help(false) {}
};

static inline bool destool_parse_uint(const std::string &text,
                                      unsigned int *value)
{
    if (value==NULL || text.empty()) return false;
    unsigned int result=0;
    for (size_t i=0;i<text.size();i++) {
      const unsigned char ch=(unsigned char)text[i];
      if (ch<'0' || ch>'9') return false;
      const unsigned int digit=(unsigned int)(ch-'0');
      if (result>(std::numeric_limits<unsigned int>::max()-digit)/10U)
        return false;
      result=result*10U+digit;
    }
    *value=result;
    return true;
}

static inline int destool_hex_nibble(char ch)
{
    if (ch>='0' && ch<='9') return ch-'0';
    if (ch>='a' && ch<='f') return ch-'a'+10;
    if (ch>='A' && ch<='F') return ch-'A'+10;
    return -1;
}

static inline bool destool_parse_hex(const std::string &text,size_t bytes,
                                     uint8_t *output)
{
    if (output==NULL || text.size()!=bytes*2U) return false;
    for (size_t i=0;i<bytes;i++) {
      const int high=destool_hex_nibble(text[i*2U]);
      const int low=destool_hex_nibble(text[i*2U+1U]);
      if (high<0 || low<0) return false;
      output[i]=(uint8_t)((high<<4)|low);
    }
    return true;
}

static inline unsigned int destool_default_threads(void)
{
    unsigned int count=std::thread::hardware_concurrency();
    if (count==0) count=1;
    if (count>DESTOOL_MAX_THREADS) count=DESTOOL_MAX_THREADS;
    return count;
}

static inline bool destool_parse_command_line(int argc,char **argv,
    destool_cli_options *options,std::string *error)
{
    if (options==NULL || error==NULL) return false;
    *options=destool_cli_options();
    error->clear();
    std::vector<std::string> positional;
    for (int i=1;i<argc;i++) {
      const std::string arg=argv[i];
      if (arg=="-h" || arg=="--help") {
        if (argc!=2) { *error="--help cannot be combined with other arguments"; return false; }
        options->show_help=true;
        return true;
      }
      if (arg=="-a" || arg=="-l" || arg=="-t" || arg=="-s" || arg=="-e") {
        if (++i>=argc) { *error="missing value for "+arg; return false; }
        const std::string value=argv[i];
        if (arg=="-a") {
          if (options->has_alphabet) { *error="duplicate -a option"; return false; }
          options->has_alphabet=true;
          if (!destool_parse_uint(value,&options->alphabet_id)) { *error="invalid alphabet ID"; return false; }
        } else if (arg=="-l") {
          if (options->has_length) { *error="duplicate -l option"; return false; }
          options->has_length=true;
          if (!destool_parse_uint(value,&options->key_length)) { *error="invalid key length"; return false; }
        } else if (arg=="-t") {
          if (options->has_threads) { *error="duplicate -t option"; return false; }
          options->has_threads=true;
          if (!destool_parse_uint(value,&options->thread_count)) { *error="invalid thread count"; return false; }
        } else if (arg=="-s") {
          if (options->has_start) { *error="duplicate -s option"; return false; }
          options->has_start=true; options->start_hex=value;
        } else {
          if (options->has_end) { *error="duplicate -e option"; return false; }
          options->has_end=true; options->end_hex=value;
        }
      } else if (!arg.empty() && arg[0]=='-') {
        *error="unknown option: "+arg; return false;
      } else positional.push_back(arg);
    }
    if (positional.size()!=2U) {
      *error="expected plaintext and ciphertext hexadecimal blocks";
      return false;
    }
    options->plaintext_hex=positional[0];
    options->ciphertext_hex=positional[1];
    if (!options->has_alphabet || !options->has_length) {
      *error="both -a and -l are required";
      return false;
    }
    if (!options->has_threads) options->thread_count=destool_default_threads();
    return true;
}

static inline bool destool_make_search_spec(const destool_cli_options &options,
    destool_search_spec *search,std::string *error)
{
    if (search==NULL || error==NULL) return false;
    error->clear();
    if (options.alphabet_id<1 || options.alphabet_id>7) {
      *error="alphabet ID must be between 1 and 7"; return false;
    }
    if (options.key_length<1 || options.key_length>DESTOOL_MAX_KEY_BYTES) {
      *error="key length must be between 1 and 7"; return false;
    }
    if (options.thread_count<1 || options.thread_count>DESTOOL_MAX_THREADS) {
      *error="thread count must be between 1 and 32"; return false;
    }
    if (!destool_parse_hex(options.plaintext_hex,8,search->plaintext) ||
        !destool_parse_hex(options.ciphertext_hex,8,search->ciphertext)) {
      *error="plaintext and ciphertext must each be exactly 16 hexadecimal characters";
      return false;
    }
    uint64_t keyspace=0;
    if (!destool_keyspace_size(options.alphabet_id,options.key_length,&keyspace)) {
      *error="invalid key space"; return false;
    }
    uint8_t endpoint[DESTOOL_MAX_KEY_BYTES]={0};
    uint64_t start=0,end_inclusive=keyspace-1U;
    if (options.has_start) {
      if (!destool_parse_hex(options.start_hex,options.key_length,endpoint) ||
          !destool_key_to_cbn(endpoint,options.alphabet_id,options.key_length,&start)) {
        *error="start key must be exact-length hexadecimal bytes in the selected alphabet";
        return false;
      }
    }
    if (options.has_end) {
      if (!destool_parse_hex(options.end_hex,options.key_length,endpoint) ||
          !destool_key_to_cbn(endpoint,options.alphabet_id,options.key_length,&end_inclusive)) {
        *error="end key must be exact-length hexadecimal bytes in the selected alphabet";
        return false;
      }
    }
    if (start>end_inclusive) { *error="start key follows end key"; return false; }
    *search=destool_search_spec();
    if (!destool_parse_hex(options.plaintext_hex,8,search->plaintext) ||
        !destool_parse_hex(options.ciphertext_hex,8,search->ciphertext)) return false;
    search->alphabet_id=options.alphabet_id;
    search->radix=destool_alphabet_radix(options.alphabet_id);
    search->key_length=options.key_length;
    search->start_cbn=start;
    search->end_cbn=end_inclusive+1U;
    const uint64_t candidates=search->end_cbn-search->start_cbn;
    search->thread_count=options.thread_count;
    if ((uint64_t)search->thread_count>candidates)
      search->thread_count=(unsigned int)candidates;
    return true;
}

static inline const char *destool_alphabet_name(unsigned int id)
{
    static const char *names[]={"invalid","00-FF","0-9","A-Z","a-z",
      "0-9,A-Z","0-9,a-z","0-9,a-z,A-Z"};
    return id<8?names[id]:names[0];
}

static inline const char *destool_backend_name(void)
{
#if defined(LMCRACK_BITSLICE_SCALAR)
    return "scalar";
#elif defined(AVX512) || defined(__AVX512F__)
    return "AVX-512";
#elif defined(AVX2) || defined(__AVX2__)
    return "AVX2";
#elif defined(SSE2) || defined(__SSE2__)
    return "SSE2";
#elif defined(LMCRACK_NEON) || defined(__aarch64__) || defined(_M_ARM64)
    return "NEON";
#else
    return "scalar";
#endif
}

static inline std::string destool_format_hex(const uint8_t *data,size_t size)
{
    std::ostringstream out;
    out<<std::uppercase<<std::hex<<std::setfill('0');
    for (size_t i=0;i<size;i++) out<<std::setw(2)<<(unsigned int)data[i];
    return out.str();
}

static inline std::string destool_format_escaped(const uint8_t *data,size_t size)
{
    std::ostringstream out;
    out<<'"';
    for (size_t i=0;i<size;i++) {
      const uint8_t ch=data[i];
      if (ch>=0x20 && ch<=0x7e && ch!='\\' && ch!='"') out<<(char)ch;
      else if (ch=='\\') out<<"\\\\";
      else if (ch=='"') out<<"\\\"";
      else out<<"\\x"<<std::uppercase<<std::hex<<std::setfill('0')
              <<std::setw(2)<<(unsigned int)ch<<std::dec;
    }
    out<<'"';
    return out.str();
}

static inline uint8_t destool_odd_parity(uint8_t value)
{
    value&=0xfeU;
    uint8_t bits=value;
    bits^=(uint8_t)(bits>>4); bits^=(uint8_t)(bits>>2); bits^=(uint8_t)(bits>>1);
    return (uint8_t)(value|((bits&1U)^1U));
}

static inline void destool_expand_des_key(const uint8_t material[7],
                                          uint8_t key[8])
{
    const uint8_t raw[8]={
      (uint8_t)(material[0]>>1),
      (uint8_t)(((material[0]&1U)<<6)|(material[1]>>2)),
      (uint8_t)(((material[1]&3U)<<5)|(material[2]>>3)),
      (uint8_t)(((material[2]&7U)<<4)|(material[3]>>4)),
      (uint8_t)(((material[3]&15U)<<3)|(material[4]>>5)),
      (uint8_t)(((material[4]&31U)<<2)|(material[5]>>6)),
      (uint8_t)(((material[5]&63U)<<1)|(material[6]>>7)),
      (uint8_t)(material[6]&127U)};
    for (size_t i=0;i<8;i++) key[i]=destool_odd_parity((uint8_t)(raw[i]<<1));
}

#endif
