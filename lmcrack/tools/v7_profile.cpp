#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "fixed_bitslice_des.h"
#include "fixed_bitslice_target.h"

static volatile unsigned sink;
#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif
// A compiler barrier makes every output observable without timing a full hash
// of the output buffer. MSVC uses a conservative byte-reading fallback.
static NOINLINE void consume(const void *p,size_t size)
{
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" : : "r"(p),"r"(size) : "memory");
#else
    const volatile unsigned char *bytes=(const volatile unsigned char*)p;
    for(size_t i=0;i<size;i++) sink^=bytes[i];
#endif
}

struct fixture {
    bs_candidate_batch batch;
    bs_vec key[BS_KEY_PLANES];
    bs_key_schedule schedule;
    bs_block_state encrypted;
};
static fixture samples[16];
static const uint8_t hash[8]={0};
static fixed_target_state target;
static bs_vec lane_masks[16];

static NOINLINE void encrypt_old(bs_block_state &state,const bs_vec *key)
{
    bs_key_schedule schedule;
    bs_make_key_schedule(key,&schedule);
    bs_copy_lm_plaintext_state(&state);
    bs_des_rounds(state.left,state.right,&schedule);
}
static NOINLINE void encrypt_new(bs_block_state &state,const bs_vec *key)
{
    bs_copy_lm_plaintext_state(&state);
    fixed_bs_des_rounds(state.left,state.right,key);
}

enum phase { generate,transpose,schedule,des_old,des_new,match_old,match_new,
             pipeline_old,pipeline_new,transpose_reference,pipeline_previous,
             lane_reference,lane_current };
static const char *names[]={"generation","transpose","schedule","DES scheduled",
    "DES schedule-free","match original","match staged","pipeline original","pipeline current",
    "transpose reference","pipeline pre-transpose","lane reference","lane current"};

static NOINLINE void run(phase mode,unsigned iterations,const char *alphabet)
{
    int indexes[7]={0};
    bs_candidate_generator generator;
    bs_candidate_generator_init(&generator,indexes,7,(unsigned)std::strlen(alphabet),
                                (uint64_t)iterations*BS_LANES);
    for(unsigned i=0;i<iterations;i++) {
        fixture &sample=samples[i%16];
        bs_candidate_batch batch;
        bs_vec key[BS_KEY_PLANES],output[64],matches;
        bs_key_schedule keys;
        bs_block_state state;
        switch(mode) {
        case lane_reference:
            sink=(unsigned)bs_first_match_lane_reference(lane_masks[i%16],BS_LANES); break;
        case lane_current:
            sink=(unsigned)bs_first_match_lane(lane_masks[i%16],BS_LANES); break;
        case generate:
            bs_candidate_next(&generator,&batch); consume(&batch,sizeof(batch)); break;
        case transpose:
            bs_transpose_passwords(&sample.batch,alphabet,std::strlen(alphabet),key);
            consume(key,sizeof(key)); break;
        case transpose_reference:
            bs_transpose_passwords_reference(&sample.batch,alphabet,std::strlen(alphabet),key);
            consume(key,sizeof(key)); break;
        case schedule:
            bs_make_key_schedule(sample.key,&keys); consume(&keys,sizeof(keys)); break;
        case des_old:
            bs_copy_lm_plaintext_state(&state);
            bs_des_rounds(state.left,state.right,&sample.schedule);
            consume(&state,sizeof(state)); break;
        case des_new:
            encrypt_new(state,sample.key); consume(&state,sizeof(state)); break;
        case match_old:
            bs_final_permutation(sample.encrypted.left,sample.encrypted.right,output);
            matches=bs_match_valid_block(output,hash,sample.batch.count);
            consume(&matches,sizeof(matches)); break;
        case match_new:
            matches=fixed_match_target_state(sample.encrypted.left,sample.encrypted.right,
                                             &target,sample.batch.count);
            consume(&matches,sizeof(matches)); break;
        default:
            bs_candidate_next(&generator,&batch);
            if(mode==pipeline_old || mode==pipeline_previous)
                bs_transpose_passwords_reference(&batch,alphabet,std::strlen(alphabet),key);
            else bs_transpose_passwords(&batch,alphabet,std::strlen(alphabet),key);
            if(mode==pipeline_old) {
                encrypt_old(state,key);
                bs_final_permutation(state.left,state.right,output);
                matches=bs_match_valid_block(output,hash,batch.count);
            } else {
                encrypt_new(state,key);
                matches=fixed_match_target_state(state.left,state.right,&target,batch.count);
            }
            sink=(unsigned)(mode==pipeline_old?
                bs_first_match_lane_reference(matches,batch.count):
                bs_first_match_lane(matches,batch.count));
            break;
        }
    }
}

int main(int argc,char **argv)
{
    unsigned iterations=argc>1?(unsigned)std::strtoul(argv[1],NULL,10):20000;
    if(iterations<100 || iterations>1000000) return 2;
    bs_sbox_init(); bs_init_lm_plaintext_state(); fixed_prepare_target_state(hash,&target);
    for(unsigned i=0;i<16;i++) lane_masks[i]=bs_zero();
    uint8_t last[BS_BYTES]={}; last[BS_BYTES-1]=0x80;
    lane_masks[15]=bs_load(last); // Mostly empty masks, occasional last-lane match.
    const char *alphabets[]={"ABCDEFGHIJKLMNOPQRSTUVWXYZ","0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                            "!#%0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_"};
    for(const char *alphabet:alphabets) {
        int indexes[7]={0}; bs_candidate_generator generator;
        bs_candidate_generator_init(&generator,indexes,7,(unsigned)std::strlen(alphabet),16*BS_LANES-1);
        for(auto &sample:samples) {
            bs_candidate_next(&generator,&sample.batch);
            bs_transpose_passwords(&sample.batch,alphabet,std::strlen(alphabet),sample.key);
            bs_make_key_schedule(sample.key,&sample.schedule);
            bs_block_state reference;
            encrypt_old(reference,sample.key); encrypt_new(sample.encrypted,sample.key);
            if(std::memcmp(&reference,&sample.encrypted,sizeof(reference))) {
                std::fprintf(stderr,"DES differential mismatch\n"); return 1;
            }
        }
        std::printf("alphabet=%s lanes=%u iterations=%u repetitions=5\n",alphabet,BS_LANES,iterations);
        std::vector<double> times[13];
        for(int p=0;p<13;p++) run((phase)p,100,alphabet);
        // Alternate order to reduce systematic temperature/order bias.
        for(int repeat=0;repeat<5;repeat++) for(int j=0;j<13;j++) {
            int p=repeat%2?12-j:j;
            auto start=std::chrono::steady_clock::now();
            run((phase)p,iterations,alphabet);
            double ns=std::chrono::duration<double,std::nano>(std::chrono::steady_clock::now()-start).count()/iterations;
            times[p].push_back(ns);
        }
        for(int p=0;p<13;p++) {
            std::sort(times[p].begin(),times[p].end());
            std::printf("%-20s median=%9.2f min=%9.2f max=%9.2f ns/batch rate=%.2f M/s\n",
                        names[p],times[p][2],times[p][0],times[p][4],BS_LANES*1000.0/times[p][2]);
        }
        std::printf("pipeline speedup=%.3fx differential=PASS\n",times[7][2]/times[8][2]);
        std::printf("transpose-only pipeline speedup=%.3fx\n",times[10][2]/times[8][2]);
    }
}
