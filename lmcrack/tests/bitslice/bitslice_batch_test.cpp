#include <cstdint>
#include <cstring>
#include "bitslice_batch.h"

static int reference_index(int out[BS_MAX_PWD], uint64_t cbn, unsigned alpha)
{
    uint64_t power=alpha;
    int length, i;
    for (i=0; i<(int)BS_MAX_PWD; i++) out[i]=-1;
    for (length=1; cbn>=power; length++) {
        cbn-=power;
        power*=alpha;
    }
    for (i=0; i<length; i++) { out[i]=(int)(cbn%alpha); cbn/=alpha; }
    return length;
}

static int run_case(unsigned alpha, uint64_t start, uint64_t count)
{
    int initial[BS_MAX_PWD], expected[BS_MAX_PWD];
    int length=reference_index(initial,start,alpha);
    bs_candidate_generator generator;
    bs_candidate_batch batch;
    uint64_t offset=0;
    if (!bs_candidate_generator_init(&generator,initial,length,alpha,count)) return 1;

    while (offset<count) {
        size_t n=bs_candidate_next(&generator,&batch);
        size_t wanted=(size_t)((count-offset<BS_LANES)?count-offset:BS_LANES);
        if (n!=wanted || batch.count!=wanted) return 2;
        for (size_t lane=0; lane<n; lane++) {
            int expected_length=reference_index(expected,start+offset+lane,alpha);
            if (batch.length[lane]!=expected_length) return 3;
            for (int i=0; i<expected_length; i++)
                if (batch.index[lane][i]!=expected[i]) return 4;
        }
        offset+=n;
    }
    if (generator.remaining!=0 || bs_candidate_next(&generator,&batch)!=0) return 5;
    return 0;
}

int main(void)
{
    if (run_case(2,0,BS_LANES+17)) return 1;
    if (run_case(3,2,BS_LANES*2+1)) return 2;
    if (run_case(26,25,BS_LANES+3)) return 3;
    if (run_case(26,26+26*26-2,9)) return 4;
    return 0;
}
