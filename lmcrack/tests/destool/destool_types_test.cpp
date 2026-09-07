#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "destool_types.h"

static void test_checked_power(void)
{
    uint64_t value=0;
    assert(destool_checked_pow(10,7,&value) && value==UINT64_C(10000000));
    assert(destool_checked_pow(26,7,&value) && value==UINT64_C(8031810176));
    assert(destool_checked_pow(36,7,&value) && value==UINT64_C(78364164096));
    assert(destool_checked_pow(62,7,&value) && value==UINT64_C(3521614606208));
    assert(destool_checked_pow(256,7,&value) && value==UINT64_C(72057594037927936));
    assert(!destool_checked_pow(UINT64_MAX,2,&value));
    assert(!destool_checked_pow(1,7,&value));
    assert(!destool_checked_pow(10,0,&value));
    assert(!destool_checked_pow(10,7,NULL));
}

static void test_partition(void)
{
    uint64_t start=0,end=0,previous=100;
    for (unsigned int worker=0;worker<3;worker++) {
      assert(destool_partition_range(100,110,worker,3,&start,&end));
      assert(start==previous);
      assert(end-start==(worker==0?4U:3U));
      previous=end;
    }
    assert(previous==110);
    assert(destool_partition_range(5,5,0,1,&start,&end));
    assert(start==5 && end==5);
    assert(!destool_partition_range(10,9,0,1,&start,&end));
    assert(!destool_partition_range(0,10,1,1,&start,&end));
    assert(!destool_partition_range(0,10,0,0,&start,&end));
}

static void test_publication(void)
{
    destool_shared_state state;
    const uint8_t first[3]={0x41,0x00,0xff};
    const uint8_t second[2]={0x42,0x43};
    assert(state.publish(first,3));
    assert(!state.publish(second,2));
    assert(state.found.load(std::memory_order_acquire));
    assert(state.stop.load(std::memory_order_acquire));
    assert(state.recovered_length==3);
    assert(memcmp(state.recovered_key,first,3)==0);
    assert(!state.publish(NULL,1));
    assert(!state.publish(first,8));
}

int main(void)
{
    test_checked_power();
    test_partition();
    test_publication();
    return 0;
}
