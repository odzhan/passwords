#include "v5x_schedule.h"
#include <algorithm>

int main()
{
    alignas(32) uint32_t prefix[40],pairs[104],out[104];
    uint32_t random=1234567;
    for(unsigned trial=0;trial<100;trial++) {
      for(auto &word:prefix) { random=random*1664525U+1013904223U; word=random; }
      for(auto &word:pairs) { random=random*1664525U+1013904223U; word=random; }
      for(unsigned offset=0;offset<8;offset++) for(unsigned count=1;count<=3;count++) {
        std::fill(out,out+104,0xdeadbeefU);
        lm5x_merge3(prefix+offset,pairs+offset,out+offset,count);
        for(unsigned word=0;word<104;word++) {
          uint32_t expected=0xdeadbeefU;
          if(word>=offset && word<offset+count*32)
            expected=prefix[offset+(word-offset)%32]|pairs[word];
          if(out[word]!=expected) return 1;
        }
      }
    }
    return 0;
}
