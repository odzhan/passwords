#include <cstdint>
#include <cstring>
#include "bitslice_vec.h"

int main(void)
{
    uint8_t a[BS_BYTES], b[BS_BYTES], out[BS_BYTES];
    for (size_t i=0; i<BS_BYTES; ++i) {
        a[i]=(uint8_t)(i*17U+3U);
        b[i]=(uint8_t)(i*29U+5U);
    }
    bs_vec va=bs_load(a), vb=bs_load(b);
    bs_store(out,bs_xor(bs_and(va,vb),bs_or(va,bs_not(vb))));
    for (size_t i=0; i<BS_BYTES; ++i) {
        uint8_t expected=(uint8_t)((a[i]&b[i])^(a[i]|(uint8_t)~b[i]));
        if (out[i]!=expected) return 1;
    }
    return 0;
}
