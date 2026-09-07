#ifndef DESTOOL_ALPHABET_H
#define DESTOOL_ALPHABET_H

#include <stddef.h>
#include <stdint.h>

#include "destool_types.h"

static inline unsigned int destool_alphabet_radix(unsigned int alphabet_id)
{
    static const unsigned int radix[8]={0,256,10,26,26,36,36,62};
    return alphabet_id<8?radix[alphabet_id]:0;
}

static inline bool destool_digit_to_byte(unsigned int alphabet_id,
                                         unsigned int digit,uint8_t *value)
{
    const unsigned int radix=destool_alphabet_radix(alphabet_id);
    if (value==NULL || digit>=radix) return false;
    switch (alphabet_id) {
      case 1: *value=(uint8_t)digit; break;
      case 2: *value=(uint8_t)('0'+digit); break;
      case 3: *value=(uint8_t)('A'+digit); break;
      case 4: *value=(uint8_t)('a'+digit); break;
      case 5: *value=(uint8_t)(digit<10?'0'+digit:'A'+digit-10); break;
      case 6: *value=(uint8_t)(digit<10?'0'+digit:'a'+digit-10); break;
      case 7:
        *value=(uint8_t)(digit<10?'0'+digit:
          (digit<36?'a'+digit-10:'A'+digit-36));
        break;
      default: return false;
    }
    return true;
}

static inline bool destool_byte_to_digit(unsigned int alphabet_id,uint8_t value,
                                         unsigned int *digit)
{
    unsigned int result;
    if (digit==NULL) return false;
    switch (alphabet_id) {
      case 1: result=value; break;
      case 2:
        if (value<'0' || value>'9') return false;
        result=(unsigned int)(value-'0'); break;
      case 3:
        if (value<'A' || value>'Z') return false;
        result=(unsigned int)(value-'A'); break;
      case 4:
        if (value<'a' || value>'z') return false;
        result=(unsigned int)(value-'a'); break;
      case 5:
        if (value>='0' && value<='9') result=(unsigned int)(value-'0');
        else if (value>='A' && value<='Z') result=10U+(unsigned int)(value-'A');
        else return false;
        break;
      case 6:
        if (value>='0' && value<='9') result=(unsigned int)(value-'0');
        else if (value>='a' && value<='z') result=10U+(unsigned int)(value-'a');
        else return false;
        break;
      case 7:
        if (value>='0' && value<='9') result=(unsigned int)(value-'0');
        else if (value>='a' && value<='z') result=10U+(unsigned int)(value-'a');
        else if (value>='A' && value<='Z') result=36U+(unsigned int)(value-'A');
        else return false;
        break;
      default: return false;
    }
    *digit=result;
    return true;
}

static inline bool destool_keyspace_size(unsigned int alphabet_id,
    unsigned int length,uint64_t *size)
{
    if (length==0 || length>DESTOOL_MAX_KEY_BYTES) return false;
    return destool_checked_pow(destool_alphabet_radix(alphabet_id),length,size);
}

static inline bool destool_cbn_to_key(uint64_t cbn,unsigned int alphabet_id,
    unsigned int length,uint8_t key[DESTOOL_MAX_KEY_BYTES])
{
    uint64_t size;
    const unsigned int radix=destool_alphabet_radix(alphabet_id);
    if (key==NULL || !destool_keyspace_size(alphabet_id,length,&size) ||
        cbn>=size) return false;
    for (unsigned int position=0;position<DESTOOL_MAX_KEY_BYTES;position++)
      key[position]=0;
    for (unsigned int position=0;position<length;position++) {
      if (!destool_digit_to_byte(alphabet_id,(unsigned int)(cbn%radix),
                                 &key[position])) return false;
      cbn/=radix;
    }
    return true;
}

static inline bool destool_key_to_cbn(const uint8_t *key,
    unsigned int alphabet_id,unsigned int length,uint64_t *cbn)
{
    uint64_t value=0,place=1,size;
    const unsigned int radix=destool_alphabet_radix(alphabet_id);
    if (key==NULL || cbn==NULL ||
        !destool_keyspace_size(alphabet_id,length,&size)) return false;
    for (unsigned int position=0;position<length;position++) {
      unsigned int digit;
      if (!destool_byte_to_digit(alphabet_id,key[position],&digit)) return false;
      value+=place*digit;
      if (position+1U<length) place*=radix;
    }
    if (value>=size) return false;
    *cbn=value;
    return true;
}

#endif
