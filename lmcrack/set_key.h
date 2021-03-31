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

void DES_str_to_key (uint8_t str[], uint8_t key[]) {
    int i;

    key[0] = str[0] >> 1;
    key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2);
    key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3);
    key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4);
    key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5);
    key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6);
    key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7);
    key[7] = str[6] & 0x7F;

    for (i = 0;i < 8;i++) {
      key[i] = (key[i] << 1);
    }
    DES_set_odd_parity ((DES_cblock*)key);
}

// initialize 7*256 key schedules
void DES_init_keys(DES_key_schedule ks_tbl[7][256]) {
    DES_cblock key;
    int        i, j;
    uint8_t    pwd[8];
    
    memset(pwd,0,sizeof(pwd));
    
    // for each byte of a 56-bit key
    for(i=0;i<7;i++) {
      // create 256 key schedules
      for(j=0;j<256;j++) {
        pwd[i]=j;
        DES_str_to_key(pwd, (uint8_t*)&key);
        DES_set_key(&key, &ks_tbl[i][j]);
      }
      // clear byte
      pwd[i]=0;
    }
}

// generate DES key schedule from precomputed DES schedules
void DES_set_keyx(DES_cblock*key, 
  DES_key_schedule *ks, DES_key_schedule ks_tbl[7][256]) 
{
    uint64_t *s, *d;
    uint8_t  *k=(uint8_t*)key;
    size_t   i, j;
    
    d = (uint64_t*)ks;
    
    // zero initialize
    for(i=0; i<128/8; i++) 
      d[i]=0;
    
    // for each byte of a 56-bit key
    for(i=0; i<7; i++) {
      // get a key schedule
      s = (uint64_t*)&ks_tbl[i][k[i]];
      
      // perform a bitwise OR
      for(j=0; j<128/8; j++) 
        d[j] |= s[j];
    }
}

// initialize key schedules for alphabet
void DES_init_keys2(char alphabet[], 
  DES_key_schedule ks_tbl[7][256]) 
{
    DES_cblock key;
    uint8_t    pwd[7+1];
    size_t     i, j, alpha_len=strlen(alphabet);
    
    memset(pwd,0,sizeof(pwd));
    
    // for each byte of a 56-bit key
    for(i=0;i<7;i++) {
      // create key schedules for each character of the alphabet
      for(j=0;j<alpha_len;j++) {
        pwd[i] = alphabet[j];
        DES_str_to_key(pwd, (uint8_t*)&key);
        DES_set_key(&key, &ks_tbl[i][j]);
      }
      // clear byte
      pwd[i]=0;
    }
}
