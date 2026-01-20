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

static bool crack_lm1(void *param) {
    int              i;
    DES_cblock       deskey;
    DES_key_schedule ks;
    uint8_t          pwd[8]={0};
    const char       ptext[]="KGS!@#$%";
    uint8_t          ctext[8];
    crack_opt_t      *c=(crack_opt_t*)param;
    
    // create password from index values
    for(i=0;i<7;i++) {
      if(c->pwd_idx[i]<0)break;
      pwd[i] = c->alphabet[c->pwd_idx[i]];
    }
      
    // while not stopped
    while(!c->stopped) {
      // convert password to DES odd parity key
      DES_str_to_key(pwd, (uint8_t*)deskey);
      // create DES subkeys 
      DES_set_key(&deskey, &ks);
      // encrypt plaintext
      DES_ecb_encrypt((const_DES_cblock*)ptext, 
        (DES_cblock*)ctext, &ks, DES_ENCRYPT);
      
      // increase how many passwords processed
      c->complete.fetch_add(1, std::memory_order_relaxed);
      
      // if hashes match, set found and exit loop
      if(memcmp(ctext, c->hash.b, 8)==0) {
        c->found=true;
        return true;
      }
      // decrease total tried. if none left, exit
      if (c->total_cbn.fetch_sub(1, std::memory_order_relaxed) == 1) {
        return false;
      }
      // update password index values
      for(i=0;;i++) {
        // increase one. if not length of alphabet, break.
        if(++c->pwd_idx[i] != c->alpha_len) {
          pwd[i] = c->alphabet[c->pwd_idx[i]];
          break;
        }  
        // reset index
        c->pwd_idx[i]=0;
        pwd[i] = c->alphabet[0];
      }
    }
    // we didn't find it
    return false;
}
