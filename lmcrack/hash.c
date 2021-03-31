
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "des.h"

char* lmhash(char *pwd) {
    DES_cblock       key1, key2;
    DES_key_schedule ks1, ks2;
    const char       ptext[]="KGS!@#$%";
    static char      hash[64], lm_pwd[16];     
    uint8_t          ctext[16];
    size_t           i, pwd_len = strlen(pwd);
    
    // 1. zero-initialize local buffer
    memset(lm_pwd, 0, sizeof(lm_pwd));
    
    // 2. convert password to uppercase (restricted to 14 characters)
    for(i=0; i<pwd_len && i<14; i++) {
      lm_pwd[i] = toupper((int)pwd[i]);
    }
    
    // 3. create two DES keys
    DES_str_to_key((uint8_t*)&lm_pwd[0], (uint8_t*)&key1);
    DES_str_to_key((uint8_t*)&lm_pwd[7], (uint8_t*)&key2);
    DES_set_key(&key1, &ks1);
    DES_set_key(&key2, &ks2);
    
    // 4. encrypt plaintext
    DES_ecb_encrypt((const_DES_cblock*)ptext, 
      (DES_cblock*)&ctext[0], &ks1, DES_ENCRYPT);

    DES_ecb_encrypt((const_DES_cblock*)ptext, 
      (DES_cblock*)&ctext[8], &ks2, DES_ENCRYPT);
      
    // 5. convert ciphertext to string
    for(i=0; i<16; i++) {
      snprintf(&hash[i*2], 3, "%02X", ctext[i]);
    }
    return hash;
}

char* halflm(char *pwd) {
    DES_cblock       key;
    DES_key_schedule ks;
    const char       ptext[]="KGS!@#$%";
    static char      hash[64], lm_pwd[16];
    uint8_t          ctext[16];
    size_t           i, pwd_len = strlen(pwd);
    
    // 1. zero-initialize local buffer
    memset(lm_pwd, 0, sizeof(lm_pwd));
    
    // 2. convert password to uppercase (restricted to 7 characters)
    for(i=0; i<pwd_len && i<7; i++) {
      lm_pwd[i] = toupper((int)pwd[i]);
    }
    
    // 3. create two DES keys
    DES_str_to_key((uint8_t*)&lm_pwd[0], (uint8_t*)&key);
    DES_set_key(&key, &ks);
    
    // 4. encrypt plaintext
    DES_ecb_encrypt((const_DES_cblock*)ptext, 
      (DES_cblock*)&ctext[0], &ks, DES_ENCRYPT);
      
    // 5. convert ciphertext to string
    for(i=0; i<8; i++) {
      snprintf(&hash[i*2], 3, "%02X", ctext[i]);
    }
    return hash;
}

int main(int argc, char *argv[]) {
    if (argc!=2) {
      printf("usage: lmhash <password>\n");
      return 0;
    }
    
    printf("Half LM Hash: %s\n", halflm(argv[1]));
    printf("Full LM Hash: %s\n", lmhash(argv[1]));
    return 0;
}
