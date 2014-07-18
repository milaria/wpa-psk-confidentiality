//
//  PRF.h
//  NetSec
//
//  Created by Ilaria Martinelli on 19/02/13.
//  Copyright (c) 2013 Ilaria Martinelli. All rights reserved.
//

#ifndef NetSec_PRF_h
#define NetSec_PRF_h

#include <assert.h>
#include <openssl/hmac.h>
/*
 * PRF -- Length of output is in octets rather than bits
 *     since length is always a multiple of 8 output array is
 *     organized so first N octets starting from 0 contains PRF output
 *
 *     supported inputs are 16, 24, 32, 48, 64
 *     output array must be 80 octets to allow for sha1 overflow
 */
void PRF(unsigned char *key, int key_len,
         unsigned char *prefix, int prefix_len,
         unsigned char *data, int data_len,
         unsigned char *output, int len){
    int i;
    unsigned char input[1024]; /* concatenated input */
    int currentindex = 0;
    int total_len;
    memcpy(input, prefix, prefix_len);
    input[prefix_len] = 0; /* single octet 0 */
    memcpy(&input[prefix_len+1], data, data_len);
    total_len = prefix_len + 1 + data_len;
    input[total_len] = 0; /* single octet count, starts at 0 */
    total_len++;
    for (i = 0; i < (len+19)/20; i++) {
        //hmac_sha1(input, total_len, key, key_len, &output[currentindex]);
        HMAC(EVP_sha1(), key, key_len, input, total_len, &output[currentindex], NULL);
        currentindex += 20;/* next concatenation location */
        input[total_len-1]++; /* increment octet count */
    }
}


#endif
