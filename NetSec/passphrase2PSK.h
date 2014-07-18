//
//  passphrase2PSK.h
//  NetSec
//
//  Created by Ilaria Martinelli on 10/12/12.
//  Copyright (c) 2012 Ilaria Martinelli. All rights reserved.
//


#ifndef NetSec_passphrase2PSK_h
#define NetSec_passphrase2PSK_h

#define A_SHA_DIGEST_LEN 20
#include <assert.h>
#include <openssl/hmac.h>

/*
 * F(P, S, c, i) = U1 xor U2 xor ... Uc
 * U1 = PRF(P, S || Int(i))
 * U2 = PRF(P, U1)
 * Uc = PRF(P, Uc-1)
 */
void F(char *password, unsigned char *ssid, int ssidlength, int iterations, int count, unsigned char *output){
    
    unsigned char digest[36], digest1[A_SHA_DIGEST_LEN];
    int i, j;
    for (i = 0; i < strlen(password); i++) {
        assert((password[i] >= 32) && (password[i] <= 126));
    }
    
    /* U1 = PRF(P, S || int(i)) */
    memcpy(digest, ssid, ssidlength);
    digest[ssidlength] = (unsigned char)((count>>24) & 0xff);
    digest[ssidlength+1] = (unsigned char)((count>>16) & 0xff);
    digest[ssidlength+2] = (unsigned char)((count>>8) & 0xff);
    digest[ssidlength+3] = (unsigned char)(count & 0xff);
    
    //hmac_sha1(digest, ssidlength+4, (unsigned char*) password, (int) strlen(password), digest, digest1);
    
    HMAC(EVP_sha1(), (unsigned char*) password,(int) strlen(password), digest, ssidlength+4, digest1, NULL);

    
    /* output = U1 */
    memcpy(output, digest1, A_SHA_DIGEST_LEN);
    for (i = 1; i < iterations; i++) {
        
        /* Un = PRF(P, Un-1) */
        //hmac_sha1(digest1, A_SHA_DIGEST_LEN, (unsigned char*) password, (int) strlen(password), digest);
        HMAC(EVP_sha1(), (unsigned char*) password,(int) strlen(password), digest1, A_SHA_DIGEST_LEN, digest, NULL);

        memcpy(digest1, digest, A_SHA_DIGEST_LEN);
        
        /* output = output xor Un */
        for (j = 0; j < A_SHA_DIGEST_LEN; j++) {
            output[j] ^= digest[j];
        }
    }
}

/*
 * password - ascii string up to 63 characters in length
 * ssid - octet string up to 32 octets
 * ssidlength - length of ssid in octets
 * output must be 40 octets in length and outputs 256 bits of key
 */
int PasswordHash ( char *password, unsigned char *ssid, int ssidlength, unsigned char *output){
    
    if ((strlen(password) > 63) || (ssidlength > 32))
        return 0;
    F(password, ssid, ssidlength, 4096, 1, output);
    F(password, ssid, ssidlength, 4096, 2, &output[A_SHA_DIGEST_LEN]);
    return 1;
}

#endif
