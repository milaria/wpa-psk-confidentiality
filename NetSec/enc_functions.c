//
//  enc_functions.c
//  NetSec
//
//  Created by Ilaria Martinelli on 22/08/14.
//  Copyright (c) 2014 Ilaria Martinelli. All rights reserved.
//

#include "enc_functions.h"
#include "util_functions.h"


Phandshake_data sta_data[MAX_NUM_STA];
u_char * PSK;

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

void generate_ptk(int sta_index){
    //PRF-X(PMK, “Pairwise key expansion”, Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce))
    u_char * AA = sta_data[sta_index]->authenticator;
    u_char * SPA = sta_data[sta_index]->supplicant;
    u_char * ANonce = sta_data[sta_index]->ANonce;
    u_char * SNonce = sta_data[sta_index]->SNonce;
    
    //data = Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
    int data_len = 76; //6+6+32+32
    u_char *data = (u_char *) malloc(data_len * sizeof(u_char));
    if(memcmp(SPA,AA, 6) > 0){
        memcpy(data, AA, 6);
        memcpy(data+6, SPA, 6);
    }else{
        memcpy(data, SPA, 6);
        memcpy(data+6, AA, 6);
    }
    
    if(memcmp(ANonce,SNonce, 32) > 0){
        memcpy(data+12, SNonce, 32);
        memcpy(data+12+32, ANonce, 32);
    }else{
        memcpy(data+12, ANonce, 32);
        memcpy(data+12+32, SNonce, 32);
    }
    
    int key_len = 32; //??
    
    u_char *prefix = (unsigned char *)"Pairwise key expansion";
    int prefix_len = (int)strlen((char *)prefix);
    
    int len = 80;
    u_char *output = (u_char *)malloc(len);
    
    PRF(PSK, key_len, prefix, prefix_len, data, data_len, output, len);
    print_exString(output, 64);
    
    memcpy(sta_data[sta_index]->PTK, output, 32 * sizeof(u_char));
    printf("\n");
    
}