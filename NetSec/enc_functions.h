//
//  enc_functions.h
//  NetSec
//
//  Created by Ilaria Martinelli on 22/08/14.
//  Copyright (c) 2014 Ilaria Martinelli. All rights reserved.
//

#ifndef NetSec_enc_functions_h
#define NetSec_enc_functions_h

#define A_SHA_DIGEST_LEN 20

#define MAX_NUM_STA 10

#include <assert.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

typedef struct handshake_data{
    u_char supplicant[6];
    u_char authenticator[6];
    u_char ANonce[32]; //32byte
    u_char SNonce[32]; //32byte
    u_char IV[16];
    u_char PTK[32];
    int state;//1 if finished
}Handshake_data, * Phandshake_data;

void F(char *password, unsigned char *ssid, int ssidlength, int iterations, int count, unsigned char *output);
int PasswordHash ( char *password, unsigned char *ssid, int ssidlength, unsigned char *output);
void PRF(unsigned char *key, int key_len,
         unsigned char *prefix, int prefix_len,
         unsigned char *data, int data_len,
         unsigned char *output, int len);
void generate_ptk(int sta_index);

#endif
