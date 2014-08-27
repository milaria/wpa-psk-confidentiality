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
    int state;//1 if finished & valid
}Handshake_data, * Phandshake_data;

void F(char *password, unsigned char *ssid, int ssidlength, int iterations, int count, unsigned char *output);
int PasswordHash ( char *password, unsigned char *ssid, int ssidlength, unsigned char *output);
void PRF(unsigned char *key, int key_len,
         unsigned char *prefix, int prefix_len,
         unsigned char *data, int data_len,
         unsigned char *output, int len);
void generate_ptk(int sta_index);

#define MICHAEL_MIC_LEN 8

struct michael_mic_ctx {
	u_long l, r;
};

void michael_mic(const u_char *key, u_char*da,u_char*sa,u_char priorityID, const u_char *data, size_t data_len, u_char *mic);

#define UPDC32(octet,crc) (crc_32_tab[((crc) ^ ((u_char)octet)) & 0xff] ^ ((crc) >> 8))
u_long updateCRC32(u_char ch, u_long crc);
u_long crc32buf(u_char *buf, size_t len);

u_char * rc4(u_char *pszText, int iTextLen, u_char *pszKey, int keylen);

void swapints(int *array, int ndx1, int ndx2);

void Phase1(u_short * P1K, const u_char * TK, const u_char * TA, u_long IV32);
void Phase2(u_char * RC4KEY, const u_char * TK, const u_short * P1K, u_short IV16);


#endif
