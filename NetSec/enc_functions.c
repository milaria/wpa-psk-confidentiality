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

// Micahel
#define __LITTLE_ENDIAN
#if defined(__linux__) || defined(__GLIBC__) || defined(__WIN32__) || defined(__APPLE__)
#include <stdint.h>
#else
#include <sys/types.h>
#endif
#include <string.h>

/* kernel defined either one or the other, stdlib defines both */
#if defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
# if defined(__BYTE_ORDER)
#  if __BYTE_ORDER == 1234
#   undef __BIG_ENDIAN
#   warning forecefully undefned __BIG_ENDIAN based on __BYTE_ORDER
#  elif __BYTE_ORDER == 4321
#   undef __LITTLE_ENDIAN
#   warning forecefully undefned __LITTLE_ENDIAN based on __BYTE_ORDER
#  endif
# endif
#endif

#if !defined(__LITTLE_ENDIAN) && !defined(__BIG_ENDIAN)
# error __LITTLE_ENDIAN or __BIG_ENDIAN must be defined
#endif
#if defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN)
# error __LITTLE_ENDIAN or __BIG_ENDIAN must be defined, not both!
#endif

/* Convert to little-endian storage, opposite of network format. */
#if defined(__BIG_ENDIAN)

/* The following guarantees declaration of the byte swap functions. */
#ifdef _MSC_VER
#include <stdlib.h>
#define bswap_16(x) _byteswap_ushort(x)
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)
#elif defined(__APPLE__)
/* Mac OS X / Darwin features */
#include <libkern/OSByteOrder.h>
#define bswap_16(x) OSSwapInt16(x)
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)
#else
#include <byteswap.h>
#endif

static inline uint32_t get_unaligned_le32(const void *p)
{
	return bswap_32(UNALIGNED_LOAD32(p));
}

static inline void put_unaligned_le16(uint16_t val, void *p)
{
	uint8_t *pp = (uint8_t*)p;
	*pp++ = val;
	*pp++ = val >> 8;
}

#else /* !defined(__BIG_ENDIAN) */
#define get_unaligned_le32(p)		(*(const uint32_t*)(p))
#define put_unaligned_le16(v, p)	*(uint16_t*)(p) = (uint16_t)(v)
#endif /* !defined(__BIG_ENDIAN) */

static inline void put_unaligned_le32(u_long val, u_char *p)
{
    put_unaligned_le16(val >> 16, p + 2);
    put_unaligned_le16(val, p);
}

static inline u_short get_unaligned_le16(const u_char *p)
{
    return p[0] | p[1] << 8;
}


#define rol32( A, n ) \
( ((A) << (n)) | ( ((A)>>(32-(n)))  & ( (1UL << (n)) - 1 ) ) )
#define ror32( A, n ) rol32( (A), 32-(n) )

static void michael_block(struct michael_mic_ctx *mctx, u_long val)
{
	mctx->l ^= val;
	mctx->r ^= rol32(mctx->l, 17);
	mctx->l += mctx->r;
	mctx->r ^= ((mctx->l & 0xff00ff00) >> 8) |
    ((mctx->l & 0x00ff00ff) << 8);
	mctx->l += mctx->r;
	mctx->r ^= rol32(mctx->l, 3);
	mctx->l += mctx->r;
	mctx->r ^= ror32(mctx->l, 2);
	mctx->l += mctx->r;
}

static void michael_mic_hdr(struct michael_mic_ctx *mctx, const u_char *key,
                            u_char*da,u_char*sa,u_char priorityID)
{
	mctx->l = get_unaligned_le32(key);
	mctx->r = get_unaligned_le32(key + 4);
    
	/*
	 * A pseudo header (DA, SA, Priority, 0, 0, 0) is used in Michael MIC
	 * calculation, but it is _not_ transmitted
	 */
	michael_block(mctx, get_unaligned_le32(da));
	michael_block(mctx, get_unaligned_le16(&da[4]) |
                  (get_unaligned_le16(sa) << 16));
	michael_block(mctx, get_unaligned_le32(&sa[2]));
	michael_block(mctx, priorityID);
}

void michael_mic(const u_char *key, u_char*da,u_char*sa,u_char priorityID,
                 const u_char *data, size_t data_len, u_char *mic)
{
	u_long val;
	size_t block, blocks, left;
	struct michael_mic_ctx mctx;
    
	michael_mic_hdr(&mctx, key, da,sa,priorityID);
    
	/* Real data */
	blocks = data_len / 4;
	left = data_len % 4;
    
	for (block = 0; block < blocks; block++)
		michael_block(&mctx, get_unaligned_le32(&data[block * 4]));
    
	/* Partial block of 0..3 bytes and padding: 0x5a + 4..7 zeros to make
	 * total length a multiple of 4. */
	val = 0x5a;
	while (left > 0) {
		val <<= 8;
		left--;
		val |= data[blocks * 4 + left];
	}
    
	michael_block(&mctx, val);
	michael_block(&mctx, 0);
    
	put_unaligned_le32(mctx.l, mic);
	put_unaligned_le32(mctx.r, mic + 4);
}
