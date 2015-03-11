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
    //u_char *data = (u_char *) malloc(data_len * sizeof(u_char));
    
    u_char data[76];
    
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
    
    int len = 64;
    u_char output[80];
    
    PRF(PSK, key_len, prefix, prefix_len, data, data_len, output, len);//FORSE len = 64...
    print_exString(output, 64);
    
    memcpy(sta_data[sta_index]->PTK, output, 64 * sizeof(u_char));
    printf("\n");
    
}

// MICHAEL
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

static inline uint32_t get_unaligned_le32(const void *p){
	return bswap_32(UNALIGNED_LOAD32(p));
}

static inline void put_unaligned_le16(uint16_t val, void *p){
	uint8_t *pp = (uint8_t*)p;
	*pp++ = val;
	*pp++ = val >> 8;
}

#else /* !defined(__BIG_ENDIAN) */
#define get_unaligned_le32(p)		(*(const uint32_t*)(p))
#define put_unaligned_le16(v, p)	*(uint16_t*)(p) = (uint16_t)(v)
#endif /* !defined(__BIG_ENDIAN) */

static inline void put_unaligned_le32(u_long val, u_char *p){
    put_unaligned_le16(val >> 16, p + 2);
    put_unaligned_le16(val, p);
}

static inline u_short get_unaligned_le16(const u_char *p){
    return p[0] | p[1] << 8;
}


#define rol32( A, n ) \
( ((A) << (n)) | ( ((A)>>(32-(n)))  & ( (1UL << (n)) - 1 ) ) )
#define ror32( A, n ) rol32( (A), 32-(n) )

static void michael_block(struct michael_mic_ctx *mctx, u_long val){
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
                            u_char *da, u_char *sa, u_char priorityID){
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

void michael_mic(const u_char *key, u_char *da,u_char *sa,u_char priorityID,
                 const u_char *data, size_t data_len, u_char *mic){
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


/*
 * Copyright (C) 1986 Gary S. Brown.  You may use this program, or code or
 * tables extracted from it, as desired without restriction.
 */
static u_long crc_32_tab[] = {		/* CRC polynomial 0xedb88320 */
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};
u_long updateCRC32(u_char ch, u_long crc){
	return UPDC32(ch, crc);
}
u_long crc32buf(u_char *buf, size_t len){
	register u_long oldcrc32;
	oldcrc32 = 0xFFFFFFFF;
	for (; len; --len, ++buf) {
		oldcrc32 = UPDC32(*buf, oldcrc32);
	}
	return ~oldcrc32;
}

/*
 * ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: ;:::
 * :: ;:::	 This function performs 'RC4' Stream Encryption
 * :: ;:::	 (Based on what is widely thought to be RSA's RC4
 * :: ;:::	 algorithm. It produces output streams that are identical
 * ::: ;:::	 to the commercial products)
 * :: ;:::
 * :: ;:::	 Adapted by permission from a VB script by Mike Shaffer
 * :: ;:::	 http://www.4guysfromrolla.com/webtech/010100-1.shtml
 * :: ;:::
 * :: ;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
 */

/*
 * ;::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: ;:::
 * his routine does all the work. Call it both to ENcrypt	::: ;:::
 * nd to DEcrypt your data.
 * :: ;:::	 You MUST free the returned pointer when no longer needed
 * ::: ;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
 */
u_char * rc4(u_char *pszText, int iTextLen, u_char *pszKey, int keylen){
	u_char  *cipher; /* Output buffer				 */
	int				a, b, i = 0, j = 0, k;	/* Ambiguously named counters	 */
	int				ilen;	/* Length of a string			 */
	int				sbox[256];	/* Encryption array				 */
	int				key[256];	/* Numeric key values			 */
    
	ilen = keylen;
    
	for (a = 0; a < 256; a++) {
		key[a] = pszKey[a % ilen];
		sbox[a] = a;
	}
    
	for (a = 0, b = 0; a < 256; a++) {
		b = (b + sbox[a] + key[a]) % 256;
		swapints(sbox, a, b);
	}
    
	cipher = (u_char *) malloc(iTextLen);
    
	for (a = 0; a < iTextLen; a++) {
		i = (i + 1) % 256;
		j = (j + sbox[i]) % 256;
		swapints(sbox, i, j);
		k = sbox[(sbox[i] + sbox[j]) % 256];
		cipher[a] = pszText[a] ^ k;
	}
	return cipher;
}

void swapints(int *array, int ndx1, int ndx2){
	int				temp = array[ndx1];
	array[ndx1] = array[ndx2];
	array[ndx2] = temp;
}


/***********************************************************************
 Contents:	 Generate IEEE 802.11 per-frame RC4 key hash test vectors
 Date:		 April 19, 2002
 Notes:
 This code is written for pedagogical purposes, NOT for performance.
 ************************************************************************/
/* macros for extraction/creation of byte/u_short values  */
#define RotR1(v16)	((((v16) >> 1) & 0x7FFF) ^ (((v16) & 1) << 15))
#define	  Lo8(v16)	((u_char)( (v16)		 & 0x00FF))
#define	  Hi8(v16)	((u_char)(((v16) >> 8) & 0x00FF))
#define	 Lo16(v32)	 ((u_short)( (v32)		  & 0xFFFF))
#define	 Hi16(v32)	 ((u_short)(((v32) >>16) & 0xFFFF))
#define	 Mk16(hi,lo) ((lo) ^ (((u_short)(hi)) << 8))
/* select the Nth 16-bit word of the Temporal Key byte array TK[]	*/
#define	 TK16(N)	 Mk16(TK[2*(N)+1],TK[2*(N)])
/* S-box lookup: 16 bits --> 16 bits */
#define _S_(v16)	 (Sbox[0][Lo8(v16)] ^ Sbox[1][Hi8(v16)])

/* fixed algorithm "parameters" */
#define PHASE1_LOOP_CNT	  8 /* this needs to be "big enough"	 */
#define TA_SIZE 6		/* 48-bit transmitter address		*/
#define TK_SIZE 16		/* 128-bit Temporal Key				 */
#define P1K_SIZE 10		/* 80-bit Phase1 key				*/
#define RC4_KEY_SIZE 16		/* 128-bit RC4KEY (104 bits unknown) */
#define A_SHA_DIGEST_LEN		20

/* 2-byte by 2-byte subset of the full AES S-box table */
const u_short		Sbox[2][256] = /* Sbox for hash (can be in ROM) */ {{
    0xC6A5, 0xF884, 0xEE99, 0xF68D, 0xFF0D, 0xD6BD, 0xDEB1, 0x9154,
    0x6050, 0x0203, 0xCEA9, 0x567D, 0xE719, 0xB562, 0x4DE6, 0xEC9A,
    0x8F45, 0x1F9D, 0x8940, 0xFA87, 0xEF15, 0xB2EB, 0x8EC9, 0xFB0B,
    0x41EC, 0xB367, 0x5FFD, 0x45EA, 0x23BF, 0x53F7, 0xE496, 0x9B5B,
    0x75C2, 0xE11C, 0x3DAE, 0x4C6A, 0x6C5A, 0x7E41, 0xF502, 0x834F,
    0x685C, 0x51F4, 0xD134, 0xF908, 0xE293, 0xAB73, 0x6253, 0x2A3F,
    0x080C, 0x9552, 0x4665, 0x9D5E, 0x3028, 0x37A1, 0x0A0F, 0x2FB5,
    0x0E09, 0x2436, 0x1B9B, 0xDF3D, 0xCD26, 0x4E69, 0x7FCD, 0xEA9F,
    0x121B, 0x1D9E, 0x5874, 0x342E, 0x362D, 0xDCB2, 0xB4EE, 0x5BFB,
    0xA4F6, 0x764D, 0xB761, 0x7DCE, 0x527B, 0xDD3E, 0x5E71, 0x1397,
    0xA6F5, 0xB968, 0x0000, 0xC12C, 0x4060, 0xE31F, 0x79C8, 0xB6ED,
    0xD4BE, 0x8D46, 0x67D9, 0x724B, 0x94DE, 0x98D4, 0xB0E8, 0x854A,
    0xBB6B, 0xC52A, 0x4FE5, 0xED16, 0x86C5, 0x9AD7, 0x6655, 0x1194,
    0x8ACF, 0xE910, 0x0406, 0xFE81, 0xA0F0, 0x7844, 0x25BA, 0x4BE3,
    0xA2F3, 0x5DFE, 0x80C0, 0x058A, 0x3FAD, 0x21BC, 0x7048, 0xF104,
    0x63DF, 0x77C1, 0xAF75, 0x4263, 0x2030, 0xE51A, 0xFD0E, 0xBF6D,
    0x814C, 0x1814, 0x2635, 0xC32F, 0xBEE1, 0x35A2, 0x88CC, 0x2E39,
    0x9357, 0x55F2, 0xFC82, 0x7A47, 0xC8AC, 0xBAE7, 0x322B, 0xE695,
    0xC0A0, 0x1998, 0x9ED1, 0xA37F, 0x4466, 0x547E, 0x3BAB, 0x0B83,
    0x8CCA, 0xC729, 0x6BD3, 0x283C, 0xA779, 0xBCE2, 0x161D, 0xAD76,
    0xDB3B, 0x6456, 0x744E, 0x141E, 0x92DB, 0x0C0A, 0x486C, 0xB8E4,
    0x9F5D, 0xBD6E, 0x43EF, 0xC4A6, 0x39A8, 0x31A4, 0xD337, 0xF28B,
    0xD532, 0x8B43, 0x6E59, 0xDAB7, 0x018C, 0xB164, 0x9CD2, 0x49E0,
    0xD8B4, 0xACFA, 0xF307, 0xCF25, 0xCAAF, 0xF48E, 0x47E9, 0x1018,
    0x6FD5, 0xF088, 0x4A6F, 0x5C72, 0x3824, 0x57F1, 0x73C7, 0x9751,
    0xCB23, 0xA17C, 0xE89C, 0x3E21, 0x96DD, 0x61DC, 0x0D86, 0x0F85,
    0xE090, 0x7C42, 0x71C4, 0xCCAA, 0x90D8, 0x0605, 0xF701, 0x1C12,
    0xC2A3, 0x6A5F, 0xAEF9, 0x69D0, 0x1791, 0x9958, 0x3A27, 0x27B9,
    0xD938, 0xEB13, 0x2BB3, 0x2233, 0xD2BB, 0xA970, 0x0789, 0x33A7,
    0x2DB6, 0x3C22, 0x1592, 0xC920, 0x8749, 0xAAFF, 0x5078, 0xA57A,
    0x038F, 0x59F8, 0x0980, 0x1A17, 0x65DA, 0xD731, 0x84C6, 0xD0B8,
    0x82C3, 0x29B0, 0x5A77, 0x1E11, 0x7BCB, 0xA8FC, 0x6DD6, 0x2C3A,
},
    {				/* second half of table is byte-reversed
                     * version of first! */
        0xA5C6, 0x84F8, 0x99EE, 0x8DF6, 0x0DFF, 0xBDD6, 0xB1DE, 0x5491,
        0x5060, 0x0302, 0xA9CE, 0x7D56, 0x19E7, 0x62B5, 0xE64D, 0x9AEC,
        0x458F, 0x9D1F, 0x4089, 0x87FA, 0x15EF, 0xEBB2, 0xC98E, 0x0BFB,
        0xEC41, 0x67B3, 0xFD5F, 0xEA45, 0xBF23, 0xF753, 0x96E4, 0x5B9B,
        0xC275, 0x1CE1, 0xAE3D, 0x6A4C, 0x5A6C, 0x417E, 0x02F5, 0x4F83,
        0x5C68, 0xF451, 0x34D1, 0x08F9, 0x93E2, 0x73AB, 0x5362, 0x3F2A,
        0x0C08, 0x5295, 0x6546, 0x5E9D, 0x2830, 0xA137, 0x0F0A, 0xB52F,
        0x090E, 0x3624, 0x9B1B, 0x3DDF, 0x26CD, 0x694E, 0xCD7F, 0x9FEA,
        0x1B12, 0x9E1D, 0x7458, 0x2E34, 0x2D36, 0xB2DC, 0xEEB4, 0xFB5B,
        0xF6A4, 0x4D76, 0x61B7, 0xCE7D, 0x7B52, 0x3EDD, 0x715E, 0x9713,
        0xF5A6, 0x68B9, 0x0000, 0x2CC1, 0x6040, 0x1FE3, 0xC879, 0xEDB6,
        0xBED4, 0x468D, 0xD967, 0x4B72, 0xDE94, 0xD498, 0xE8B0, 0x4A85,
        0x6BBB, 0x2AC5, 0xE54F, 0x16ED, 0xC586, 0xD79A, 0x5566, 0x9411,
        0xCF8A, 0x10E9, 0x0604, 0x81FE, 0xF0A0, 0x4478, 0xBA25, 0xE34B,
        0xF3A2, 0xFE5D, 0xC080, 0x8A05, 0xAD3F, 0xBC21, 0x4870, 0x04F1,
        0xDF63, 0xC177, 0x75AF, 0x6342, 0x3020, 0x1AE5, 0x0EFD, 0x6DBF,
        0x4C81, 0x1418, 0x3526, 0x2FC3, 0xE1BE, 0xA235, 0xCC88, 0x392E,
        0x5793, 0xF255, 0x82FC, 0x477A, 0xACC8, 0xE7BA, 0x2B32, 0x95E6,
        0xA0C0, 0x9819, 0xD19E, 0x7FA3, 0x6644, 0x7E54, 0xAB3B, 0x830B,
        0xCA8C, 0x29C7, 0xD36B, 0x3C28, 0x79A7, 0xE2BC, 0x1D16, 0x76AD,
        0x3BDB, 0x5664, 0x4E74, 0x1E14, 0xDB92, 0x0A0C, 0x6C48, 0xE4B8,
        0x5D9F, 0x6EBD, 0xEF43, 0xA6C4, 0xA839, 0xA431, 0x37D3, 0x8BF2,
        0x32D5, 0x438B, 0x596E, 0xB7DA, 0x8C01, 0x64B1, 0xD29C, 0xE049,
        0xB4D8, 0xFAAC, 0x07F3, 0x25CF, 0xAFCA, 0x8EF4, 0xE947, 0x1810,
        0xD56F, 0x88F0, 0x6F4A, 0x725C, 0x2438, 0xF157, 0xC773, 0x5197,
        0x23CB, 0x7CA1, 0x9CE8, 0x213E, 0xDD96, 0xDC61, 0x860D, 0x850F,
        0x90E0, 0x427C, 0xC471, 0xAACC, 0xD890, 0x0506, 0x01F7, 0x121C,
        0xA3C2, 0x5F6A, 0xF9AE, 0xD069, 0x9117, 0x5899, 0x273A, 0xB927,
        0x38D9, 0x13EB, 0xB32B, 0x3322, 0xBBD2, 0x70A9, 0x8907, 0xA733,
        0xB62D, 0x223C, 0x9215, 0x20C9, 0x4987, 0xFFAA, 0x7850, 0x7AA5,
        0x8F03, 0xF859, 0x8009, 0x171A, 0xDA65, 0x31D7, 0xC684, 0xB8D0,
        0xC382, 0xB029, 0x775A, 0x111E, 0xCB7B, 0xFCA8, 0xD66D, 0x3A2C,
    }
};

/***********************************************************************
 * Routine: Phase 1 -- generate P1K, given TA, TK, IV32
 *
 * Inputs:
 * TK[]					[128 bits]	= Temporal Key
 * TA[]					[ 48 bits]	= transmitter's MAC address
 * IV32					[ 32 bits]	= upper 32 bits of IV
 *
 * Output:
 *	  P1K[]				[ 80 bits]	= Phase 1 key
 *
 * Note:
 *	  This function only needs to be called every 2**16 frames,
 *	  although in theory it could be called every frame.
 *
 ***********************************************************************/
void Phase1(u_short * P1K, const u_char * TK, const u_char * TA, u_long IV32){
	int				i;
	/* Initialize the 80 bits of P1K[] from IV32 and TA[0..5]	  */
	P1K[0] = Lo16(IV32);
	P1K[1] = Hi16(IV32);
	P1K[2] = Mk16(TA[1], TA[0]);	/* use TA[] as little-endian */
	P1K[3] = Mk16(TA[3], TA[2]);
	P1K[4] = Mk16(TA[5], TA[4]);
	/* Now compute an unbalanced Feistel cipher with 80-bit block */
	/* size on the 80-bit block P1K[], using the 128-bit key TK[] */
	for (i = 0; i < PHASE1_LOOP_CNT; i++) {
		/* Each add operation here is mod 2**16 */
		P1K[0] += _S_(P1K[4] ^ TK16((i & 1) + 0));
		P1K[1] += _S_(P1K[0] ^ TK16((i & 1) + 2));
		P1K[2] += _S_(P1K[1] ^ TK16((i & 1) + 4));
		P1K[3] += _S_(P1K[2] ^ TK16((i & 1) + 6));
		P1K[4] += _S_(P1K[3] ^ TK16((i & 1) + 0));
		P1K[4] += i;	/* avoid "slide attacks" */
	}
}
/***********************************************************************
 * Routine: Phase 2 -- generate RC4KEY, given TK, P1K, IV16
 *
 * Inputs:
 * TK[]				[128 bits] = Temporal Key
 * P1K[]				[ 80 bits] = Phase 1 output key
 * IV16				[ 16 bits] = low 16 bits of IV counter
 *
 * Output:
 *	  RC4KEY[]		[128 bits]	= the key used to encrypt the frame
 *
 * Note:
 *	  The value {TA,IV32,IV16} for Phase1/Phase2 must be unique
 *	  across all frames using the same key TK value. Then, for a
 *	  given value of TK[], this TKIP48 construction guarantees that
 *	  the final RC4KEY value is unique across all frames.
 *
 * Suggested implementation optimization: if PPK[] is "overlaid"
 *	  appropriately on RC4KEY[], there is no need for the final
 *	  for loop below that copies the PPK[] result into RC4KEY[].
 *
 ***********************************************************************/
void Phase2(u_char * RC4KEY, const u_char * TK, const u_short * P1K, u_short IV16){
	int				i;
	u_short			PPK[6]; /* temporary key for mixing	   */
	/* all adds in the PPK[] equations below are mod 2**16		   */
	for (i = 0; i < 5; i++)
		PPK[i] = P1K[i];/* first, copy P1K to PPK */
	PPK[5] = P1K[4] + IV16; /* next,  add in IV16 */
	/* Bijective non-linear mixing of the 96 bits of PPK[0..5] */
	PPK[0] += _S_(PPK[5] ^ TK16(0));	/* Mix key in each "round" */
	PPK[1] += _S_(PPK[0] ^ TK16(1));
	PPK[2] += _S_(PPK[1] ^ TK16(2));
	PPK[3] += _S_(PPK[2] ^ TK16(3));
	PPK[4] += _S_(PPK[3] ^ TK16(4));
	PPK[5] += _S_(PPK[4] ^ TK16(5));	/* Total # S-box lookups == 6  */
    
	/* Final sweep: bijective, linear. Rotates kill LSB correlations */
	PPK[0] += RotR1(PPK[5] ^ TK16(6));
	PPK[1] += RotR1(PPK[0] ^ TK16(7));	/* Use all of TK[] in Phase2 */
	PPK[2] += RotR1(PPK[1]);
	PPK[3] += RotR1(PPK[2]);
	PPK[4] += RotR1(PPK[3]);
	PPK[5] += RotR1(PPK[4]);
	/* At this point, for a given key TK[0..15], the 96-bit output */
	/* value PPK[0..5] is guaranteed to be unique, as a function   */
	/* of the 96-bit "input" value	 {TA,IV32,IV16}. That is, P1K  */
	/* is now a keyed permutation of {TA,IV32,IV16}.			   */
	/* Set RC4KEY[0..3], which includes cleartext portion of RC4 key   */
	RC4KEY[0] = Hi8(IV16);	/* RC4KEY[0..2] is the WEP IV  */
	RC4KEY[1] = (Hi8(IV16) | 0x20) & 0x7F;	/* Help avoid FMS weak keys	 */
	RC4KEY[2] = Lo8(IV16);
	RC4KEY[3] = Lo8((PPK[5] ^ TK16(0)) >> 1);
	/* Copy 96 bits of PPK[0..5] to RC4KEY[4..15] (little-endian) */
	for (i = 0; i < 6; i++) {
		RC4KEY[4 + 2 * i] = Lo8(PPK[i]);
		RC4KEY[5 + 2 * i] = Hi8(PPK[i]);
	}
}
