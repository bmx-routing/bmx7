/*
 * Copyright (c) 2010  Axel Neumann
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

/*
 * Alternative cryptographic libraries are:
 * libtomcrypt and gcrypt
 */

//#define CRYPT_CYASSL
//#define CRYPT_POLARSSL


#define POLARSSL_MIN   1000
#define POLARSSL_1_2_5 1125
#define POLARSSL_1_2_9 1129
#define POLARSSL_1_3_3 1133
#define POLARSSL_1_3_4 1134
#define POLARSSL_1_3_9 1139
#define POLARSSL_MAX   1999
#define CYASSL_MIN     2000
#define CYASSL_2_8_0   2280
#define CYASSL_MAX     2999

#ifndef CRYPTLIB
#define CRYPTLIB POLARSSL_1_3_4
#endif

#define CRYPT_DER_BUF_SZ 16000

#define CRYPT_SHA1_LEN 20





#define CRYPT_KEY_N_MOD 128
#define CRYPT_KEY_E_VAL 65537




#define CRYPT_RSA512_TYPE  1
#define CRYPT_RSA512_LEN   64
#define CRYPT_RSA512_NAME  "RSA512"
#define CRYPT_RSA768_TYPE  2
#define CRYPT_RSA768_LEN   (768/8) //96
#define CRYPT_RSA768_NAME  "RSA768"
#define CRYPT_RSA896_TYPE  3
#define CRYPT_RSA896_LEN   (896/8) //112
#define CRYPT_RSA896_NAME  "RSA896"
#define CRYPT_RSA1024_TYPE 4
#define CRYPT_RSA1024_LEN  (1024/8) //128
#define CRYPT_RSA1024_NAME "RSA1024"
#define CRYPT_RSA1536_TYPE 5
#define CRYPT_RSA1536_LEN  (1536/8) //192
#define CRYPT_RSA1536_NAME "RSA1536"
#define CRYPT_RSA2048_TYPE 6
#define CRYPT_RSA2048_LEN  (2048/8) //256
#define CRYPT_RSA2048_NAME "RSA2048"
#define CRYPT_RSA3072_TYPE 7
#define CRYPT_RSA3072_LEN  (3072/8) //384
#define CRYPT_RSA3072_NAME "RSA3072"
#define CRYPT_RSA4096_TYPE 8
#define CRYPT_RSA4096_LEN  (4096/8) //512
#define CRYPT_RSA4096_NAME "RSA4096"

#define CRYPT_RSA_MIN_TYPE CRYPT_RSA512_TYPE
#define CRYPT_RSA_MAX_TYPE 8
#define CRYPT_RSA_MAX_LEN  512

#define CRYPT_DHM1024_TYPE 16 //DHM parameter defined in DHM_RFC2409_MODP_1024_P /_G
#define CRYPT_DHM1024_LEN  (1024/8) //128
#define CRYPT_DHM1024_NAME "DHM1024-112"
#define CRYPT_DHM2048_TYPE 17 //DHM parameter defined in DHM_RFC3526_MODP_2048_P /_G
#define CRYPT_DHM2048_LEN  (2048/8) //256
#define CRYPT_DHM2048_NAME "DHM2048-112"
#define CRYPT_DHM3072_TYPE 18 //DHM parameter defined in DHM_RFC3526_MODP_3072_P /_G
#define CRYPT_DHM3072_LEN  (3072/8)
#define CRYPT_DHM3072_NAME "DHM3072-112"

#define CRYPT_DHM_MIN_TYPE CRYPT_DHM1024_TYPE
#define CRYPT_DHM_MAX_TYPE CRYPT_DHM3072_TYPE
#define CRYPT_DHM_MAX_LEN CRYPT_DHM3072_LEN



typedef struct CRYPTSHA1_T {
	union {
		uint8_t u8[CRYPT_SHA1_LEN];
		uint32_t u32[CRYPT_SHA1_LEN/sizeof(uint32_t)];
	} h;
} CRYPTSHA1_T;

extern const CRYPTSHA1_T ZERO_CYRYPSHA1;


#define CRYPT_SHA112_BITSIZE 112
// 2^112=5.2e33!
// As of April 2016 the total cummulative number of bitcoin double-sha256 hashes is < 1e26 < 2^89 (source http://bitcoin.sipa.be/ ).
// Work for 2^89 double-sha256 == work for 2^90 single-sha256 (and single-sha224)
// Assuming a doubling of hash power per year I assume that 112 bits remains unfeasible for 112-90=22 more years!
// Note that HashChainAnchors and DhmKeys are renewed with description updates (e.g. every OGM_SQN_RANGE ogm intervals ~ every hour)

typedef struct CRYPTSHA112_T {
	uint8_t u8[CRYPT_SHA112_BITSIZE / 8];
} CRYPTSHA112_T;


typedef struct CRYPTRSA_T {
    TIME_SEC_T endOfLife;
	uint8_t rawKeyType;
	uint16_t rawKeyLen;
	//	uint8_t __nativeBackendKey;
	//	uint8_t *__rawKey;
	void *backendKey;
} CRYPTRSA_T;

extern const CRYPTRSA_T CYRYPTRSA_ZERO;

typedef struct CRYPTDHM_T {
	TIME_SEC_T endOfLife;
	uint16_t rawGXLen;
	uint8_t rawGXType;
	void *backendKey;
} CRYPTDHM_T;

uint8_t cryptDhmKeyTypeByLen(int len);
uint16_t cryptDhmKeyLenByType(int type);
char *cryptDhmKeyTypeAsString(int type);


void cryptDhmKeyFree(CRYPTDHM_T **cryptKey);
CRYPTDHM_T *cryptDhmKeyMake(uint8_t dhmSignType, uint8_t attempt);
CRYPTSHA1_T *cryptDhmSecretForNeigh(CRYPTDHM_T *myDhm, uint8_t *neighRawKey, uint16_t neighRawKeyLen);
void cryptDhmPubKeyGetRaw(CRYPTDHM_T* key, uint8_t* buff, uint16_t buffLen);

#ifndef NO_KEY_GEN
int cryptRsaKeyMakeDer(int32_t keyType, char *path);
CRYPTRSA_T *cryptRsaKeyMake(uint8_t keyType);
#endif


CRYPTRSA_T *cryptRsaKeyFromDer(char *tmp_path);
CRYPTRSA_T *cryptRsaPubKeyFromRaw(uint8_t *rawKey, uint16_t rawKeyLen);
int cryptRsaPubKeyGetRaw(CRYPTRSA_T *key, uint8_t *buff, uint16_t buffLen);
int cryptRsaPubKeyCheck(CRYPTRSA_T *pubKey);


void cryptRsaKeyFree(CRYPTRSA_T **key);

int cryptRsaEncrypt(uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen, CRYPTRSA_T *pubKey);
int cryptRsaDecrypt(uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);
int cryptRsaSign(CRYPTSHA1_T *inSha, uint8_t *out, size_t outLen, CRYPTRSA_T *cryptKey);
int cryptRsaVerify(uint8_t *sign, size_t signLen, CRYPTSHA1_T *sha, CRYPTRSA_T *pubKey);
uint8_t cryptRsaKeyTypeByLen(int len);
uint16_t cryptRsaKeyLenByType(int type);
char *cryptRsaKeyTypeAsString(int type);



void cryptRand(void *out, uint32_t outLen);

void cryptShaAtomic( void *in, int32_t len, CRYPTSHA1_T *sha);
void cryptShaNew( void *in, int32_t len);
void cryptShaUpdate( void *in, int32_t len);
void cryptShaFinal( CRYPTSHA1_T *sha);

char *cryptShaAsString( CRYPTSHA1_T *sha);
char *cryptShaAsShortStr( CRYPTSHA1_T *sha);

int cryptShasEqual( CRYPTSHA1_T *sha1, CRYPTSHA1_T *sha2);




void init_crypt(void);
void cleanup_crypt(void);

