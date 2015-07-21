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
#define POLARSSL_MAX   1999
#define CYASSL_MIN     2000
#define CYASSL_2_8_0   2280
#define CYASSL_MAX     2999

#ifndef CRYPTLIB
#define CRYPTLIB POLARSSL_1_3_4
#endif

#define CRYPT_DER_BUF_SZ 16000

#define CRYPT_KEY_N_MOD 128
#define CRYPT_KEY_N_MAX 4096
#define CRYPT_KEY_E_VAL 65537

#define CRYPT_SHA1_LEN 20

#define CRYPT_RSA_MIN_TYPE 1
#define CRYPT_RSA_MIN_LEN  64
#define CRYPT_RSA_MIN_NAME "RSA512"
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
#define CRYPT_RSA1024_LEN  128
#define CRYPT_RSA1024_NAME "RSA1024"
#define CRYPT_RSA1536_TYPE 5
#define CRYPT_RSA1536_LEN  (1536/8) //192
#define CRYPT_RSA1536_NAME "RSA1536"
#define CRYPT_RSA2048_TYPE 6
#define CRYPT_RSA2048_LEN  256
#define CRYPT_RSA2048_NAME "RSA2048"
#define CRYPT_RSA3072_TYPE 7
#define CRYPT_RSA3072_LEN  (3072/8) //384
#define CRYPT_RSA3072_NAME "RSA3072"
#define CRYPT_RSA4096_TYPE 8
#define CRYPT_RSA4096_LEN  512
#define CRYPT_RSA4096_NAME "RSA4096"
#define CRYPT_RSA_MAX_TYPE 8
#define CRYPT_RSA_MAX_LEN  512
#define CRYPT_RSA_MAX_NAME "RSA4096"


typedef struct CRYPTSHA1_T {
	union {
		uint8_t u8[CRYPT_SHA1_LEN];
		uint32_t u32[CRYPT_SHA1_LEN/sizeof(uint32_t)];
	} h;
} CRYPTSHA1_T;

extern const CRYPTSHA1_T ZERO_CYRYPSHA1;

typedef struct CRYPTKEY_T {
    TIME_SEC_T endOfLife;
    void *backendKey;
    uint16_t rawKeyLen;
    uint8_t nativeBackendKey;
    uint8_t rawKeyType;
    uint8_t *rawKey;
} CRYPTKEY_T;

extern const CRYPTKEY_T CYRYPTKEY_ZERO;

#ifndef NO_KEY_GEN
int cryptKeyMakeDer( int32_t keyBitSize, char *path );
CRYPTKEY_T *cryptKeyMake( int32_t keyBitSize );
#endif

CRYPTKEY_T *cryptKeyFromDer( char *tmp_path );
CRYPTKEY_T *cryptPubKeyFromRaw( uint8_t *rawKey, uint16_t rawKeyLen );
int cryptPubKeyCheck( CRYPTKEY_T *pubKey);

void cryptKeyFree( CRYPTKEY_T **key );

int cryptEncrypt( uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen, CRYPTKEY_T *pubKey);
int cryptDecrypt(uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen);
int cryptSign( CRYPTSHA1_T *inSha, uint8_t *out, size_t outLen, CRYPTKEY_T *cryptKey);
int cryptVerify(uint8_t *sign, size_t signLen, CRYPTSHA1_T *sha, CRYPTKEY_T *pubKey);

void cryptRand( void *out, int32_t outLen);

void cryptShaAtomic( void *in, int32_t len, CRYPTSHA1_T *sha);
void cryptShaNew( void *in, int32_t len);
void cryptShaUpdate( void *in, int32_t len);
void cryptShaFinal( CRYPTSHA1_T *sha);

char *cryptShaAsString( CRYPTSHA1_T *sha);
char *cryptShaAsShortStr( CRYPTSHA1_T *sha);

int cryptShasEqual( CRYPTSHA1_T *sha1, CRYPTSHA1_T *sha2);

int cryptKeyTypeByLen(int len);
int cryptKeyLenByType(int type);
char *cryptKeyTypeAsString(int type);



void init_crypt(void);
void cleanup_crypt(void);

