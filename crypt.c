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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "tools.h"
#include "allocate.h"

const CRYPTSHA1_T ZERO_CYRYPSHA1 = { .h.u32 = {0} };
const CRYPTRSA_T CYRYPTRSA_ZERO = {.backendKey = NULL};

static uint8_t shaClean = NO;

static CRYPTRSA_T *my_PrivKey = NULL;

/******************* accessing cyassl: ***************************************/
#if CRYPTLIB >= CYASSL_MIN && CRYPTLIB <= CYASSL_MAX

#define XKEY_DP_SZ sizeof( mp_digit)

#ifndef NO_KEY_GEN
#define CYASSL_KEY_GEN
#endif

#ifdef NO_CTAOCRYPT_DIR
#include <cyassl/sha.h>
#include <cyassl/rsa.h>
#include <cyassl/asn.h>
#else
//#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/rsa.h>
//#include <cyassl/ctaocrypt/asn_public.h>
#include <cyassl/ctaocrypt/asn.h>
//#include <cyassl/ctaocrypt/ecc.h>
//#include <cyassl/ssl.h>
#endif

RNG cryptRng;
Sha cryptSha;

STATIC_FUNC
void * clone_to_nbo(void *in, uint32_t len) {

	uint32_t i;

	if ( htonl(47) == 47 )
		return in;

	uint8_t *out = debugMallocReset(len, -300601);

	for (i=0; i<len; i++)
		out[i] = ((uint8_t*)in)[len-i-1];

	return out;
}


STATIC_FUNC
uint8_t * mp_int_get_raw( mp_int *in, uint16_t *rawLen) {

	int s = XKEY_DP_SZ;
	int u = in->used;
	*rawLen = ( ( ((s*u*8)-((u)*4)) / CRYPT_KEY_N_MOD ) * CRYPT_KEY_N_MOD) / 8;
	int w = ((*rawLen*8) / ((s*8)-4)) + (((*rawLen*8) % ((s*8)-4)) ? 1 : 0);
	int zeros = (s*u)-(*rawLen);

	assertion(-502018, (u == w));

	mp_digit *nbo = clone_to_nbo(in->dp, (u*s));
	mp_digit *tmp = debugMallocReset(u*s, -300602);

	dbgf_sys(DBGT_INFO, "s=%d u=%d (nbo==in->dp)=%d rawLen=%d w=%d zeros=%d", s, u, (nbo==in->dp), *rawLen, w, zeros );
	dbgf_sys(DBGT_INFO, " in:\n%s", memAsHexStringSep( in->dp, (u*s), 16, "\n"));

	int i = u-1; // i:= u-1 .. 0
	int r = 0;   // r:= 0 .. u-1
	while (i>=0) {
		if (s==8) {
			*((uint64_t*)(((uint8_t*)&(tmp[i]))+(r/2))) = nbo[i];
			if (i>=1)
				*((uint64_t*)(((uint8_t*)&(tmp[i-1]))+1+(r/2))) = htobe64( (be64toh(nbo[i-1])<<4) | (be64toh(nbo[i])>>((s-1)*8)));
		} else if (s==4) {
			*((uint32_t*)(((uint8_t*)&(tmp[i]))+(r/2))) = nbo[i];
			if (i>=1)
				*((uint32_t*)(((uint8_t*)&(tmp[i-1]))+1+(r/2))) = htobe32( (be32toh(nbo[i-1])<<4) | (be32toh(nbo[i])>>((s-1)*8)));
		} else {
			cleanup_all(-502019);
		}
		i-=2;
		r+=2;
	}

	if (nbo != in->dp)
		debugFree(nbo, -300603);

	uint8_t *begin = ((uint8_t*)tmp) + zeros;
	
	uint8_t *raw = debugMalloc(*rawLen, -300604);
	memcpy(raw, begin, *rawLen);
	
	dbgf_sys(DBGT_INFO, "raw:\n%s", memAsHexStringSep( raw, *rawLen, 16, "\n"));

	assertion(-502020, (*rawLen >= (CRYPT_KEY_N_MOD/8))); // too small key!?
	assertion(-502021, (!is_zero( begin, 4))); // strange key with 4 leading octets!
	assertion(-502022, (is_zero(tmp, zeros)));

	debugFree(tmp, -300605);


	return raw;
}

STATIC_FUNC
int mp_int_put_raw( mp_int *out, uint8_t *raw, uint32_t rawLen) {

	int s = XKEY_DP_SZ;
	int u = ((rawLen*8) / ((s*8)-4)) + (((rawLen*8) % ((s*8)-4)) ? 1 : 0);
	int zeros = (s*u)-(rawLen);

	mp_digit *in  = debugMallocReset(u*s, -300606);
	memcpy( (((uint8_t*)in)+zeros), raw, rawLen );

	mp_digit *tmp = debugMallocReset(u*s, -300607);

	int i = u-1; // i:= u-1 .. 0
	int r = 0;   // r:= 0 .. u-1
	while (i>=0) {
		if (s==8) {
			tmp[i] = htobe64( ((be64toh( *((uint64_t*)(((uint8_t*)&(in[i]))+(r/2)))))<<4)>>4 );

			if (i>=1)
				tmp[i-1] = htobe64( (be64toh(*((uint64_t*)(((uint8_t*)&(in[i-1]))+1+(r/2)))))>>4);

		} else if (s==4) {

			tmp[i] = htobe32( ((be32toh( *((uint32_t*)(((uint8_t*)&(in[i]))+(r/2)))))<<4)>>4 );

			if (i>=1)
				tmp[i-1] = htobe32( (be32toh(*((uint32_t*)(((uint8_t*)&(in[i-1]))+1+(r/2)))))>>4);
			
		} else {
			cleanup_all(-502023);
		}
		i-=2;
		r+=2;
	}

	debugFree(in, -300608);
	dbgf_all(DBGT_INFO, "tmp:\n%s", memAsHexStringSep( tmp, (u*s), 16, "\n"));

	out->dp = clone_to_nbo(tmp, (u*s));

	dbgf_all(DBGT_INFO, "out:\n%s", memAsHexStringSep( out->dp, (u*s), 16, "\n"));

	if (out->dp != tmp)
		debugFree(tmp, -300609);

	return u;
}







void cryptRsaKeyFree( CRYPTRSA_T **cryptKey ) {

	if (!*cryptKey)
		return;

	if ((*cryptKey)->backendKey) {

		RsaKey *key = (*cryptKey)->backendKey;

		if ((*cryptKey)->nativeBackendKey) {
			FreeRsaKey(key);
		} else {
			debugFree(key->n.dp, -300610);
			debugFree(key->e.dp, -300611);
		}

		debugFree((*cryptKey)->backendKey, -300612);
	}

	if ((*cryptKey)->rawKey) {
		debugFree((*cryptKey)->rawKey, -300613);
	}

	debugFree( (*cryptKey), -300614);

	cryptKey = NULL;
}


CRYPTRSA_T *cryptRsaPubKeyFromRaw( uint8_t *rawKey, uint16_t rawKeyLen ) {

	CRYPTRSA_T *cryptKey = debugMallocReset(sizeof(CRYPTRSA_T), -300615);

	assertion(-502024, (rawKey && cryptRsaKeyTypeByLen(rawKeyLen)));

	cryptKey->nativeBackendKey = 0;
	cryptKey->backendKey = debugMalloc(sizeof(RsaKey), -300616);
	RsaKey *key = cryptKey->backendKey;

	key->type = RSA_PUBLIC;

	key->e.dp = debugMallocReset(sizeof (mp_digit) * 4, -300617);
	key->e.dp[0] = CRYPT_KEY_E_VAL;
	key->e.alloc = 4;
	key->e.used  = 1;
	key->e.sign  = MP_ZPOS;

	int used = mp_int_put_raw( &key->n, rawKey, rawKeyLen );
	key->n.alloc = used;
	key->n.used  = used;
	key->n.sign  = MP_ZPOS;

	cryptKey->rawKeyLen = rawKeyLen;
	cryptKey->rawKeyType = cryptRsaKeyTypeByLen(rawKeyLen);
	cryptKey->rawKey = debugMalloc(rawKeyLen,-300618);
	memcpy(cryptKey->rawKey, rawKey, rawKeyLen);

	return cryptKey;
}

STATIC_FUNC
void cryptKeyAddRaw( CRYPTRSA_T *cryptKey) {

	assertion(-502025, (cryptKey->backendKey && !cryptKey->rawKey));

	RsaKey *key = cryptKey->backendKey;
	int keyNLen = (key->n.used * XKEY_DP_SZ);
	int keyELen = (key->e.used * XKEY_DP_SZ);

	dbgf_sys(DBGT_INFO, "type=%d",key->type);
	dbgf_sys(DBGT_INFO, "pub N: alloc=%d sign=%d used=%d sizeof=%d len=%d bits=%d",
		key->n.alloc, key->n.sign, key->n.used, XKEY_DP_SZ, keyNLen, keyNLen*8 );

	dbgf_sys(DBGT_INFO, "pub E: alloc=%d sign=%d used=%d sizeof=%d len=%d bits=%d E:\n%s",
		key->e.alloc, key->e.sign, key->e.used, XKEY_DP_SZ, keyELen, keyELen*8,
		memAsHexStringSep( key->e.dp, keyELen, 4, NULL));

	dbgf_sys(DBGT_INFO, "E=%d", (uint32_t)key->e.dp[0]);

	assertion(-502026, (key->type == RSA_PUBLIC || key->type == RSA_PRIVATE));
	assertion(-502027, (key->e.dp[0] == CRYPT_KEY_E_VAL));

	cryptKey->rawKey = mp_int_get_raw(&key->n, &cryptKey->rawKeyLen);
	cryptKey->rawKeyType = cryptRsaKeyTypeByLen(cryptKey->rawKeyLen);


#ifndef NO_ASSERTIONS
	CRYPTRSA_T *test = cryptRsaPubKeyFromRaw(cryptKey->rawKey, cryptKey->rawKeyLen);
	assertion(-502028, !memcmp(((RsaKey*)(cryptKey->backendKey))->n.dp, ((RsaKey*)(test->backendKey))->n.dp, (((RsaKey*)(cryptKey->backendKey))->n.used * XKEY_DP_SZ)));
	cryptRsaKeyFree(&test);
#endif
}




CRYPTRSA_T *cryptRsaKeyFromDer( char *tmp_path ) {

	uint8_t der[CRYPT_DER_BUF_SZ];
	int derSz = 0;
	FILE* keyFile;
	int    ret;
	word32 idx = 0;
	
	assertion(-502029, (!my_PrivKey));

	if (!(keyFile = fopen(tmp_path, "rb"))) {
		dbgf_sys(DBGT_ERR, "can not open %s: %s", tmp_path, strerror(errno));
		return NULL;
	}

	if(((derSz = (int)fread(der, 1, sizeof(der), keyFile)) <= 0) || derSz == sizeof(der)) {
		dbgf_sys(DBGT_ERR, "can not read %s: %s", tmp_path, strerror(errno));
		return NULL;
	} else {
		dbgf_sys(DBGT_INFO, "read %d bytes from %s", derSz, tmp_path);
	}

	fclose(keyFile);

	CRYPTRSA_T *ckey = debugMallocReset(sizeof(CRYPTRSA_T), -300619);

	ckey->backendKey = debugMalloc(sizeof(RsaKey), -300620);
	ckey->nativeBackendKey = 1;
	InitRsaKey((RsaKey*)ckey->backendKey, 0);

	if ((ret = RsaPrivateKeyDecode(der, &idx, (RsaKey*)ckey->backendKey, derSz)) != 0) {
		dbgf_sys(DBGT_ERR, "can not decode ret=%d", ret);
		return NULL;
	}

	cryptKeyAddRaw(ckey);

	my_PrivKey = ckey;

	return cryptRsaPubKeyFromRaw( my_PrivKey->__rawKey, my_PrivKey->rawKeyLen );

}

#ifndef NO_KEY_GEN
int cryptRsaKeyMakeDer( int32_t keyType, char *tmp_path ) {

	int32_t keyBitSize = (cryptRsaKeyLenByType(keyType) * 8);
	RsaKey *key = debugMalloc(sizeof(RsaKey), -300621);
	FILE* keyFile;
	uint8_t der[CRYPT_DER_BUF_SZ];
	int derSz = CRYPT_DER_BUF_SZ;
	int ret;

	InitRsaKey(key, 0);

	if ((ret = MakeRsaKey(key, keyBitSize, CRYPT_KEY_E_VAL, &cryptRng)) != 0) {
		dbgf_sys(DBGT_ERR, "Failed making rsa key! ret=%d", ret);
		return FAILURE;
	}

	dbgf_sys(DBGT_INFO, "NEW Key: alloc=%d sign=%d used=%d sizeof=%ld len=%ld bits=%ld N:\n%s",
		key->n.alloc, key->n.sign, key->n.used, XKEY_DP_SZ, (key->n.used * XKEY_DP_SZ), (key->n.used * XKEY_DP_SZ)*8,
		memAsHexStringSep( key->n.dp, (key->n.used * XKEY_DP_SZ), 16, "\n")
		);

	if ((derSz = RsaKeyToDer(key, der, derSz)) < 0) {
		dbgf_sys(DBGT_ERR, "Failed translating rsa key to der! derSz=%d", derSz)
		return FAILURE;
	}
	
	// alternatively create private der encoded key with openssl:
	// openssl genrsa -out /etc/bmx7/rsa.pem 1024
	// openssl rsa -in /etc/bmx7/rsa.pem -inform PEM -out /etc/bmx7/rsa.der -outform DER
	//
	// read this with:
	//    dumpasn1 key.der
	//    note that all first INTEGER bytes are not zero (unlike with openssl certificates), but after conversion they are.
	// convert to pem with openssl:
	//    openssl rsa -in rsa-test/key.der -inform DER -out rsa-test/openssl.pem -outform PEM
	// extract public key with openssl:
	//    openssl rsa -in rsa-test/key.der -inform DER -pubout -out rsa-test/openssl.der.pub -outform DER

	FreeRsaKey(key);


	if (!(keyFile = fopen(tmp_path, "wb")) || ((int)fwrite(der, 1, derSz, keyFile)) != derSz ) {
		dbgf_sys(DBGT_ERR, "Failed writing %s!", tmp_path);
		return FAILURE;
	}


	fclose(keyFile);
	return SUCCESS;
}
#endif

int cryptRsaEncrypt( uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen, CRYPTRSA_T *pubKey) {

	RsaKey *key = pubKey->backendKey;

	int ret;

	if ((ret = RsaPublicEncrypt(in, inLen, out, *outLen, key, &cryptRng)) < 0)
		return FAILURE;

	*outLen = ret;
	return SUCCESS;
}

int cryptRsaDecrypt(uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen) {

	int ret;

	if ((ret = RsaPrivateDecrypt(in, inLen, out, *outLen, (RsaKey *)my_PrivKey->backendKey)) < 0)
		return FAILURE;

	*outLen = ret;
	return SUCCESS;
}

int cryptRsaSign( CRYPTSHA1_T *inSha, uint8_t *out, size_t outLen, CRYPTRSA_T *cryptKey) {

	if (!cryptKey)
		cryptKey = my_PrivKey;

	if (outLen != cryptKey->rawKeyLen)
		return FAILURE;

	if ((RsaSSL_Sign((uint8_t*)inSha, sizeof(CRYPTSHA1_T), out, outLen, (RsaKey *)cryptKey->backendKey, &cryptRng)) < 0)
		return FAILURE;

	return SUCCESS;
}

int cryptRsaVerify(uint8_t *sign, size_t signLen, CRYPTSHA1_T *sha, CRYPTRSA_T *pubKey) {

	RsaKey *key = pubKey->backendKey;
	CRYPTSHA1_T signSha;

	if (RsaSSL_Verify(sign, signLen, (uint8_t*)&signSha, sizeof(CRYPTSHA1_T), key) != sizeof(CRYPTSHA1_T) ||
		memcmp(&signSha, sha, sizeof(CRYPTSHA1_T) ))
		return FAILURE;
	
	return SUCCESS;
}

STATIC_FUNC
void cryptRngInit( void ) {

	if ((InitRng(&cryptRng)) != 0)
		cleanup_all(-500525);
}

STATIC_FUNC
void cryptRngFree( void ) {
}

void cryptRand( void *out, int32_t outLen) {
	RNG_GenerateBlock(&cryptRng, (byte*)out, outLen);
}


STATIC_FUNC
void cryptShaInit( void ) {
	InitSha(&cryptSha);
	shaClean = YES;
}

STATIC_FUNC
void cryptShaFree( void ) {
}

void cryptShaAtomic( void *in, int32_t len, CRYPTSHA1_T *sha) {

	assertion(-502030, (shaClean==YES));
	assertion(-502031, (sha));
	assertion(-502032, (in && len>0 && !memcmp(in, in, len)));

	ShaUpdate(&cryptSha, (byte*) in, len);
	ShaFinal(&cryptSha, (byte*) sha);
}

void cryptShaNew( void *in, int32_t len) {

	assertion(-502033, (shaClean==YES));
	assertion(-502034, (in && len>0 && !memcmp(in, in, len)));
	shaClean = NO;
	ShaUpdate(&cryptSha, (byte*) in, len);
}

void cryptShaUpdate( void *in, int32_t len) {

	assertion(-502035, (shaClean==NO));
	assertion(-502036, (in && len>0 && !memcmp(in, in, len)));
	ShaUpdate(&cryptSha, (byte*)in, len);
}

void cryptShaFinal( CRYPTSHA1_T *sha) {

	assertion(-502037, (shaClean==NO));
	assertion(-502038, (sha));
	ShaFinal(&cryptSha, (byte*) sha);
	shaClean = YES;
}


#elif CRYPTLIB >= POLARSSL_MIN && CRYPTLIB <= POLARSSL_MAX
/******************* accessing polarssl: *************************************/

#include "polarssl/config.h"
#include "polarssl/sha1.h"

#include "polarssl/entropy.h"
//#include "polarssl/entropy_poll.h"

#include "polarssl/error.h"
#include "polarssl/md.h"
#include "polarssl/dhm.h"
#include "polarssl/rsa.h"
#include "polarssl/ctr_drbg.h"

#include "polarssl/x509.h"
#if CRYPTLIB <= POLARSSL_1_2_9
#include "polarssl/x509write.h"
#elif CRYPTLIB >= POLARSSL_1_3_3
#include "polarssl/pk.h"
#endif

static entropy_context entropy_ctx;
static ctr_drbg_context ctr_drbg;

static sha1_context sha_ctx;


uint8_t cryptDhmKeyTypeByLen(int len) {
	return 	len == CRYPT_DHM1024_LEN ? CRYPT_DHM1024_TYPE : (
		len == CRYPT_DHM2048_LEN ? CRYPT_DHM2048_TYPE : (
		len == CRYPT_DHM3072_LEN ? CRYPT_DHM3072_TYPE : (
		0 )));
}

uint16_t cryptDhmKeyLenByType(int type) {
	return 	type == CRYPT_DHM1024_TYPE ? CRYPT_DHM1024_LEN : (
		type == CRYPT_DHM2048_TYPE ? CRYPT_DHM2048_LEN : (
		type == CRYPT_DHM3072_TYPE ? CRYPT_DHM3072_LEN : (
		0 )));
}

char *cryptDhmKeyTypeAsString(int type) {
	return 	type == CRYPT_DHM1024_TYPE ? CRYPT_DHM1024_NAME : (
		type == CRYPT_DHM2048_TYPE ? CRYPT_DHM2048_NAME : (
		type == CRYPT_DHM3072_TYPE ? CRYPT_DHM3072_NAME : (
		NULL )));
}


void cryptDhmKeyFree( CRYPTDHM_T **cryptKey ) {

	if (!*cryptKey)
		return;

	if ((*cryptKey)->backendKey) {
		dhm_free((dhm_context*)((*cryptKey)->backendKey));
		debugFree((*cryptKey)->backendKey, -300828);
	}


	debugFree( (*cryptKey), -300614);

	*cryptKey = NULL;
}

/*
 * Verify sanity of parameter with regards to P
 *
 * Parameter should be: 2 <= public_param <= P - 2
 *
 * For more information on the attack, see:
 *  http://www.cl.cam.ac.uk/~rja14/Papers/psandqs.pdf
 *  http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2005-2643
 */
static int _cryptDhmCheckRange(const mpi *param, const mpi *P)
{
	mpi L, U;
	int ret = FAILURE; //POLARSSL_ERR_DHM_BAD_INPUT_DATA;

	mpi_init(&L);
	mpi_init(&U);

	if (
		mpi_lset(&L, 2) == 0 &&
		mpi_sub_int(&U, P, 2) == 0 &&
		mpi_cmp_mpi(param, &L) >= 0 &&
		mpi_cmp_mpi(param, &U) <= 0) {

		ret = SUCCESS;
	}

	mpi_free(&L);
	mpi_free(&U);
	return( ret);
}


CRYPTDHM_T *cryptDhmKeyMake( uint8_t keyType, uint8_t attempt) {

	int ret = 0;
	char *goto_error_code = NULL;
	int keyLen = 0;
	CRYPTDHM_T *key = debugMallocReset(sizeof(CRYPTDHM_T), -300829);
	dhm_context *dhm = debugMallocReset(sizeof(dhm_context), -300830);
	char *pptr = NULL;
	char *gptr = NULL;;
	int pSize = 0;
	int xSize = 0;
	int gxSize = 0;
	int count = 0;

#if CRYPTLIB >= POLARSSL_1_3_9
	// in older versions, if dhm_init() exist, it only zero-memsets the dhm context
	dhm_init( dhm );
#endif
	key->backendKey = dhm;

	if (!(keyType))
		goto_error(finish, "Missing type");
	if ((keyLen = cryptDhmKeyLenByType(keyType)) <= 0)
		goto_error(finish, "Invalid size");

	if( keyType == CRYPT_DHM1024_TYPE) {
		pptr = POLARSSL_DHM_RFC5114_MODP_1024_P;
		gptr = POLARSSL_DHM_RFC5114_MODP_1024_G;
	} else if (keyType == CRYPT_DHM2048_TYPE) {
		pptr = POLARSSL_DHM_RFC3526_MODP_2048_P;
		gptr = POLARSSL_DHM_RFC3526_MODP_2048_G;
	} else if (keyType == CRYPT_DHM3072_TYPE) {
		pptr = POLARSSL_DHM_RFC3526_MODP_3072_P;
		gptr = POLARSSL_DHM_RFC3526_MODP_3072_G;
	} else {
		goto_error(finish, "Unsupported dhm type!");
	}

	if ((ret = mpi_read_string(&dhm->P, 16, pptr)) != 0 || (ret = mpi_read_string(&dhm->G, 16, gptr)) != 0)
		goto_error(finish, "Failed setting dhm parameters!");

	if (mpi_cmp_int(&dhm->P, 0) == 0)
		goto_error(finish, "Empty dhm->P");

	// Generate X as large as possible ( < P )
	if ((pSize = mpi_size(&dhm->P)) != keyLen)
		goto_error(finish, "Invalid P size");

	do {
		if ((ret = mpi_fill_random(&dhm->X, pSize, ctr_drbg_random, &ctr_drbg)) != 0)
			goto_error(finish, "Failed allocating randomness");

		while( mpi_cmp_mpi( &dhm->X, &dhm->P ) >= 0 ) {
			if ((ret = mpi_shift_r(&dhm->X, 1)) != 0)
				goto_error(finish, "Failed shifting dhm->X param");
		}

		if ((ret = count++) > 10)
			goto_error(finish, "Failed creating dhm->X param");

	} while ((ret = _cryptDhmCheckRange(&dhm->X, &dhm->P)) != SUCCESS);

	// Calculate GX = G^X mod P
	if (mpi_exp_mod(&dhm->GX, &dhm->G, &dhm->X, &dhm->P, &dhm->RP) != 0)
		goto_error(finish, "Failed creating GX modulo");
	if (((int) (dhm->len = mpi_size(&dhm->P))) != keyLen)
		goto_error(finish, "Invalid len");
	if ((xSize = mpi_size(&dhm->X)) != keyLen)
		goto_error(finish, "Invalid X size");
	if ((gxSize = mpi_size(&dhm->GX)) != keyLen)
		goto_error(finish, "Invalid GX size");
	if ((ret=_cryptDhmCheckRange(&dhm->GX, &dhm->P)) != SUCCESS)
		goto_error(finish, "Invalid GX range");

	key->rawGXType = keyType;
	key->rawGXLen = keyLen;

finish:
	dbgf(goto_error_code ? DBGL_SYS : DBGL_CHANGES, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s ret=%d keyType=%d keyLen=%d pSize=%d xSize=%d gxSize=%d count=%d attempt=%d",
		goto_error_code, ret, keyType, keyLen, pSize, xSize, gxSize, count, attempt);

	if (goto_error_code) {
		cryptDhmKeyFree(&key);

		if ((++attempt) < 10)
			return cryptDhmKeyMake(keyType, attempt);

		assertion(-502718, (0));
		return NULL;
	}

	return key;
}

void cryptDhmPubKeyGetRaw(CRYPTDHM_T* key, uint8_t* buff, uint16_t buffLen)
{
	assertion_dbg(-502719, (key && buff && buffLen && key->rawGXType && buffLen == key->rawGXLen),
		"Failed: key=%d buff=%d buffLen=%d key.GXLen=%d", !!key, !!buff, buffLen, key ? key->rawGXLen : 0);

	dhm_context *dhm = key->backendKey;

	assertion_dbg(-502720, (dhm && buffLen == mpi_size(&dhm->GX) && buffLen == dhm->len),
		"Failed: dhm.GXlen=%d dhm.len=%d", dhm ? mpi_size(&dhm->GX) : 0, dhm ? dhm->len : 0);

	mpi_write_binary(&dhm->GX, buff, key->rawGXLen);
}


STATIC_FUNC
IDM_T cryptDhmKeyCheck(CRYPTDHM_T *key)
{
	char *goto_error_code = NULL;
	dhm_context *dhm = NULL;
	uint8_t keyType = 0;
	int keyLen = 0;
	int pSize = 0;
	int xSize = 0;
	int gxSize = 0;
	int gySize = 0;

	if (!(dhm = (dhm_context *) key->backendKey))
		goto_error(finish, "Missing backend key");
	if (!(keyType = key->rawGXType))
		goto_error(finish, "Missing type");
	if ((keyLen = cryptDhmKeyLenByType(keyType)) <= 0)
		goto_error(finish, "Invalid size");
	if ((int)dhm->len != keyLen)
		goto_error(finish, "Invalid len");
	if ((pSize = mpi_size(&dhm->P)) != keyLen)
		goto_error(finish, "Invalid P size");
	if ((xSize = mpi_size(&dhm->X)) != keyLen)
		goto_error(finish, "Invalid X size");
	if ((gxSize = mpi_size(&dhm->GX)) != keyLen)
		goto_error(finish, "Invalid GX size");
	if ((gySize = mpi_size(&dhm->GY)) != keyLen)
		goto_error(finish, "Invalid GY size");
	if (_cryptDhmCheckRange(&dhm->GX, &dhm->P) != SUCCESS)
		goto_error(finish, "Invalid GX range");
	if (_cryptDhmCheckRange(&dhm->GY, &dhm->P) != SUCCESS)
		goto_error(finish, "Invalid GY range");

	return SUCCESS;

finish:
	dbgf_track(DBGT_WARN, "%s keyType=%d keyLen=%d dhmLen=%d pSize=%d xSize=%d gxSize=%d gySize=%d",
		goto_error_code, keyType, keyLen, dhm ? dhm->len : 0, pSize, xSize, gxSize, gySize);

	return FAILURE;
}

CRYPTSHA1_T *cryptDhmSecretForNeigh(CRYPTDHM_T *myDhm, uint8_t *neighRawKey, uint16_t neighRawKeyLen)
{
	char *goto_error_code = NULL;
	uint8_t keyType = 0;
	int ret = 0;
	CRYPTSHA1_T *secret = NULL;
	dhm_context *dhm = NULL;
	uint8_t buff[CRYPT_DHM_MAX_LEN];
	size_t n = 0;

	if (!myDhm || !(dhm = myDhm->backendKey) || !myDhm->rawGXType)
		goto_error(finish, "Disabled dhm link signing");

	if (((keyType = cryptDhmKeyTypeByLen(neighRawKeyLen)) != myDhm->rawGXType) || ((n = dhm->len) != neighRawKeyLen) || (sizeof(buff) < neighRawKeyLen))
		goto_error(finish, "Wrong type or keyLength");

	if ((ret = mpi_read_binary(&dhm->GY, neighRawKey, neighRawKeyLen)) != 0)
		goto_error(finish, "Invalid GY");

	if (cryptDhmKeyCheck(myDhm) != SUCCESS)
		goto_error(finish, "Failed key check");

	if ((ret = dhm_calc_secret(dhm, buff, &n, ctr_drbg_random, &ctr_drbg)) != 0)
		goto_error(finish, "Failed calculating secret");

	if (n > neighRawKeyLen || n < ((neighRawKeyLen / 4)*3))
		goto_error(finish, "Unexpected secret length");

	secret = debugMallocReset(sizeof(CRYPTSHA1_T), -300831);
	cryptShaAtomic(buff, n, secret);

	
finish:{
	dbgf(((goto_error_code || n != neighRawKeyLen) ? DBGL_SYS : DBGL_CHANGES), ((goto_error_code || n != neighRawKeyLen) ? DBGT_WARN : DBGT_INFO),
		"%s n=%d neighKeyLen=%d myKeyLen=%d", goto_error_code, n, neighRawKeyLen, myDhm->rawGXLen);

	mpi_free(&dhm->GY);
	mpi_free(&dhm->K);
	memset(buff, 0, sizeof(buff));
	return secret;
}
}


void cryptRsaKeyFree( CRYPTRSA_T **cryptKey ) {

	if (!*cryptKey)
		return;

	if ((*cryptKey)->backendKey) {
		rsa_free((rsa_context*)((*cryptKey)->backendKey));
		debugFree((*cryptKey)->backendKey, -300612);
	}

//	if ((*cryptKey)->__rawKey) {
//		debugFree((*cryptKey)->__rawKey, -300613);
//	}

	debugFree( (*cryptKey), -300614);

	*cryptKey = NULL;
}

int cryptRsaPubKeyGetRaw(CRYPTRSA_T *key, uint8_t *buff, uint16_t buffLen) {
	
	rsa_context *rsa;
	if (!key || !buff || !buffLen ||
		!key->rawKeyType || (buffLen != key->rawKeyLen) ||
		!(rsa=(rsa_context*)key->backendKey) || buffLen != mpi_size(&rsa->N) || buffLen != rsa->len ) {
		
		return FAILURE;
	}
	
	if (mpi_write_binary(&rsa->N, buff, buffLen) != 0)
		return FAILURE;

	return SUCCESS;
}

CRYPTRSA_T *cryptRsaPubKeyFromRaw( uint8_t *rawKey, uint16_t rawKeyLen ) {

	assertion(-502024, (rawKey && cryptRsaKeyTypeByLen(rawKeyLen)));

	uint32_t e = ntohl(CRYPT_KEY_E_VAL);

	CRYPTRSA_T *cryptKey = debugMallocReset(sizeof(CRYPTRSA_T), -300615);

	cryptKey->backendKey = debugMalloc(sizeof(rsa_context), -300620);

	rsa_context *rsa = (rsa_context*)cryptKey->backendKey;

	rsa_init(rsa, RSA_PKCS_V15, 0);


	if (
		(mpi_read_binary(&rsa->N, rawKey, rawKeyLen)) ||
		(mpi_read_binary(&rsa->E, (uint8_t*)&e, sizeof(e)))
		 ) {
		cryptRsaKeyFree(&cryptKey);
		return NULL;
	}

	rsa->len = rawKeyLen;
	cryptKey->rawKeyLen = rawKeyLen;
	cryptKey->rawKeyType = cryptRsaKeyTypeByLen(rawKeyLen);


#ifdef EXTREME_PARANOIA
	uint8_t buff[rawKeyLen];
	memset(buff, 0, rawKeyLen);
	int test = cryptRsaPubKeyGetRaw(cryptKey, buff, rawKeyLen);
	assertion(-502721, (test == SUCCESS));
	assertion(-502722, (memcmp(rawKey, buff, rawKeyLen) == 0));
#endif


//	cryptKey->__rawKey = debugMalloc(rawKeyLen,-300618);
//	memcpy(cryptKey->__rawKey, rawKey, rawKeyLen);

	return cryptKey;
}

int cryptRsaPubKeyCheck( CRYPTRSA_T *pubKey) {
	assertion(-502141, (pubKey));
	assertion(-502142, (pubKey->backendKey));

	rsa_context *rsa = (rsa_context*)pubKey->backendKey;

	if (!rsa->len || (int)rsa->len != cryptRsaKeyLenByType(pubKey->rawKeyType) || rsa->len != pubKey->rawKeyLen || rsa->len != mpi_size(&rsa->N) ||
		rsa_check_pubkey((rsa_context*)pubKey->backendKey)) {

		return FAILURE;
	}

	return SUCCESS;
}

/*
STATIC_FUNC
void cryptKeyAddRaw( CRYPTRSA_T *cryptKey) {

	assertion(-502025, (cryptKey->backendKey && !cryptKey->__rawKey));
	int ret;
	rsa_context *rsa = cryptKey->backendKey;

	uint8_t rawBuff[512];
	uint8_t *rawStart;

	memset(rawBuff, 0, sizeof(rawBuff));

	if ((ret=mpi_write_binary(&rsa->N, rawBuff, sizeof(rawBuff) ))) {
		dbgf_sys(DBGT_ERR, "failed mpi_write_binary ret=%d", ret);
		cleanup_all(-502143);
	}

	for (rawStart = rawBuff; (!(*rawStart) && rawStart < (rawBuff + sizeof(rawBuff))); rawStart++);

	uint32_t rawLen = ((rawBuff + sizeof(rawBuff)) - rawStart);

	assertion(-502144, (cryptRsaKeyTypeByLen(rawLen) != FAILURE));

	dbgf_track(DBGT_INFO, "mpi_size=%zd rawLen=%d", mpi_size( &rsa->N ), rawLen );

	cryptKey->__rawKey = debugMalloc(rawLen, -300641);
	memcpy(cryptKey->__rawKey, rawStart, rawLen);
	cryptKey->__rawKeyLen = rawLen;
	cryptKey->rawKeyType = cryptRsaKeyTypeByLen(rawLen);
}
*/


CRYPTRSA_T *cryptRsaKeyFromDer( char *keyPath ) {

	assertion(-502029, (!my_PrivKey));

	CRYPTRSA_T *privKey = debugMallocReset(sizeof(CRYPTRSA_T), -300619);
	CRYPTRSA_T *pubKey = NULL;
	privKey->backendKey = debugMallocReset(sizeof(rsa_context), -300620);

	rsa_context *rsa = privKey->backendKey;
	int ret = 0;
	int keyType = 0;
	int keyLen = 0;
	uint8_t keyBuff[CRYPT_RSA_MAX_LEN];

#if CRYPTLIB <= POLARSSL_1_2_9
	if(
		(ret=x509parse_keyfile(rsa, keyPath, "")) ||
		(ret=rsa_check_privkey(rsa))
		) {
		dbgf_sys(DBGT_ERR, "failed opening private key=%s err=%d", keyPath, ret);
		cryptRsaKeyFree(&privKey);
		return NULL;
	}
#elif CRYPTLIB >= POLARSSL_1_3_3
	pk_context pk;
	pk_init(&pk);

	if (
		((ret = pk_parse_keyfile(&pk, keyPath, "")) != 0) ||
		((ret = rsa_copy(rsa, pk_rsa(pk))) != 0) ||
		((ret = rsa_check_privkey(rsa)) != 0)
		) {
		dbgf_sys(DBGT_ERR, "failed opening private key=%s keyLen=%d keyType=%d err=-%X", keyPath, keyLen, keyType, -ret);
		pk_free(&pk);
		cryptRsaKeyFree(&privKey);
		return NULL;
	}
	pk_free(&pk);

#else
# error "Please fix CRYPTLIB"
#endif

	//cryptKeyAddRaw(ckey);

	if (
		((keyLen = mpi_size(&rsa->N)) <= 0) ||
		!(keyType = cryptRsaKeyTypeByLen(keyLen)) ||
		!(privKey->rawKeyType = keyType) ||
		!(privKey->rawKeyLen = keyLen) ||
		(cryptRsaPubKeyGetRaw(privKey, keyBuff, keyLen) != SUCCESS) ||
		!(pubKey = cryptRsaPubKeyFromRaw(keyBuff, keyLen)) ) {

		cryptRsaKeyFree(&privKey);
		return NULL;
	}

	my_PrivKey = privKey;
	return pubKey;

}

#ifndef NO_KEY_GEN

// alternatively create private der encoded key with openssl:
// openssl genrsa -out /etc/bmx7/rsa.pem 2048
// openssl rsa -in /etc/bmx7/rsa.pem -inform PEM -out /etc/bmx7/rsa.der -outform DER
//
// read this with:
//    dumpasn1 key.der
//    note that all first INTEGER bytes are not zero (unlike with openssl certificates), but after conversion they are.
// convert to pem with openssl:
//    openssl rsa -in rsa-test/key.der -inform DER -out rsa-test/openssl.pem -outform PEM
// extract public key with openssl:
//    openssl rsa -in rsa-test/key.der -inform DER -pubout -out rsa-test/openssl.der.pub -outform DER

int cryptRsaKeyMakeDer( int32_t keyType, char *path ) {

	int32_t keyBitSize = (cryptRsaKeyLenByType(keyType) * 8);
	FILE* keyFile = NULL;
	unsigned char derBuf[CRYPT_DER_BUF_SZ];
	int derSz = 0;
	int ret = 0;
	char *goto_error_code = NULL;

	memset(derBuf, 0, CRYPT_DER_BUF_SZ);

#if CRYPTLIB <= POLARSSL_1_2_9
	rsa_context rsa;
	rsa_init(&rsa, RSA_PKCS_V15, 0);

        if ((ret = rsa_gen_key( &rsa, ctr_drbg_random, &ctr_drbg, keyBitSize, CRYPT_KEY_E_VAL )))
		goto_error(finish, "Failed making rsa key! ret=%d");

	if ((derSz = x509_write_key_der(derBuf, sizeof(derBuf), &rsa)) < 0)
		goto_error(finish, "Failed translating rsa key to der! derSz=%d");
#elif CRYPTLIB >= POLARSSL_1_3_3
	pk_context pk;
	pk_init( &pk );
	pk_init_ctx( &pk, pk_info_from_type( POLARSSL_PK_RSA ) );

	if ((ret = rsa_gen_key(pk_rsa(pk), ctr_drbg_random, &ctr_drbg, keyBitSize, CRYPT_KEY_E_VAL)) ||
		(ret = rsa_check_privkey(pk_rsa(pk))))
		goto_error(finish, "Failed making rsa key! ret=%d");

	if ((derSz = pk_write_key_der(&pk, derBuf, sizeof(derBuf))) <= 0)
		goto_error(finish, "Failed translating rsa key to der! derSz=%d");
#else
# error "Please fix CRYPTLIB"
#endif

	unsigned char *derStart = derBuf + sizeof(derBuf) - derSz;


	if (!(keyFile = fopen(path, "wb")) || ((int)fwrite(derStart, 1, derSz, keyFile)) != derSz )
		goto_error(finish, "Failed writing");

finish: {
	memset(derBuf, 0, CRYPT_DER_BUF_SZ);

#if CRYPTLIB <= POLARSSL_1_2_9
	rsa_free( &rsa );
#elif CRYPTLIB >= POLARSSL_1_3_3
	pk_free(&pk);
#else
# error "Please fix CRYPTLIB"
#endif

	if (keyFile)
		fclose(keyFile);

	if (goto_error_code) {
		dbgf_sys(DBGT_ERR, "%s ret=%d derSz=%d path=%s", goto_error_code, ret, derSz, path);
		return FAILURE;
	}
	
	return SUCCESS;
}
}

CRYPTRSA_T *cryptRsaKeyMake( uint8_t keyType ) {

	int32_t keyLen = cryptRsaKeyLenByType(keyType);
	int ret = 0;
	char *goto_error_code = NULL;
	CRYPTRSA_T *key = debugMallocReset(sizeof(CRYPTRSA_T), -300642);

	rsa_context *rsa = debugMallocReset(sizeof(rsa_context), -300643);
	rsa_init(rsa, RSA_PKCS_V15, 0);

        if ((ret = rsa_gen_key( rsa, ctr_drbg_random, &ctr_drbg, (keyLen * 8), CRYPT_KEY_E_VAL )))
		goto_error(finish, "Failed making rsa key!");

	key->backendKey = rsa;
	key->rawKeyType = keyType;
	key->rawKeyLen = keyLen;
//	cryptKeyAddRaw(key);

finish: {
	if (goto_error_code) {

		cryptRsaKeyFree(&key);

		dbgf_sys(DBGT_ERR, "%s ret=%d", goto_error_code, ret);
		return NULL;
	}

	return key;
}
}
#endif


int cryptRsaEncrypt( uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen, CRYPTRSA_T *pubKey) {

	rsa_context *pk = pubKey->backendKey;

	assertion(-502723, (mpi_size(&pk->N) == pubKey->rawKeyLen));
	assertion(-502145, (*outLen >= pubKey->rawKeyLen));

	if (rsa_pkcs1_encrypt(pk, ctr_drbg_random, &ctr_drbg, RSA_PUBLIC, inLen, in, out))
		return FAILURE;

	*outLen = pubKey->rawKeyLen;

	return SUCCESS;

}

int cryptRsaDecrypt(uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen) {

	rsa_context *pk = my_PrivKey->backendKey;

	assertion(-502724, (mpi_size(&pk->N) == my_PrivKey->rawKeyLen));
	assertion(-502146, (inLen >= my_PrivKey->rawKeyLen));
#if CRYPTLIB == POLARSSL_1_2_5
	if (rsa_pkcs1_decrypt(pk, RSA_PRIVATE, &inLen, in, out, *outLen))
		return FAILURE;
#elif CRYPTLIB >= POLARSSL_1_2_9
	if (rsa_pkcs1_decrypt(pk, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE, &inLen, in, out, *outLen))
		return FAILURE;
#else
# error "Please fix CRYPTLIB"
#endif
	*outLen = inLen;

	return SUCCESS;
}

int cryptRsaSign( CRYPTSHA1_T *inSha, uint8_t *out, size_t outLen, CRYPTRSA_T *cryptKey) {

	if (!cryptKey)
		cryptKey = my_PrivKey;

	rsa_context *pk = cryptKey->backendKey;

	if (outLen < cryptKey->rawKeyLen)
		return FAILURE;

#if CRYPTLIB <= POLARSSL_1_2_9
	if (rsa_pkcs1_sign(pk, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE, SIG_RSA_SHA1, sizeof(CRYPTSHA1_T), (uint8_t*)inSha, out))
		return FAILURE;
#elif CRYPTLIB >= POLARSSL_1_3_3
	if (rsa_pkcs1_sign(pk, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE, POLARSSL_MD_SHA1, sizeof(CRYPTSHA1_T), (uint8_t*)inSha, out))
		return FAILURE;
#else
# error "Please fix CRYPTLIB"
#endif

	return SUCCESS;
}

int cryptRsaVerify(uint8_t *sign, size_t signLen, CRYPTSHA1_T *plainSha, CRYPTRSA_T *pubKey) {

	rsa_context *pk = pubKey->backendKey;

	assertion(-502147, (signLen == pubKey->rawKeyLen));

#if CRYPTLIB == POLARSSL_1_2_5
	if (rsa_pkcs1_verify(pk, RSA_PUBLIC, SIG_RSA_SHA1, sizeof(CRYPTSHA1_T), (uint8_t*)plainSha, sign))
		return FAILURE;
#elif CRYPTLIB == POLARSSL_1_2_9
	if (rsa_pkcs1_verify(pk, ctr_drbg_random, &ctr_drbg, RSA_PUBLIC, SIG_RSA_SHA1, sizeof(CRYPTSHA1_T), (uint8_t*)plainSha, sign))
		return FAILURE;
#elif CRYPTLIB >= POLARSSL_1_3_3
	if (rsa_pkcs1_verify(pk, ctr_drbg_random, &ctr_drbg, RSA_PUBLIC, POLARSSL_MD_SHA1, sizeof(CRYPTSHA1_T), (uint8_t*)plainSha, sign))
		return FAILURE;
#elif CRYPTLIB == POLARSSL_1_3_3
#else
# error "Please fix CRYPTLIB"
#endif


	return SUCCESS;
}



void cryptRand( void *out, uint32_t outLen) {

	assertion(-502139, ENTROPY_BLOCK_SIZE > sizeof(CRYPTSHA1_T));

	if (outLen <= sizeof(CRYPTSHA1_T)) {

		if (entropy_func( &entropy_ctx, out, outLen) != 0)
			cleanup_all(-502148);
	} else {

		CRYPTSHA1_T seed[2];
		uint32_t outPos;

		if (entropy_func( &entropy_ctx, (void*)&seed[0], sizeof(CRYPTSHA1_T)) != 0)
			cleanup_all(-502140);

		cryptShaAtomic(&seed[0], sizeof(CRYPTSHA1_T), &seed[1]);

		for (outPos = 0; outLen > outPos; outPos += sizeof(CRYPTSHA1_T)) {

			cryptShaAtomic(&seed, sizeof(seed), &seed[1]);

			memcpy(&(((uint8_t*) out)[outPos]), &seed[1], XMIN(outLen - outPos, sizeof(CRYPTSHA1_T)));
		}

	}
}

STATIC_FUNC
void cryptRngInit( void ) {

	int ret;

	fflush( stdout );
	entropy_init( &entropy_ctx );

	if( (ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy_ctx, NULL, 0)) != 0 )
		cleanup_all(-502149);

	int test=0;

	cryptRand( &test, sizeof(test));
	assertion( -500525, (test));
}

STATIC_FUNC
void cryptRngFree( void ) {
//    entropy_free( &entropy_ctx );
}



STATIC_FUNC
void cryptShaInit( void ) {
/*
	InitSha(&cryptSha);
*/
	shaClean = YES;
}

STATIC_FUNC
void cryptShaFree( void ) {
}

void cryptShaAtomic( void *in, int32_t len, CRYPTSHA1_T *sha) {

	assertion(-502030, (shaClean==YES));
	assertion(-502031, (sha));
	assertion(-502032, (in && len>0 && !memcmp(in, in, len)));

//	sha1( in, len, sha);

	sha1_starts( &sha_ctx );
	sha1_update( &sha_ctx, in, len );
	sha1_finish( &sha_ctx, (unsigned char*)sha );

	memset( &sha_ctx, 0, sizeof( sha1_context ) );

}

void cryptShaNew( void *in, int32_t len) {

	assertion(-502033, (shaClean==YES));
	assertion(-502034, (in && len>0 && !memcmp(in, in, len)));
	shaClean = NO;

	sha1_starts( &sha_ctx );
	sha1_update( &sha_ctx, in, len );
}

void cryptShaUpdate( void *in, int32_t len) {

	assertion(-502035, (shaClean==NO));
	assertion(-502036, (in && len>0 && !memcmp(in, in, len)));

	sha1_update( &sha_ctx, in, len );
}

void cryptShaFinal( CRYPTSHA1_T *sha) {

	assertion(-502037, (shaClean==NO));
	assertion(-502038, (sha));

	sha1_finish( &sha_ctx, (unsigned char*)sha );
	memset( &sha_ctx, 0, sizeof( sha1_context ) );
	shaClean = YES;
}



/*****************************************************************************/
#else
# error "Please fix CRYPTLIB"
#endif

char *cryptShaAsString( CRYPTSHA1_T *sha)
{
#define SHA1ASSTR_BUFF_SIZE ((2*sizeof(CRYPTSHA1_T))+1)
#define SHA1ASSTR_BUFFERS 4
	static uint8_t c=0;
        static char out[SHA1ASSTR_BUFFERS][SHA1ASSTR_BUFF_SIZE];
        uint8_t i;

        if (!sha)
                return NULL;

        c = (c+1) % SHA1ASSTR_BUFFERS;

	for (i=0; i<=4; i++)
		sprintf(&(out[c][i*8]), "%.8X", ntohl(sha->h.u32[i]));

        return out[c];
}

char *cryptShaAsShortStr( CRYPTSHA1_T *sha)
{
#define SHA1ASSHORT_BUFF_SIZE ((2*sizeof(uint32_t))+1)
#define SHA1ASSHORT_BUFFERS 4
	static uint8_t c=0;
        static char out[SHA1ASSHORT_BUFFERS][SHA1ASSHORT_BUFF_SIZE];

        if (!sha)
                return NULL;

        c = (c+1) % SHA1ASSHORT_BUFFERS;

	sprintf(out[c], "%.8X", ntohl(sha->h.u32[0]));

        return out[c];
}

int cryptShasEqual( CRYPTSHA1_T *sha1, CRYPTSHA1_T *sha2)
{
	return !memcmp(sha1, sha2, sizeof(CRYPTSHA1_T));
}

uint8_t cryptRsaKeyTypeByLen(int len) {
	return 	len == CRYPT_RSA512_LEN ? CRYPT_RSA512_TYPE : (
		len == CRYPT_RSA768_LEN ? CRYPT_RSA768_TYPE : (
		len == CRYPT_RSA896_LEN ? CRYPT_RSA896_TYPE : (
		len == CRYPT_RSA1024_LEN ? CRYPT_RSA1024_TYPE : (
		len == CRYPT_RSA1536_LEN ? CRYPT_RSA1536_TYPE : (
		len == CRYPT_RSA2048_LEN ? CRYPT_RSA2048_TYPE : (
		len == CRYPT_RSA3072_LEN ? CRYPT_RSA3072_TYPE : (
		len == CRYPT_RSA4096_LEN ? CRYPT_RSA4096_TYPE : (
		0 ))))))));
}

uint16_t cryptRsaKeyLenByType(int type) {
	return 	type == CRYPT_RSA512_TYPE ? CRYPT_RSA512_LEN : (
		type == CRYPT_RSA768_TYPE ? CRYPT_RSA768_LEN : (
		type == CRYPT_RSA896_TYPE ? CRYPT_RSA896_LEN : (
		type == CRYPT_RSA1024_TYPE ? CRYPT_RSA1024_LEN : (
		type == CRYPT_RSA1536_TYPE ? CRYPT_RSA1536_LEN : (
		type == CRYPT_RSA2048_TYPE ? CRYPT_RSA2048_LEN : (
		type == CRYPT_RSA3072_TYPE ? CRYPT_RSA3072_LEN : (
		type == CRYPT_RSA4096_TYPE ? CRYPT_RSA4096_LEN : (
		0 ))))))));
}

char *cryptRsaKeyTypeAsString(int type) {
	return 	type == CRYPT_RSA512_TYPE ? CRYPT_RSA512_NAME : (
		type == CRYPT_RSA768_TYPE ? CRYPT_RSA768_NAME : (
		type == CRYPT_RSA896_TYPE ? CRYPT_RSA896_NAME : (
		type == CRYPT_RSA1024_TYPE ? CRYPT_RSA1024_NAME : (
		type == CRYPT_RSA1536_TYPE ? CRYPT_RSA1536_NAME : (
		type == CRYPT_RSA2048_TYPE ? CRYPT_RSA2048_NAME : (
		type == CRYPT_RSA3072_TYPE ? CRYPT_RSA3072_NAME : (
		type == CRYPT_RSA4096_TYPE ? CRYPT_RSA4096_NAME : (
		NULL ))))))));
}

void init_crypt(void) {
	
	cryptRngInit();
	cryptShaInit();

        unsigned int random;
        cryptRand( &random, sizeof (random));
	srand( random );
}

void cleanup_crypt(void) {

        cryptRsaKeyFree(&my_PrivKey);

	cryptRngFree();
	cryptShaFree();
}
