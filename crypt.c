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

const CRYPTSHA_T ZERO_CYRYPSHA = { .h.u32 = {0} };
const CRYPTRSA_T CYRYPTRSA_ZERO = {.backendKey = NULL};

static uint8_t shaClean = NO;

static CRYPTRSA_T *my_PrivKey = NULL;

#if (CRYPTLIB >= POLARSSL_MIN && CRYPTLIB <= POLARSSL_MAX) || (CRYPTLIB >= MBEDTLS_MIN && CRYPTLIB <= MBEDTLS_MAX)

#if (CRYPTLIB >= POLARSSL_MIN && CRYPTLIB <= POLARSSL_MAX)
/******************* accessing polarssl: *************************************/
#include "polarssl/config.h"
#include "polarssl/sha256.h"

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

#elif (CRYPTLIB >= MBEDTLS_MIN && CRYPTLIB <= MBEDTLS_MAX)
/******************* accessing mbedtls: *************************************/

#if CRYPTLIB >= MBEDTLS_2_16_0
#include "mbedtls/platform_util.h"
#endif 

#include "mbedtls/compat-1.3.h"
#include "mbedtls/config.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/dhm.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"

#endif

static entropy_context entropy_ctx;
static ctr_drbg_context ctr_drbg;

static sha256_context sha_ctx;

uint8_t cryptDhmKeyTypeByLen(int len)
{
	return len == CRYPT_DHM1024_LEN ? CRYPT_DHM1024_TYPE : (
		len == CRYPT_DHM2048_LEN ? CRYPT_DHM2048_TYPE : (
		len == CRYPT_DHM3072_LEN ? CRYPT_DHM3072_TYPE : (
		0)));
}

uint16_t cryptDhmKeyLenByType(int type)
{
	return type == CRYPT_DHM1024_TYPE ? CRYPT_DHM1024_LEN : (
		type == CRYPT_DHM2048_TYPE ? CRYPT_DHM2048_LEN : (
		type == CRYPT_DHM3072_TYPE ? CRYPT_DHM3072_LEN : (
		0)));
}

char *cryptDhmKeyTypeAsString(int type)
{
	return type == CRYPT_DHM1024_TYPE ? CRYPT_DHM1024_NAME : (
		type == CRYPT_DHM2048_TYPE ? CRYPT_DHM2048_NAME : (
		type == CRYPT_DHM3072_TYPE ? CRYPT_DHM3072_NAME : (
		NULL)));
}

void cryptDhmKeyFree(CRYPTDHM_T **cryptKey)
{

	if (!*cryptKey)
		return;

	if ((*cryptKey)->backendKey) {
		dhm_free((dhm_context*) ((*cryptKey)->backendKey));
		debugFree((*cryptKey)->backendKey, -300828);
	}

	debugFree((*cryptKey), -300614);

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

CRYPTDHM_T *cryptDhmKeyMake(uint8_t keyType, uint8_t attempt)
{

	int ret = 0;
	char *goto_error_code = NULL;
	int keyLen = 0;
	CRYPTDHM_T *key = debugMallocReset(sizeof(CRYPTDHM_T), -300829);
	dhm_context *dhm = debugMallocReset(sizeof(dhm_context), -300830);
#if !(CRYPTLIB >= MBEDTLS_2_8_0 && CRYPTLIB <= MBEDTLS_MAX)
	char *pptr = NULL;
	char *gptr = NULL;
#endif
	int pSize = 0;
	int xSize = 0;
	int gxSize = 0;
	int count = 0;

#if CRYPTLIB >= POLARSSL_1_3_9
	// in older versions, if dhm_init() exist, it only zero-memsets the dhm context
	dhm_init(dhm);
#endif
	key->backendKey = dhm;

	if (!(keyType))
		goto_error(finish, "Missing type");
	if ((keyLen = cryptDhmKeyLenByType(keyType)) <= 0)
		goto_error(finish, "Invalid size");

#if (CRYPTLIB >= POLARSSL_MIN && CRYPTLIB <= POLARSSL_MAX)
	if (keyType == CRYPT_DHM1024_TYPE) {
		pptr = POLARSSL_DHM_RFC5114_MODP_1024_P;
		gptr = POLARSSL_DHM_RFC5114_MODP_1024_G;
	} else if (keyType == CRYPT_DHM2048_TYPE) {
		pptr = POLARSSL_DHM_RFC3526_MODP_2048_P;
		gptr = POLARSSL_DHM_RFC3526_MODP_2048_G;
	} else if (keyType == CRYPT_DHM3072_TYPE) {
		pptr = POLARSSL_DHM_RFC3526_MODP_3072_P;
		gptr = POLARSSL_DHM_RFC3526_MODP_3072_G;
#elif (CRYPTLIB >= MBEDTLS_MIN && CRYPTLIB < MBEDTLS_2_8_0)
	if (keyType == CRYPT_DHM2048_TYPE) {
		pptr = MBEDTLS_DHM_RFC3526_MODP_2048_P;
		gptr = MBEDTLS_DHM_RFC3526_MODP_2048_G;
	} else if (keyType == CRYPT_DHM3072_TYPE) {
		pptr = MBEDTLS_DHM_RFC3526_MODP_3072_P;
		gptr = MBEDTLS_DHM_RFC3526_MODP_3072_G;
#elif (CRYPTLIB >= MBEDTLS_2_8_0 && CRYPTLIB <= MBEDTLS_MAX)
		
	if (keyType == CRYPT_DHM2048_TYPE) {
		static const unsigned char modp2048P[(2048/8)] = MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
		static const unsigned char modp2048G[1] = MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;
		if ((ret = mpi_read_binary(&dhm->P, modp2048P, sizeof(modp2048P) )) != 0 || (ret = mpi_read_binary(&dhm->G, modp2048G, sizeof(modp2048G))) != 0)
			goto_error(finish, "Failed setting dhm parameters!");
		
	} else if (keyType == CRYPT_DHM3072_TYPE) {
		static const unsigned char modp3072P[(3072/8)] = MBEDTLS_DHM_RFC3526_MODP_3072_P_BIN;
		static const unsigned char modp3072G[1] = MBEDTLS_DHM_RFC3526_MODP_3072_G_BIN;
		if ((ret = mpi_read_binary(&dhm->P, modp3072P, sizeof(modp3072P) )) != 0 || (ret = mpi_read_binary(&dhm->G, modp3072G, sizeof(modp3072G))) != 0)
			goto_error(finish, "Failed setting dhm parameters!");
#endif
	} else {
		goto_error(finish, "Unsupported dhm type!");
	}

#if !(CRYPTLIB >= MBEDTLS_2_8_0 && CRYPTLIB <= MBEDTLS_MAX)
	if ((ret = mpi_read_string(&dhm->P, 16, pptr)) != 0 || (ret = mpi_read_string(&dhm->G, 16, gptr)) != 0)
		goto_error(finish, "Failed setting dhm parameters!");
#endif
	if (mpi_cmp_int(&dhm->P, 0) == 0)
		goto_error(finish, "Empty dhm->P");

	// Generate X as large as possible ( < P )
	if ((pSize = mpi_size(&dhm->P)) != keyLen)
		goto_error(finish, "Invalid P size");

	do {
		if ((ret = mpi_fill_random(&dhm->X, pSize, ctr_drbg_random, &ctr_drbg)) != 0)
			goto_error(finish, "Failed allocating randomness");

		while (mpi_cmp_mpi(&dhm->X, &dhm->P) >= 0) {
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
	if ((ret = _cryptDhmCheckRange(&dhm->GX, &dhm->P)) != SUCCESS)
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
		"Failed: dhm.GXlen=%zd dhm.len=%zd", dhm ? mpi_size(&dhm->GX) : 0, dhm ? dhm->len : 0);

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
	if ((int) dhm->len != keyLen)
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
	dbgf_track(DBGT_WARN, "%s keyType=%d keyLen=%d dhmLen=%zd pSize=%d xSize=%d gxSize=%d gySize=%d",
		goto_error_code, keyType, keyLen, dhm ? dhm->len : 0, pSize, xSize, gxSize, gySize);

	return FAILURE;
}

CRYPTSHA_T *cryptDhmSecretForNeigh(CRYPTDHM_T *myDhm, uint8_t *neighRawKey, uint16_t neighRawKeyLen)
{
	char *goto_error_code = NULL;
	uint8_t keyType = 0;
	int ret = 0;
	CRYPTSHA_T *secret = NULL;
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

#if (CRYPTLIB >= POLARSSL_MIN && CRYPTLIB <= POLARSSL_MAX)
	if ((ret = dhm_calc_secret(dhm, buff, &n, ctr_drbg_random, &ctr_drbg)) != 0)
#elif (CRYPTLIB >= MBEDTLS_MIN && CRYPTLIB <= MBEDTLS_MAX)
	if ((ret = dhm_calc_secret(dhm, buff, sizeof(buff), &n, ctr_drbg_random, &ctr_drbg)) != 0)
#endif
		goto_error(finish, "Failed calculating secret");

	if (n > neighRawKeyLen || n < ((neighRawKeyLen / 4)*3))
		goto_error(finish, "Unexpected secret length");

	secret = debugMallocReset(sizeof(CRYPTSHA_T), -300831);
	cryptShaAtomic(buff, n, secret);


finish:
	{
		dbgf(((goto_error_code || n != neighRawKeyLen) ? DBGL_SYS : DBGL_CHANGES), ((goto_error_code || n != neighRawKeyLen) ? DBGT_WARN : DBGT_INFO),
		"%s n=%zd neighKeyLen=%d myKeyLen=%d", goto_error_code, n, neighRawKeyLen, myDhm->rawGXLen);

		mpi_free(&dhm->GY);
		mpi_free(&dhm->K);
		memset(buff, 0, sizeof(buff));
		return secret; }
}

void cryptRsaKeyFree(CRYPTRSA_T **cryptKey)
{

	if (!*cryptKey)
		return;

	if ((*cryptKey)->backendKey) {
		rsa_free((rsa_context*) ((*cryptKey)->backendKey));
		debugFree((*cryptKey)->backendKey, -300612);
	}

	//	if ((*cryptKey)->__rawKey) {
	//		debugFree((*cryptKey)->__rawKey, -300613);
	//	}

	debugFree((*cryptKey), -300614);

	*cryptKey = NULL;
}

int cryptRsaPubKeyGetRaw(CRYPTRSA_T *key, uint8_t *buff, uint16_t buffLen)
{

	rsa_context *rsa;
	if (!key || !buff || !buffLen ||
		!key->rawKeyType || (buffLen != key->rawKeyLen) ||
		!(rsa = (rsa_context*) key->backendKey) || buffLen != mpi_size(&rsa->N) || buffLen != rsa->len) {

		return FAILURE;
	}

	if (mpi_write_binary(&rsa->N, buff, buffLen) != 0)
		return FAILURE;

	return SUCCESS;
}

CRYPTRSA_T *cryptRsaPubKeyFromRaw(uint8_t *rawKey, uint16_t rawKeyLen)
{

	assertion(-502024, (rawKey && cryptRsaKeyTypeByLen(rawKeyLen)));

	uint32_t e = ntohl(CRYPT_KEY_E_VAL);

	CRYPTRSA_T *cryptKey = debugMallocReset(sizeof(CRYPTRSA_T), -300615);

	cryptKey->backendKey = debugMalloc(sizeof(rsa_context), -300620);

	rsa_context *rsa = (rsa_context*) cryptKey->backendKey;

	rsa_init(rsa, RSA_PKCS_V15, 0);


	if (
		(mpi_read_binary(&rsa->N, rawKey, rawKeyLen)) ||
		(mpi_read_binary(&rsa->E, (uint8_t*) & e, sizeof(e)))
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

int cryptRsaPubKeyCheck(CRYPTRSA_T *pubKey)
{
	assertion(-502141, (pubKey));
	assertion(-502142, (pubKey->backendKey));

	rsa_context *rsa = (rsa_context*) pubKey->backendKey;

	if (!rsa->len || (int) rsa->len != cryptRsaKeyLenByType(pubKey->rawKeyType) || rsa->len != pubKey->rawKeyLen || rsa->len != mpi_size(&rsa->N) ||
		rsa_check_pubkey((rsa_context*) pubKey->backendKey)) {

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


CRYPTRSA_T *cryptRsaKeyFromDer(char *keyPath)
{

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
	if (
		(ret = x509parse_keyfile(rsa, keyPath, "")) ||
		(ret = rsa_check_privkey(rsa))
		) {
		dbgf_sys(DBGT_ERR, "failed opening private key=%s err=%d", keyPath, ret);
		cryptRsaKeyFree(&privKey);
		return NULL;
	}
#elif CRYPTLIB >= POLARSSL_1_3_3
	pk_context pk;
	pk_init(&pk);
	rsa_init(rsa, RSA_PKCS_V15, 0);

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
#error "Please fix CRYPTLIB"
#endif

	//cryptKeyAddRaw(ckey);

	if (
		((keyLen = mpi_size(&rsa->N)) <= 0) ||
		!(keyType = cryptRsaKeyTypeByLen(keyLen)) ||
		!(privKey->rawKeyType = keyType) ||
		!(privKey->rawKeyLen = keyLen) ||
		(cryptRsaPubKeyGetRaw(privKey, keyBuff, keyLen) != SUCCESS) ||
		!(pubKey = cryptRsaPubKeyFromRaw(keyBuff, keyLen))) {

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

int cryptRsaKeyMakeDer(int32_t keyType, char *path)
{

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

	if ((ret = rsa_gen_key(&rsa, ctr_drbg_random, &ctr_drbg, keyBitSize, CRYPT_KEY_E_VAL)))
		goto_error(finish, "Failed making rsa key! ret=%d");

	if ((derSz = x509_write_key_der(derBuf, sizeof(derBuf), &rsa)) < 0)
		goto_error(finish, "Failed translating rsa key to der! derSz=%d");
#elif CRYPTLIB >= POLARSSL_1_3_3
	pk_context pk;
	pk_init(&pk);
	pk_init_ctx(&pk, pk_info_from_type(POLARSSL_PK_RSA));

	if ((ret = rsa_gen_key(pk_rsa(pk), ctr_drbg_random, &ctr_drbg, keyBitSize, CRYPT_KEY_E_VAL)) ||
		(ret = rsa_check_privkey(pk_rsa(pk))))
		goto_error(finish, "Failed making rsa key! ret=%d");

	if ((derSz = pk_write_key_der(&pk, derBuf, sizeof(derBuf))) <= 0)
		goto_error(finish, "Failed translating rsa key to der! derSz=%d");
#else
#error "Please fix CRYPTLIB"
#endif

	unsigned char *derStart = derBuf + sizeof(derBuf) - derSz;


	if (!(keyFile = fopen(path, "wb")) || ((int) fwrite(derStart, 1, derSz, keyFile)) != derSz)
		goto_error(finish, "Failed writing");

finish:
	{
		memset(derBuf, 0, CRYPT_DER_BUF_SZ);

#if CRYPTLIB <= POLARSSL_1_2_9
		rsa_free(&rsa);
#elif CRYPTLIB >= POLARSSL_1_3_3
		pk_free(&pk);
#else
#error "Please fix CRYPTLIB"
#endif

		if (keyFile)
			fclose(keyFile);

		if (goto_error_code) {
			dbgf_sys(DBGT_ERR, "%s ret=%d derSz=%d path=%s", goto_error_code, ret, derSz, path);
			return FAILURE;
		}

		return SUCCESS; }
}

CRYPTRSA_T *cryptRsaKeyMake(uint8_t keyType)
{

	int32_t keyLen = cryptRsaKeyLenByType(keyType);
	int ret = 0;
	char *goto_error_code = NULL;
	CRYPTRSA_T *key = debugMallocReset(sizeof(CRYPTRSA_T), -300642);

	rsa_context *rsa = debugMallocReset(sizeof(rsa_context), -300643);
	rsa_init(rsa, RSA_PKCS_V15, 0);

	if ((ret = rsa_gen_key(rsa, ctr_drbg_random, &ctr_drbg, (keyLen * 8), CRYPT_KEY_E_VAL)))
		goto_error(finish, "Failed making rsa key!");

	key->backendKey = rsa;
	key->rawKeyType = keyType;
	key->rawKeyLen = keyLen;
	//	cryptKeyAddRaw(key);

finish:
	{
		if (goto_error_code) {

			cryptRsaKeyFree(&key);

			dbgf_sys(DBGT_ERR, "%s ret=%d", goto_error_code, ret);
			return NULL;
		}

		return key; }
}
#endif

int cryptRsaEncrypt(uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen, CRYPTRSA_T *pubKey)
{

	rsa_context *pk = pubKey->backendKey;

	assertion(-502723, (mpi_size(&pk->N) == pubKey->rawKeyLen));
	assertion(-502145, (*outLen >= pubKey->rawKeyLen));

	if (rsa_pkcs1_encrypt(pk, ctr_drbg_random, &ctr_drbg, RSA_PUBLIC, inLen, in, out))
		return FAILURE;

	*outLen = pubKey->rawKeyLen;

	return SUCCESS;

}

int cryptRsaDecrypt(uint8_t *in, size_t inLen, uint8_t *out, size_t *outLen)
{

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
#error "Please fix CRYPTLIB"
#endif
	*outLen = inLen;

	return SUCCESS;
}

int cryptRsaSign(CRYPTSHA_T *inSha, uint8_t *out, size_t outLen, CRYPTRSA_T *cryptKey)
{

	if (!cryptKey)
		cryptKey = my_PrivKey;

	rsa_context *pk = cryptKey->backendKey;

	if (outLen < cryptKey->rawKeyLen)
		return FAILURE;

#if CRYPTLIB <= POLARSSL_1_2_9
	if (rsa_pkcs1_sign(pk, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE, SIG_RSA_SHA224, sizeof(CRYPTSHA_T), (uint8_t*) inSha, out))
		return FAILURE;
#elif CRYPTLIB >= POLARSSL_1_3_3
	if (rsa_pkcs1_sign(pk, ctr_drbg_random, &ctr_drbg, RSA_PRIVATE, POLARSSL_MD_SHA224, sizeof(CRYPTSHA_T), (uint8_t*) inSha, out))
		return FAILURE;
#else
#error "Please fix CRYPTLIB"
#endif

	return SUCCESS;
}

int cryptRsaVerify(uint8_t *sign, size_t signLen, CRYPTSHA_T *plainSha, CRYPTRSA_T *pubKey)
{

	rsa_context *pk = pubKey->backendKey;

	assertion(-502147, (signLen == pubKey->rawKeyLen));

#if CRYPTLIB == POLARSSL_1_2_5
	if (rsa_pkcs1_verify(pk, RSA_PUBLIC, SIG_RSA_SHA224, sizeof(CRYPTSHA_T), (uint8_t*) plainSha, sign))
		return FAILURE;
#elif CRYPTLIB == POLARSSL_1_2_9
	if (rsa_pkcs1_verify(pk, ctr_drbg_random, &ctr_drbg, RSA_PUBLIC, SIG_RSA_SHA224, sizeof(CRYPTSHA_T), (uint8_t*) plainSha, sign))
		return FAILURE;
#elif CRYPTLIB >= POLARSSL_1_3_3
	if (rsa_pkcs1_verify(pk, ctr_drbg_random, &ctr_drbg, RSA_PUBLIC, POLARSSL_MD_SHA224, sizeof(CRYPTSHA_T), (uint8_t*) plainSha, sign))
		return FAILURE;
#else
#error "Please fix CRYPTLIB"
#endif


	return SUCCESS;
}

void cryptRand(void *out, uint32_t outLen)
{

	assertion(-502139, ENTROPY_BLOCK_SIZE > sizeof(CRYPTSHA_T));

	if (outLen <= sizeof(CRYPTSHA_T)) {

		if (entropy_func(&entropy_ctx, out, outLen) != 0)
			cleanup_all(-502148);
	} else {

		CRYPTSHA_T seed[2];
		uint32_t outPos;

		if (entropy_func(&entropy_ctx, (void*) &seed[0], sizeof(CRYPTSHA_T)) != 0)
			cleanup_all(-502140);

		cryptShaAtomic(&seed[0], sizeof(CRYPTSHA_T), &seed[1]);

		for (outPos = 0; outLen > outPos; outPos += sizeof(CRYPTSHA_T)) {

			cryptShaAtomic(&seed, sizeof(seed), &seed[1]);

			memcpy(&(((uint8_t*) out)[outPos]), &seed[1], XMIN(outLen - outPos, sizeof(CRYPTSHA_T)));
		}

	}
}

STATIC_FUNC
void cryptRngInit(void)
{

	int ret;

	fflush(stdout);
	entropy_init(&entropy_ctx);

#if (CRYPTLIB >= POLARSSL_MIN && CRYPTLIB <= POLARSSL_MAX)
	if ((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy_ctx, NULL, 0)) != 0)
		cleanup_all(-502149);
#elif (CRYPTLIB >= MBEDTLS_MIN && CRYPTLIB <= MBEDTLS_MAX)
	mbedtls_ctr_drbg_init(&ctr_drbg);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, entropy_func, &entropy_ctx, NULL, 0)) != 0)
		cleanup_all(-502149);
#endif

	int test = 0;

	cryptRand(&test, sizeof(test));
	assertion(-500525, (test));
}

STATIC_FUNC
void cryptRngFree(void)
{
	//    entropy_free( &entropy_ctx );
}

STATIC_FUNC
void cryptShaInit(void)
{
#if CRYPTLIB < POLARSSL_1_3_9
	memset(&sha_ctx, 0, sizeof(sha_ctx));
#else
	sha256_init(&sha_ctx);
#endif
	shaClean = YES;
}

STATIC_FUNC
void cryptShaFree(void)
{
#if CRYPTLIB < POLARSSL_1_3_9
	memset(&sha_ctx, 0, sizeof(sha_ctx));
#else
	sha256_free(&sha_ctx);
#endif
}

void cryptShaAtomic(void *in, int32_t len, CRYPTSHA_T *sha)
{
	assertion(-502030, (shaClean == YES));
	assertion(-502031, (sha));
	assertion(-502032, (in && len > 0 && !memcmp(in, in, len)));
	
	unsigned char output[32];
	
#if (CRYPTLIB >= MBEDTLS_2_8_0 && CRYPTLIB <= MBEDTLS_MAX)
	mbedtls_sha256_starts_ret(&sha_ctx, 1/*is224*/);
	mbedtls_sha256_update_ret(&sha_ctx, in, len);
	mbedtls_sha256_finish_ret(&sha_ctx, output);
#else
	sha256_starts(&sha_ctx, 1/*is224*/);
	sha256_update(&sha_ctx, in, len);
	sha256_finish(&sha_ctx, output);
#endif
	memcpy(sha, output, sizeof(CRYPTSHA_T));
	memset(output, 0, sizeof(output));
}

void cryptShaNew(void *in, int32_t len)
{

	assertion(-502033, (shaClean == YES));
	assertion(-502034, (in && len > 0 && !memcmp(in, in, len)));
	shaClean = NO;

#if (CRYPTLIB >= MBEDTLS_2_8_0 && CRYPTLIB <= MBEDTLS_MAX)
	mbedtls_sha256_starts_ret(&sha_ctx, 1/*is224*/);
	mbedtls_sha256_update_ret(&sha_ctx, in, len);
#else
	sha256_starts(&sha_ctx, 1/*is224*/);
	sha256_update(&sha_ctx, in, len);
#endif
}

void cryptShaUpdate(void *in, int32_t len)
{

	assertion(-502035, (shaClean == NO));
	assertion(-502036, (in && len > 0 && !memcmp(in, in, len)));

#if (CRYPTLIB >= MBEDTLS_2_8_0 && CRYPTLIB <= MBEDTLS_MAX)
	mbedtls_sha256_update_ret(&sha_ctx, in, len);
#else
	sha256_update(&sha_ctx, in, len);
#endif
}

void cryptShaFinal(CRYPTSHA_T *sha)
{

	assertion(-502037, (shaClean == NO));
	assertion(-502038, (sha));
	unsigned char output[32];

#if (CRYPTLIB >= MBEDTLS_2_8_0 && CRYPTLIB <= MBEDTLS_MAX)
	mbedtls_sha256_finish_ret(&sha_ctx, output);
#else
	sha256_finish(&sha_ctx, output);
#endif
	memcpy(sha, output, sizeof(CRYPTSHA_T));
	memset(output, 0, sizeof(output));

	shaClean = YES;
}



/*****************************************************************************/
#else
#error "Please fix CRYPTLIB"
#endif

char *cryptShaAsString(CRYPTSHA_T *sha)
{
#define SHAASSTR_BUFF_SIZE ((2*sizeof(CRYPTSHA_T))+1)
#define SHAASSTR_BUFFERS 4
	static uint8_t c = 0;
	static char out[SHAASSTR_BUFFERS][SHAASSTR_BUFF_SIZE];
	uint8_t i;

	if (!sha)
		return NULL;

	c = (c + 1) % SHAASSTR_BUFFERS;

	for (i = 0; i < (sizeof(CRYPTSHA_T) / sizeof(uint32_t)); i++)
		sprintf(&(out[c][i * 8]), "%.8X", ntohl(sha->h.u32[i]));

	return out[c];
}

char *cryptShaAsShortStr(CRYPTSHA_T *sha)
{
#define SHAASSHORT_BUFF_SIZE ((2*sizeof(uint32_t))+1)
#define SHAASSHORT_BUFFERS 4
	static uint8_t c = 0;
	static char out[SHAASSHORT_BUFFERS][SHAASSHORT_BUFF_SIZE];

	if (!sha)
		return NULL;

	c = (c + 1) % SHAASSHORT_BUFFERS;

	sprintf(out[c], "%.8X", ntohl(sha->h.u32[0]));

	return out[c];
}

int cryptShasEqual(CRYPTSHA_T *shaA, CRYPTSHA_T *shaB)
{
	return !memcmp(shaA, shaB, sizeof(CRYPTSHA_T));
}

uint8_t cryptRsaKeyTypeByLen(int len)
{
	return len == CRYPT_RSA512_LEN ? CRYPT_RSA512_TYPE : (
		len == CRYPT_RSA768_LEN ? CRYPT_RSA768_TYPE : (
		len == CRYPT_RSA896_LEN ? CRYPT_RSA896_TYPE : (
		len == CRYPT_RSA1024_LEN ? CRYPT_RSA1024_TYPE : (
		len == CRYPT_RSA1536_LEN ? CRYPT_RSA1536_TYPE : (
		len == CRYPT_RSA2048_LEN ? CRYPT_RSA2048_TYPE : (
		len == CRYPT_RSA3072_LEN ? CRYPT_RSA3072_TYPE : (
		len == CRYPT_RSA4096_LEN ? CRYPT_RSA4096_TYPE : (
		0))))))));
}

uint16_t cryptRsaKeyLenByType(int type)
{
	return type == CRYPT_RSA512_TYPE ? CRYPT_RSA512_LEN : (
		type == CRYPT_RSA768_TYPE ? CRYPT_RSA768_LEN : (
		type == CRYPT_RSA896_TYPE ? CRYPT_RSA896_LEN : (
		type == CRYPT_RSA1024_TYPE ? CRYPT_RSA1024_LEN : (
		type == CRYPT_RSA1536_TYPE ? CRYPT_RSA1536_LEN : (
		type == CRYPT_RSA2048_TYPE ? CRYPT_RSA2048_LEN : (
		type == CRYPT_RSA3072_TYPE ? CRYPT_RSA3072_LEN : (
		type == CRYPT_RSA4096_TYPE ? CRYPT_RSA4096_LEN : (
		0))))))));
}

char *cryptRsaKeyTypeAsString(int type)
{
	return type == CRYPT_RSA512_TYPE ? CRYPT_RSA512_NAME : (
		type == CRYPT_RSA768_TYPE ? CRYPT_RSA768_NAME : (
		type == CRYPT_RSA896_TYPE ? CRYPT_RSA896_NAME : (
		type == CRYPT_RSA1024_TYPE ? CRYPT_RSA1024_NAME : (
		type == CRYPT_RSA1536_TYPE ? CRYPT_RSA1536_NAME : (
		type == CRYPT_RSA2048_TYPE ? CRYPT_RSA2048_NAME : (
		type == CRYPT_RSA3072_TYPE ? CRYPT_RSA3072_NAME : (
		type == CRYPT_RSA4096_TYPE ? CRYPT_RSA4096_NAME : (
		NULL))))))));
}

void init_crypt(void)
{
	cryptRngInit();
	cryptShaInit();

	unsigned int random;
	cryptRand(&random, sizeof(random));
	srand(random);

	CRYPTSHA_T doubleSha[2];
	memset(&doubleSha, 0, sizeof(doubleSha));
	cryptShaAtomic(&random, sizeof(random), &doubleSha[0]);
	assertion(-502763, (!is_zero(&doubleSha[0], sizeof(CRYPTSHA_T))));
	assertion(-502764, (is_zero(&doubleSha[1], sizeof(CRYPTSHA_T))));


}

void cleanup_crypt(void)
{
	cryptRsaKeyFree(&my_PrivKey);

	cryptRngFree();
	cryptShaFree();
}
