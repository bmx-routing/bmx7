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


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <zlib.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "allocate.h"
#include "z.h"


//inspired by: http://www.zlib.net/zpipe.c

//compress
/*
 * on success and if available and when finished stores uncompressed data to:
 * *dst + dlen (which is reallocated) and
 * darr and returns compressed data size.
 * Therefore, src and *dst can point to same memory area !
 * on failure leaves dst untouched and returnes -1
 */
int32_t z_compress( uint8_t *src, int32_t slen, uint8_t **dst, uint32_t dpos, uint8_t *darr, int32_t darr_max_size)
{
	
    z_stream strm = {.zalloc = Z_NULL, .zfree = Z_NULL, .opaque = Z_NULL};
    int32_t tlen = 0;
    uint8_t *tmp = NULL;
    int z_ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);

    if (z_ret != Z_OK)
        return FAILURE;

    strm.avail_in = slen;
    strm.next_in = src;

    do {
	    tmp = debugRealloc(tmp, tlen + Z_CHUNK_SIZE, -300573);

	    strm.avail_out = Z_CHUNK_SIZE;
	    strm.next_out = tmp + tlen;

	    if ((z_ret = deflate(&strm, Z_FINISH)) != Z_OK && z_ret != Z_STREAM_END) { //== Z_STREAM_ERROR) {
		    dbgf_sys(DBGT_ERR, "slen=%d tlen=%d z_ret=%d error: %s ???", slen, tlen, z_ret, strerror(errno));
		    tlen = FAILURE;
		    break;
	    } else {
		    tlen += (Z_CHUNK_SIZE - strm.avail_out);
	    }

    } while (strm.avail_out == 0);

    if (tmp && tlen > 0 && tlen < slen) {
	    if (dst) {
		    *dst = debugRealloc(*dst, dpos + tlen, -300574);
		    memcpy(*dst + dpos, tmp, tlen);
	    }
	    if (darr && darr_max_size >= tlen)
		    memcpy(darr, tmp, tlen);

    } else if (tmp && tlen >= slen) {
	    tlen = 0;

    } else {
	    tlen = FAILURE;
    }

    (void)deflateEnd(&strm);

    if (tmp)
	    debugFree(tmp, -300575);

    dbgf(tlen>=0?DBGL_CHANGES:DBGL_SYS, tlen>=0?DBGT_INFO:DBGT_ERR, "slen=%d tlen=%d", slen, tlen);

    return tlen;
}



//decompress:
/*
 * on success and when finished, returns new compressed size and adds to (*dst) + dpos
 * Therefore src and *dst can point to same memory area.
 * on failure returns -1 and (*dst) is untouched
 * if dst == NULL then dst is untouched
 */
int32_t z_decompress( uint8_t *src, uint32_t slen, uint8_t **dst, uint32_t dpos) {

	uint8_t *tmp = NULL;
	int32_t tlen = 0;
	int z_ret;

	z_stream strm = {.zalloc = Z_NULL, .zfree = Z_NULL, .opaque = Z_NULL, .avail_in = 0, .next_in = Z_NULL};

	if ((z_ret=inflateInit(&strm)) != Z_OK)
		return FAILURE;

	strm.avail_in = slen;
	strm.next_in = (Bytef*)src;

	do {
		tmp = debugRealloc(tmp, tlen + Z_CHUNK_SIZE, -300576);

		strm.avail_out = Z_CHUNK_SIZE;
		strm.next_out = tmp;

		if (tlen >= (INT32_MAX - Z_CHUNK_SIZE) || (((z_ret=inflate(&strm, Z_NO_FLUSH)) != Z_OK) && z_ret != Z_STREAM_END)) {
//		if (err==Z_STREAM_ERROR || err==Z_NEED_DICT || err==Z_DATA_ERROR || err==Z_MEM_ERROR) {
			dbgf_sys(DBGT_ERR, "slen=%d tlen=%d z_ret=%d error: %s ???", slen, tlen, z_ret, strerror(errno));
			tlen = FAILURE;
			break;
		}

		tlen += (Z_CHUNK_SIZE - strm.avail_out);

        } while (strm.avail_out == 0);

	// clean up and return:
	(void)inflateEnd(&strm);

	if (dst && tmp && tlen > 0) {
		*dst = debugRealloc(*dst, dpos + tlen, -300577);
		memcpy( (*dst) + dpos, tmp, tlen);
	}

	if(tmp)
		debugFree(tmp, -300578);

	dbgf(tlen>0?DBGL_CHANGES:DBGL_SYS, tlen>0?DBGT_INFO:DBGT_ERR, "slen=%d tlen=%d", slen, tlen);

	return tlen;
}

