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
 *
 * Contributors:
 *	Simó Albert i Beltran
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <glob.h>
#include <limits.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "tools.h"
#include "allocate.h"

char *strToLower(char *s)
{
	uint32_t i;
	for (i = 0; s[i]; i++)
		s[i] = tolower(s[i]);

	return s;
}

char* memAsHexStringSep( const void* mem, uint32_t len, uint16_t seperationLen, char *seperator)
{
#define MEMASSTR_BUFF_SIZE 2048
#define MEMASSTR_BUFFERS 4
#define MEMASSTR_STEP_SIZE 2
#define TRAILER_LEN 4
        seperationLen = (seperationLen && seperationLen<len) ? seperationLen : MEMASSTR_BUFF_SIZE;
	static uint8_t c=0;
        static char out[MEMASSTR_BUFFERS][MEMASSTR_BUFF_SIZE];
        uint32_t i = 0, l = 0;

        if (!mem)
                return NULL;

        c = (c+1) % MEMASSTR_BUFFERS;

        while (l < len && i < (MEMASSTR_BUFF_SIZE - TRAILER_LEN)) {

                i += sprintf(&(out[c][i]), "%s%.2X", ((l && !(l % seperationLen)) ? (seperator?seperator:" ") : ""), ((uint8_t*) mem)[l]);
                l++;
        }

        if (l < len)
                i += sprintf(&(out[c][i]), "...");

        out[c][i] = 0;

        return out[c];
}

char* memAsHexString( const void* mem, uint32_t len)
{
        return memAsHexStringSep(mem, len, 0, NULL);
}

char* rmStrKeyValue(char* str, char* key)
{
	char *needleBegin = NULL, *needleVal = NULL, *needleEnd = NULL, *ret = NULL;
	char *haystack = debugMallocReset(strlen(str)+1, -300810);

	if (
		(strcpy(haystack, str)) &&
		(needleBegin = strstr(haystack, key)) &&
		(strlen(needleBegin) > strlen(key)) &&
		(needleVal = needleBegin + strlen(key)) &&
		(needleEnd = (strchr(needleVal, '.') ? strchr(needleVal, '.') : strchr(needleVal, 0))) &&
		(needleVal < needleEnd)
		) {

		memset(str, 0, strlen(str));

		if (haystack < needleBegin)
			strncpy(str + strlen(str), haystack, (needleBegin - haystack));

		if (*needleEnd != 0)
			strcpy(str + strlen(str), needleEnd);

		*needleEnd = 0;

		strcpy(str + strlen(str) + 1, needleBegin);

		ret = (str + strlen(str) + 1 + (needleVal - needleBegin));
	}


	dbgf_all(DBGT_INFO, "in=%s key=%s beg=%s val=%s end=%s ret=%s, out=%s", haystack, key, needleBegin, needleVal, needleEnd, ret, str);
	debugFree(haystack, -300811);
	return ret;
}

IDM_T hexStrToMem(char *s, uint8_t *m, uint16_t mLen, uint8_t strict)
{
        assertion(-501291, (s && mLen));

	int l = XMIN(strlen(s), (2 * mLen));
        int o = (2 * mLen) - l;
        int p = 0;

        if(m)
                memset(m, 0, mLen);

        if (strict && (strlen(s) > 2 * mLen))
                return FAILURE;

	while (p < l) {

                char *endptr;

		if (s[p] != toupper(s[p]))
			return FAILURE;

                char c[2] = {s[p], 0};
                //c[0] = s[o];
                long int i = strtol(c, &endptr, 16);

                if (i > 15 || i < 0 || endptr != &(c[1]))
                        return FAILURE;

                if(m) {
                        if (((p + o) % 2) != 0)
                                m[((p + o) / 2)] += i;
                        else
                                m[((p + o) / 2)] += (i << 4);
                }

                p++;
        }

        return SUCCESS;
}

IDM_T check_string(char*s, char *okChars, char replaceChar)
{
	uint32_t i,j;

	for (i=0; i<strlen(s);i++) {
		IDM_T ok = NO;
		for (j=0;j<strlen(okChars);j++) {
			if (s[i] == okChars[j] ) {
				ok = YES;
				break;
			}
		}
		if (!ok) {
			if (replaceChar)
				s[i] = replaceChar;
			else
				return FAILURE;
		}
	}
	return SUCCESS;

}


IDM_T validate_char_string(const char* data, uint32_t len)
{

        uint32_t pos = 0;

        for (pos = 0; pos < len; pos++) {
                if (data[pos] < ' ' || data[pos] >= 0x7F /*delete according to man ascii(7)*/ ) {
                        dbgf_sys(DBGT_ERR, "stream len=%d pos=%d contains char=%d", len, pos, data[pos]);
                        return FAILURE;
                }
        }

        if (data[pos] != '\0') {
                return FAILURE;
                dbgf_sys(DBGT_ERR, "stream len=%d pos=%d not terminated with \\0", len, pos);
        }

        return SUCCESS;
}

IDM_T validate_name_string(char* name, uint32_t field_len, char* exceptions)
{
        uint32_t i, e, string_len = strlen(name);

        if (field_len && (string_len >= field_len || !is_zero(&name[string_len], field_len - string_len)))
                return FAILURE;

        for (i = 0; i < string_len; i++) {

                char c = name[i];

                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        c == '-' || c == '_' || (c == '.' && (i != 0 && i != (string_len - 1))))
                        continue;

                if (exceptions) {
                        for (e = 0; e < strlen(exceptions); e++) {
                                if (c == exceptions[e])
                                        break;
                        }

                        if (e < strlen(exceptions))
                               continue;
                }


                return FAILURE;
        }

        return SUCCESS;
}



char* memAsCharString( const char* mem, uint32_t len)
{
#define MEMASSTR_BUFF_SIZE 2048
#define MEMASSTR_BUFFERS 4
	static uint8_t c=0;
        static char out[MEMASSTR_BUFFERS][MEMASSTR_BUFF_SIZE];


        if (!mem)
                return NULL;

        len = XMIN(strlen(mem), len);

        if (len >= (MEMASSTR_BUFF_SIZE - 1) || validate_char_string(mem, len) == FAILURE)
                return NULL;

        c = (c+1) % MEMASSTR_BUFFERS;

        memcpy(out[c], mem, len);

        out[c][len] = 0;

        return out[c];
}

int32_t max_i32(int32_t a, int32_t b)
{
        return (a > b) ? a : b;
}

int32_t min_i32( int32_t a, int32_t b )
{
        return (a < b) ? a : b;
}



//http://en.wikipedia.org/wiki/Fast_inverse_square_root
//http://www.codemaestro.com/reviews/9
//http://www.beyond3d.com/content/articles/8/
float fast_inverse_sqrt(float x)
{
        float h = x / 2.0f;
        int32_t i;
        ASSERTION(-501045, (sizeof (i) == sizeof (x)));

        memcpy(&i, &x, sizeof (x));
        i = 0x5f3759df - (i >> 1);
        memcpy(&x, &i, sizeof (i));
        x = x * (1.5f - h * x * x);
        x = x * (1.5f - h * x * x);
        return x;
}


//TODO: check all callers: currently limit parameter defines the first out-of-range element and not the max legal one!
uint32_t rand_num(const uint32_t limit)
{

	return ( limit == 0 ? 0 : rand() % limit );
}

/* counting bits based on http://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetTable */

static unsigned char BitsSetTable256[256];

static
void init_set_bits_table256(void)
{
	BitsSetTable256[0] = 0;
	int i;
	for (i = 0; i < 256; i++)
	{
		BitsSetTable256[i] = (i & 1) + BitsSetTable256[i / 2];
	}
}


// clears byte range between and including begin and end
// accept overlap of begin and end
void byte_clear(uint8_t *array, uint32_t array_size, uint32_t begin, uint32_t end)
{

        assertion(-500436, (array_size % 2 == 0));

        begin = begin % array_size;
        end = end % array_size;

        memset(array + begin, 0, end >= begin ? end + 1 - begin : array_size - begin);

        if ( begin > end)
                memset(array, 0, end + 1);


}


// count the number of true bits in v
uint8_t bits_count(uint32_t v)
{
	uint8_t c=0;

	for (; v; v = v>>8 )
		c += BitsSetTable256[v & 0xff];

	return c;
}

uint8_t bit_get(const uint8_t *array, const uint32_t array_bit_size, uint32_t bit)
{
        bit = bit % array_bit_size;

        uint32_t byte_pos = bit / 8;
        uint8_t bit_pos = bit % 8;

        return (array[byte_pos] & (0x01 << (7 - bit_pos))) ? 1 : 0;
}

void bit_set(uint8_t *array, uint32_t array_bit_size, uint32_t bit, IDM_T value)
{
        bit = bit % array_bit_size;

        uint32_t byte_pos = bit / 8;
        uint8_t bit_pos = bit % 8;

        if (value)
                array[byte_pos] |= (0x01 << (7 - bit_pos));
        else
                array[byte_pos] &= ~(0x01 << (7 - bit_pos));

        assertion(-500415, (!value == !bit_get(array, array_bit_size, bit)));
}


uint32_t bits_get(uint8_t *array, uint32_t array_bit_size, uint32_t beg_bit, uint32_t end_bit, uint32_t range_mask)
{
        assertion(-502491, (array_bit_size % 8 == 0));
        assertion(-502492, ((range_mask & (end_bit - beg_bit)) < array_bit_size));

        uint32_t begin_byte = (beg_bit % array_bit_size) / 8;
        uint32_t end_byte = (end_bit % array_bit_size) / 8;
        uint32_t array_byte_size = array_bit_size / 8;

        uint32_t counted = 0;
        uint32_t pos = begin_byte;

        do {
                uint8_t val = array[pos];

                if (pos == begin_byte)
                        val = val & (0xFF >> (beg_bit % 8));

                if (pos == end_byte)
                        val = val & (0xFF << (7-(end_bit % 8)));

                counted += BitsSetTable256[val];

                pos = ((pos + 1) % array_byte_size);

        } while (pos != ((end_byte + 1) % array_byte_size));

        return counted;
}


// clears bit range between and including begin and end
 void bits_clear(uint8_t *array, uint32_t array_bit_size, uint32_t beg_bit, uint32_t end_bit, uint32_t range_mask)
{
        assertion(-500435, (array_bit_size % 8 == 0));
        assertion(-501060, ((range_mask & (end_bit - beg_bit)) < array_bit_size));

        uint32_t array_byte_size = array_bit_size / 8;


        beg_bit = beg_bit % array_bit_size;
        end_bit = end_bit % array_bit_size;

        uint32_t beg_byte = beg_bit/8;
        uint32_t end_byte = end_bit/8;


        if (beg_byte == end_byte  ?  (beg_bit % 8) > (end_bit % 8)  :  (beg_byte + 1) % array_byte_size != end_byte)
                byte_clear(array, array_byte_size, (beg_byte + 1) % array_byte_size, (end_byte - 1) % array_byte_size);


        uint8_t beg_mask = ~(0xFF >> (beg_bit % 8));       //eg 1: ~(01111111) = 10000000
        uint8_t end_mask = ~(0xFF << (7 - (end_bit % 8))); //eg 5: ~(11111100) = 00000011

        if (beg_byte == end_byte) {

                if ((beg_bit % 8) <= (end_bit % 8))
                        array[beg_byte] &= (beg_mask | end_mask);
                else
                        array[beg_byte] &= (beg_mask & end_mask);

        } else {

                array[beg_byte] &= beg_mask;
                array[end_byte] &= end_mask;
        }
}

char* bits_print(uint8_t *array, uint32_t array_bit_size, uint32_t beg_bit, uint32_t end_bit, uint32_t range_mask)
{
        assertion(-502493, (array_bit_size % 8 == 0));
        assertion(-502494, ((range_mask & (end_bit - beg_bit)) < array_bit_size));

#define BITS_PRINT_MAX 256
        assertion(-501059, ((uint32_t) (end_bit - beg_bit)) < array_bit_size);

        uint16_t c = 0;
        static char output[BITS_PRINT_MAX + 4];

        uint32_t pos = (beg_bit % array_bit_size);

        do {
                sprintf(&output[c], "%s", bit_get(array, array_bit_size, pos) ? "1" : "0");
                if ((++c) >=BITS_PRINT_MAX) {
                        sprintf(&output[c], "..");
                        c=c+2;
                        break;
                }

                pos = (pos + 1) % array_bit_size;

        } while (pos != ((end_bit + 1) % array_bit_size));

        output[c]=0;

        return output;
}



uint8_t is_zero(void *data, int32_t len)
{
        int32_t i;
        char *d = data;
        for (i = 0; i < len && !d[i]; i++);

        if ( i < len )
                return NO;

        return YES;
}

void bit_xor(void *out, void *a, void *b, uint32_t size)
{
	uint32_t p = 0;

	while (p < size) {

		if ((size - p) >= sizeof(uint64_t)) {
			*((uint64_t*) &(((uint8_t*) out)[p])) = (*((uint64_t*) &(((uint8_t*) a)[p]))) ^ (*((uint64_t*) &(((uint8_t*) b)[p])));
			p += sizeof(uint64_t);
		} else if ((size - p) >= sizeof(uint32_t)) {
			*((uint32_t*) &(((uint8_t*) out)[p])) = (*((uint32_t*) &(((uint8_t*) a)[p]))) ^ (*((uint32_t*) &(((uint8_t*) b)[p])));
			p += sizeof(uint32_t);
		} else if ((size - p) >= sizeof(uint16_t)) {
			*((uint16_t*) &(((uint8_t*) out)[p])) = (*((uint16_t*) &(((uint8_t*) a)[p]))) ^ (*((uint16_t*) &(((uint8_t*) b)[p])));
			p += sizeof(uint16_t);
		} else if ((size - p) >= sizeof(uint8_t)) {
			*((uint8_t*) &(((uint8_t*) out)[p])) = (*((uint8_t*) &(((uint8_t*) a)[p]))) ^ (*((uint8_t*) &(((uint8_t*) b)[p])));
			p += sizeof(uint8_t);
		}
	}
	assertion(-502609, (p == size));
}



int32_t check_file(char *path, uint8_t regular, uint8_t read, uint8_t write, uint8_t exec) {

	struct stat fstat;

	errno = 0;
	int stat_ret = stat( path, &fstat );

	if ( stat_ret  < 0 ) {

                dbgf_mute(20, DBGL_CHANGES, DBGT_WARN, "%s does not exist! (%s)", path, strerror(errno));

	} else {

                if ((!regular || (S_ISREG(fstat.st_mode))) &&
                        (!read || (S_IRUSR & fstat.st_mode)) &&
                        (!write || (S_IWUSR & fstat.st_mode)) &&
                        (!exec || (S_IXUSR & fstat.st_mode)))
                        return SUCCESS;

                dbgf_mute(25, DBGL_CHANGES, DBGT_ERR, "%s exists but has inappropriate permissions (%s)", path, strerror(errno));

	}

	return FAILURE;
}



int32_t check_dir( char *path, uint8_t create, uint8_t write, uint8_t onlyBasePath ) {

	struct stat fstat;
	char tmp_path[MAX_PATH_SIZE] = "";
	strcpy( tmp_path, path );
	char *slash;

	if (onlyBasePath && (slash = strrchr(tmp_path, '/')) && slash != tmp_path)
		*slash = 0;

	errno = 0;
	int stat_ret = stat( tmp_path, &fstat );

	if ( stat_ret >= 0 ) {

		if ( S_ISDIR( fstat.st_mode )  &&
		     ( S_IRUSR & fstat.st_mode)  &&
		     ( S_IXUSR & fstat.st_mode)  &&
		     ((S_IWUSR & fstat.st_mode) || !write) )
			return SUCCESS;

                dbgf_sys(DBGT_ERR, "directory %s exists but has inappropriate permissions (%s)", path, strerror(errno));

	} else {

		if (create && (slash = strrchr(tmp_path, '/')) && slash != tmp_path)
			check_dir( tmp_path, create, write, YES);

		if ( create && mkdir( tmp_path, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH ) >= 0 )
			return SUCCESS;

                dbgf_sys(DBGT_ERR, "directory %s does not exist and can not be created (%s)", tmp_path, strerror(errno));
	}

	return FAILURE;
}


int32_t rm_dir_content(char* dir_name, char* prefix)
{

        assertion(-501287, dir_name);

        struct dirent *d;
        DIR *dir ;

        if ((dir = opendir(dir_name))) {

                while ((d = readdir(dir))) {

                        if (!prefix || !strncmp(d->d_name, prefix, strlen(prefix))) {

                                char rm_file[MAX_PATH_SIZE];
                                sprintf(rm_file, "%s/%s", dir_name, d->d_name);

                                if (validate_name_string(d->d_name, strlen(d->d_name) + 1, ":") == SUCCESS) {

                                        dbgf_track(DBGT_INFO, "removing stale file: %s", rm_file);

                                        if (remove(rm_file) != 0) {
                                                dbgf_sys(DBGT_ERR, "could not remove file %s: %s",
                                                        rm_file, strerror(errno));
                                                return FAILURE;
                                        }
                                } else {
                                        dbgf_track(DBGT_INFO, "keeping file: %s", rm_file);
                                }
                        }
                }
                closedir(dir);
                return SUCCESS;
        } else {
                dbgf_sys(DBGT_ERR, "failed opening dir=%s : %s", dir_name, strerror(errno));
                return FAILURE;
        }
}


uint32_t wordlen ( char *s ) {

	uint32_t i = 0;

	if ( !s )
		return 0;

	for( i=0; i<strlen(s); i++ ) {

		if ( s[i] == '\0' || s[i] == '\n' || s[i]==' ' || s[i]=='\t' )
			return i;
	}

	return i;
}


int8_t wordsEqual ( char *a, char *b ) {

	if ( wordlen( a ) == wordlen ( b )  &&  !strncmp( a, b, wordlen(a) ) )
		return YES;

	return NO;
}


void wordCopy( char *out, char *in ) {

	if ( out  &&  in  &&  wordlen(in) < MAX_ARG_SIZE ) {

		snprintf( out, wordlen(in)+1, "%s", in );

	} else if ( out && !in ) {

		out[0]=0;

	} else {

                dbgf_sys(DBGT_ERR, "called with out: %s  and  in: %s", out, in);
		cleanup_all( -500017 );

	}
}

uint8_t *find_array_data(uint8_t *arr, uint32_t arrLen, uint8_t *element, uint32_t elemLen) {

	uint32_t p;

	if (!arr || !arrLen || !element || !elemLen)
		return NULL;

	for(p=0; p < arrLen; p+=elemLen ) {

		if ( !memcmp(&arr[p], element, elemLen) )
			return &arr[p];
	}

	return NULL;
}


#ifdef WITH_DEVEL

struct ring_buffer {
	uint16_t field_size;
	uint16_t elements;
        uint16_t pos;
	void *buffer;
};

struct ring_buffer *create_ring_buffer(uint16_t field_size, uint16_t elements)
{
        struct ring_buffer *ring = debugMalloc(sizeof (struct ring_buffer), -300316);
        ring->field_size = field_size;
        ring->elements = elements;
        ring->pos = 0;
        ring->buffer = debugMalloc(field_size*elements, -300317);
        memset(ring->buffer, 0, field_size * elements);
        
}

static const char LogTable256[256] =
{
#define LT(n) n, n, n, n, n, n, n, n, n, n, n, n, n, n, n, n
    -1, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
    LT(4), LT(5), LT(5), LT(6), LT(6), LT(6), LT(6),
    LT(7), LT(7), LT(7), LT(7), LT(7), LT(7), LT(7), LT(7)
};

uint32_t log_bin(uint32_t v)
{

        //unsigned int v; // 32-bit word to find the log of
        uint32_t r; // r will be lg(v)
        uint32_t t, tt; // temporaries

        if ((tt = v >> 16)) {
                r = ((t = tt >> 8)) ? 24 + LogTable256[t] : 16 + LogTable256[tt];
        } else {
                r = ((t = v >> 8)) ? 8 + LogTable256[t] : LogTable256[v];
        }

        return r;
}
#endif

/* recurse down layer-2 interfaces until we hit a layer-1 interface using Linux' sysfs */
int interface_get_lowest(char *hwifname, const char *ifname) {
	int ret;
	glob_t globbuf;
	char *lowentry = NULL;
	char *buf, *phypath;
	char *fnamebuf = debugMalloc(1 + strlen(VIRTIF_PREFIX) + IF_NAMESIZE + strlen(LOWERGLOB_SUFFIX), -300321);
	ssize_t len;

	sprintf(fnamebuf, "%s%s%s", VIRTIF_PREFIX, ifname, LOWERGLOB_SUFFIX);
	glob(fnamebuf, GLOB_NOSORT | GLOB_NOESCAPE, NULL, &globbuf);

	if (globbuf.gl_pathc == 1) {
		lowentry = debugMalloc(1 + strlen(globbuf.gl_pathv[0]), -300322);
		strncpy(lowentry, globbuf.gl_pathv[0], 1 + strlen(globbuf.gl_pathv[0]));
	}

	globfree(&globbuf);
	debugFree(fnamebuf, -300321);

	if (!lowentry) {
		/* no lower interface found, check if physical interface exists */
		phypath = debugMalloc(1 + strlen(NETIF_PREFIX) + strlen(ifname), -300323);
		sprintf(phypath, "%s%s", NETIF_PREFIX, ifname);

		ret = access(phypath, F_OK);
		debugFree(phypath, -300323);

		if (ret != 0)
			return FAILURE;

		strncpy(hwifname, ifname, IF_NAMESIZE - 1);
		dbgf_sys(DBGT_INFO, "got %s", hwifname);
		return SUCCESS;

	} else {
		/* lower interface found, recurse down */
		buf = debugMalloc(PATH_MAX, -300324);

		len = readlink(lowentry, buf, PATH_MAX - 1);
		debugFree(lowentry, -300322);

		if (len != -1) {
			buf[len] = '\0';
		} else {
			/* readlink failed */
			debugFree(buf, -300324);
			return FAILURE;
		}

		if (strncmp(buf, "../", 3) == 0) {
			ret = interface_get_lowest(hwifname, strrchr(buf, '/') + 1);
			debugFree(buf, -300324);
			return ret;
		} else {
			debugFree(buf, -300324);
			return FAILURE;
		}

	}
}


void init_tools( void )
{
        init_set_bits_table256();

/*
#ifdef TEST_BIT_ARRAY_OPERATIONS
#define TOOL_WINDOW_BYTES 16
#define TOOL_WINDOW_BITS (TOOL_WINDOW_BYTES*8)
        uint8_t array[TOOL_WINDOW_BYTES];
        memset(array, 0, TOOL_WINDOW_BYTES);
        uint16_t i;
        for (i = 0; i < TOOL_WINDOW_BITS;) {
                bit_set(array, TOOL_WINDOW_BITS, i, 1);
                i++;
                uint16_t bits = bits_get(array, TOOL_WINDOW_BITS, 0, TOOL_WINDOW_BITS - 1);
                dbgf_sys(DBGT_INFO, "i=%3d array_bits=%3d >%s<",
                        i, bits, bits_print(array, TOOL_WINDOW_BITS, 0, TOOL_WINDOW_BITS - 1));
                ASSERTION(-501057, (i==bits));
        }

#endif
*/

}

