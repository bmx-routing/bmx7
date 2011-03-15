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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include "bmx.h"
#include "ip.h"
#include "tools.h"

char* memAsStr( const void* mem, const uint32_t len)
{
#define MEMASSTR_BUFF_SIZE 2048
#define MEMASSTR_BUFFERS 2
#define MEMASSTR_STEP_SIZE 2
	static uint8_t c=0;
        static char out[2][MEMASSTR_BUFF_SIZE];
        uint32_t i;

        if (!mem)
                return NULL;

        c = (c+1) % MEMASSTR_BUFFERS;

        for (i = 0; i < len && i < ((MEMASSTR_BUFF_SIZE / MEMASSTR_STEP_SIZE) - MEMASSTR_STEP_SIZE); i++) {

                sprintf(&(out[c][i * MEMASSTR_STEP_SIZE]), "%.2X", ((uint8_t*) mem)[i]);
        }

        if (len > i)
                snprintf(&(out[c][(i - 1) * MEMASSTR_STEP_SIZE]), MEMASSTR_STEP_SIZE, "..");

        out[c][i * MEMASSTR_STEP_SIZE] = 0;

        return out[c];
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
void byte_clear(uint8_t *array, uint16_t array_size, uint16_t begin, uint16_t end)
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

uint8_t bit_get(const uint8_t *array, const uint16_t array_bit_size, uint16_t bit)
{
        bit = bit % array_bit_size;

        uint16_t byte_pos = bit / 8;
        uint8_t bit_pos = bit % 8;

        return (array[byte_pos] & (0x01 << bit_pos)) ? 1 : 0;
}

void bit_set(uint8_t *array, uint16_t array_bit_size, uint16_t bit, IDM_T value)
{
        bit = bit % array_bit_size;

        uint16_t byte_pos = bit / 8;
        uint8_t bit_pos = bit % 8;

        if (value)
                array[byte_pos] |= (0x01 << bit_pos);
        else
                array[byte_pos] &= ~(0x01 << bit_pos);

        assertion(-500415, (!value == !bit_get(array, array_bit_size, bit)));
}


uint16_t bits_get(uint8_t *array, uint16_t array_bit_size, uint16_t begin_bit, uint16_t end_bit)
{
        assertion(-501058, ((uint16_t) (end_bit - begin_bit)) < array_bit_size);

        uint16_t begin_byte = (begin_bit % array_bit_size) / 8;
        uint16_t end_byte = (end_bit % array_bit_size) / 8;
        uint16_t array_byte_size = array_bit_size / 8;

        uint16_t counted = 0;
        uint16_t pos = begin_byte;

        do {
                uint8_t val = array[pos];

                if (pos == begin_byte)
                        val = val & (0xFF << (begin_bit % 8));

                if (pos == end_byte)
                        val = val & (0xFF >> (7-(end_bit % 8)));

                counted += BitsSetTable256[val];

                pos = ((pos + 1) % array_byte_size);

        } while (pos != ((end_byte + 1) % array_byte_size));

        return counted;
}


// clears bit range between and including begin and end
 void bits_clear(uint8_t *array, uint16_t array_bit_size, uint16_t begin_bit, uint16_t end_bit)
{
        assertion(-500435, (array_bit_size % 8 == 0));
        assertion(-501060, ((uint16_t) (end_bit - begin_bit)) < array_bit_size);

        uint16_t array_byte_size = array_bit_size / 8;

/*
        if (((uint16_t) (end_bit - begin_bit)) >= array_bit_size) {
                memset(array, 0, array_byte_size);
                return;
        }
*/

        begin_bit = begin_bit % array_bit_size;
        end_bit = end_bit % array_bit_size;

        uint16_t begin_byte = begin_bit/8;
        uint16_t end_byte = end_bit/8;


        if (begin_byte != end_byte && ((begin_byte + 1) % array_byte_size) != end_byte)
                byte_clear(array, array_byte_size, begin_byte + 1, end_byte - 1);


        uint8_t begin_mask = ~(0xFF << (begin_bit % 8));   //eg 2: ~(11111100) = 00000011
        uint8_t end_mask =   ~(0xFF >> (7-(end_bit % 8))); //eg 3: ~(00001111) = 11110000

        if (begin_byte == end_byte) {

                array[begin_byte] &= (begin_mask | end_mask);

        } else {

                array[begin_byte] &= begin_mask;
                array[end_byte] &= end_mask;
        }
}

char* bits_print(uint8_t *array, uint16_t array_bit_size, uint16_t begin_bit, uint16_t end_bit)
{
#define BITS_PRINT_MAX 256
        assertion(-501059, ((uint16_t) (end_bit - begin_bit)) < array_bit_size);

        uint16_t c = 0;
        static char output[BITS_PRINT_MAX + 4];

        uint16_t pos = (begin_bit % array_bit_size);

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



uint8_t is_zero(void *data, int len)
{
        int i;
        char *d = data;
        for (i = 0; i < len && !d[i]; i++);

        if ( i < len )
                return NO;

        return YES;
}






IDM_T str2netw(char* args, IPX_T *ipX, char delimiter, struct ctrl_node *cn, uint8_t *maskp, uint8_t *familyp)
{

	char *slashptr = NULL;

        char switch_arg[IP6NET_STR_LEN] = {0};

	if ( wordlen( args ) < 1 || wordlen( args ) >= IP6NET_STR_LEN )
		return FAILURE;

	wordCopy( switch_arg, args );
	switch_arg[wordlen( args )] = '\0';

	if ( maskp ) {

                if ((slashptr = strchr(switch_arg, delimiter))) {
			char *end = NULL;

			*slashptr = '\0';

			errno = 0;
                        int mask = strtol(slashptr + 1, &end, 10);

			if ( ( errno == ERANGE ) || mask > 128 || mask < 0 ) {

				dbgf_cn( cn, DBGL_SYS, DBGT_ERR, "invalid argument %s %s",
				         args, strerror( errno ) );

				return FAILURE;

			} else if ( end==slashptr+1 ||  wordlen(end) ) {

				dbgf_cn( cn, DBGL_SYS, DBGT_ERR, "invalid argument trailer %s", end );
				return FAILURE;
			}

                        *maskp = mask;

		} else {

			dbgf_cn( cn, DBGL_SYS, DBGT_ERR, "invalid argument %s! Fix you parameters!", switch_arg );
			return FAILURE;
		}
	}

	errno = 0;

        struct in_addr in4;
        struct in6_addr in6;

        if ((inet_pton(AF_INET, switch_arg, &in4) == 1) && (!maskp || *maskp <= 32)) {

                ip42X(ipX, in4.s_addr);

                if (familyp)
                        *familyp = AF_INET;

                return SUCCESS;

        } else

                if ((inet_pton(AF_INET6, switch_arg, &in6) == 1) && (!maskp || *maskp <= 128)) {

                *ipX = in6;

                if (familyp)
                        *familyp = AF_INET6;

                return SUCCESS;
        }

        dbgf_all(DBGT_WARN, "invalid argument: %s: %s", args, strerror(errno));
        return FAILURE;
}




int32_t check_file( char *path, uint8_t write, uint8_t exec ) {

	struct stat fstat;

	errno = 0;
	int stat_ret = stat( path, &fstat );

	if ( stat_ret  < 0 ) {

                dbgf_track(DBGT_WARN, "%s does not exist! (%s)", path, strerror(errno));

	} else {

		if ( S_ISREG( fstat.st_mode )  &&
		     (S_IRUSR & fstat.st_mode)  &&
		     ((S_IWUSR & fstat.st_mode) || !write) &&
		     ((S_IXUSR & fstat.st_mode) || !exec) )
			return SUCCESS;

                dbgf_sys(DBGT_ERR, "%s exists but has inapropriate permissions (%s)", path, strerror(errno));

	}

	return FAILURE;
}

int32_t check_dir( char *path, uint8_t create, uint8_t write ) {

	struct stat fstat;

	errno = 0;
	int stat_ret = stat( path, &fstat );

	if ( stat_ret < 0 ) {

		if ( create && mkdir( path, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH ) >= 0 )
			return SUCCESS;

                dbgf_sys(DBGT_ERR, "directory %s does not exist and can not be created (%s)", path, strerror(errno));

	} else {

		if ( S_ISDIR( fstat.st_mode )  &&
		     ( S_IRUSR & fstat.st_mode)  &&
		     ( S_IXUSR & fstat.st_mode)  &&
		     ((S_IWUSR & fstat.st_mode) || !write) )
			return SUCCESS;

                dbgf_sys(DBGT_ERR, "directory %s exists but has inapropriate permissions (%s)", path, strerror(errno));

	}

	return FAILURE;
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


#ifdef WITH_UNUSED

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