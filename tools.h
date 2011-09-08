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

#define XOR( a, b ) ( !(a) != !(b) )
#define IMPLIES( a, b ) ( !(a) || (b) )


// LOG2(val=0)=0, LOG2(val=1)=0, LOG2(val=2)=1, LOG2(val=3)=1, LOG2(val=4)=2, ...
#define LOG2(result, val, VAL_TYPE)                                             \
        do {                                                                    \
                VAL_TYPE val_tmp = val;                                         \
                uint8_t j = ((8 * sizeof (VAL_TYPE) ) >> 1 );                   \
                result = 0;                                                     \
                for (; val_tmp > 0x01; j >>= 1) {                               \
                        if (val_tmp >> j) {                                     \
                                result += j;                                    \
                                val_tmp >>= j;                                  \
                        }                                                       \
                }                                                               \
        } while(0)












IDM_T hexStrToMem(char *s, uint8_t *m, uint16_t mLen);
char* memAsHexString( const void* mem, uint32_t len);
char* memAsCharString( const char* mem, uint32_t len);

IDM_T validate_char_string (const char* data, uint32_t len);
IDM_T validate_name_string(char* name, uint32_t field_len);

char *globalIdAsString( struct GLOBAL_ID *id );


int32_t max_i32( int32_t a, int32_t b );
int32_t min_i32( int32_t a, int32_t b );

float fast_inverse_sqrt(float x);

uint32_t rand_num(const uint32_t limit);

void byte_clear(uint8_t *array, uint16_t array_size, uint16_t begin, uint16_t range);
uint8_t bits_count(uint32_t v);
uint8_t bit_get(const uint8_t *array, const uint16_t array_bit_size, uint16_t bit);

void bit_set(uint8_t *array, uint16_t array_bit_size, uint16_t bit, IDM_T value);

uint16_t bits_get(uint8_t *array, uint16_t array_bit_size, uint16_t begin_bit, uint16_t end_bit);

void bits_clear(uint8_t *array, uint16_t array_bit_size, uint16_t begin, uint16_t end);

char* bits_print(uint8_t *array, uint16_t array_bit_size, uint16_t begin_bit, uint16_t end_bit);


uint8_t is_zero(void *data, int len);


IDM_T str2netw(char* args, IPX_T *ipX, struct ctrl_node *cn, uint8_t *maskp, uint8_t *familyp);

int8_t wordsEqual ( char *a, char *b );
void wordCopy( char *out, char *in );
uint32_t wordlen ( char *s );
int32_t check_file( char *path, uint8_t write, uint8_t exec );
int32_t check_dir( char *path, uint8_t create, uint8_t write );
int32_t rm_dir_content(char* dir_name);


void init_tools(void);

