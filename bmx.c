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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <linux/rtnetlink.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "ogm.h"
#include "link.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "ip.h"
#include "hna.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "plugin.h"
#include "allocate.h"
#include "prof.h"

#define CODE_CATEGORY_NAME "general"


int32_t my_compatibility = DEF_COMPATIBILITY;

int32_t my_conformance_tolerance = DEF_CONFORMANCE_TOLERANCE;

char my_Hostname[MAX_HOSTNAME_LEN] = "";


int32_t dad_to = DEF_DAD_TO;

uint16_t my_desc_capabilities = MY_DESC_CAPABILITIES;


const IPX_T  ZERO_IP = { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } };
const MAC_T  ZERO_MAC = {{0}};
const ADDR_T ZERO_ADDR = {{0}};

const struct net_key ZERO_NET_KEY = ZERO_NET_KEY_INIT;
const struct net_key ZERO_NET4_KEY = ZERO_NET4_KEY_INIT;
const struct net_key ZERO_NET6_KEY = ZERO_NET6_KEY_INIT;


IDM_T terminating = 0;
IDM_T initializing = YES;
IDM_T cleaning_up = NO;

const IDM_T CONST_YES = YES;
const IDM_T CONST_NO = NO;






TIME_T bmx_time = 0;
TIME_SEC_T bmx_time_sec = 0;


uint32_t s_curr_avg_cpu_load = 0;


AVL_TREE(status_tree, struct status_handl, status_name);


IDM_T validate_param(int32_t probe, int32_t min, int32_t max, char *name)
{

        if ( probe < min || probe > max ) {

                dbgf_sys(DBGT_ERR, "Illegal %s parameter value %d ( min %d  max %d )", name, probe, min, max);

                return FAILURE;
        }

        return SUCCESS;
}



/***********************************************************
 Runtime Infrastructure
************************************************************/


#ifndef NO_TRACE_FUNCTION_CALLS
static char* function_call_buffer_name_array[FUNCTION_CALL_BUFFER_SIZE] = {0};
static TIME_T function_call_buffer_time_array[FUNCTION_CALL_BUFFER_SIZE] = {0};
static uint8_t function_call_buffer_pos = 0;

static void debug_function_calls(void)
{
        uint8_t i;
        for (i = function_call_buffer_pos + 1; i != function_call_buffer_pos; i = ((i+1) % FUNCTION_CALL_BUFFER_SIZE)) {

                if (!function_call_buffer_name_array[i])
                        continue;

                dbgf_sys(DBGT_ERR, "%10d %s()", function_call_buffer_time_array[i], function_call_buffer_name_array[i]);

        }
}


void trace_function_call(const char *func)
{
        if (function_call_buffer_name_array[function_call_buffer_pos] != func) {
                function_call_buffer_time_array[function_call_buffer_pos] = bmx_time;
                function_call_buffer_name_array[function_call_buffer_pos] = (char*)func;
                function_call_buffer_pos = ((function_call_buffer_pos+1) % FUNCTION_CALL_BUFFER_SIZE);
        }
}


#endif

char *get_human_uptime(uint32_t reference)
{
	//                  DD:HH:MM:SS
	static char ut[32]="00:00:00:00";

	sprintf( ut, "%i:%i%i:%i%i:%i%i",
	         (((bmx_time_sec-reference)/86400)),
	         (((bmx_time_sec-reference)%86400)/36000)%10,
	         (((bmx_time_sec-reference)%86400)/3600)%10,
	         (((bmx_time_sec-reference)%3600)/600)%10,
	         (((bmx_time_sec-reference)%3600)/60)%10,
	         (((bmx_time_sec-reference)%60)/10)%10,
	         (((bmx_time_sec-reference)%60))%10
	       );

	return ut;
}


void wait_sec_msec(TIME_SEC_T sec, TIME_T msec)
{

        TRACE_FUNCTION_CALL;
	struct timeval time;

	//no debugging here because this is called from debug_output() -> dbg_fprintf() which may case a loop!

	time.tv_sec = sec + (msec/1000) ;
	time.tv_usec = ( msec * 1000 ) % 1000000;

	select( 0, NULL, NULL, NULL, &time );

	return;
}

static void handler(int32_t sig)
{

        TRACE_FUNCTION_CALL;
	if ( !Client_mode ) {
                dbgf_sys(DBGT_ERR, "called with signal %d", sig);
	}

	printf("\n");// to have a newline after ^C

	terminating = YES;
}





static void segmentation_fault(int32_t sig)
{
        TRACE_FUNCTION_CALL;
        static int segfault = NO;

        if (!segfault) {

                segfault = YES;

                dbg_sys(DBGT_ERR, "First SIGSEGV %d received, try cleaning up...", sig);

#ifndef NO_TRACE_FUNCTION_CALLS
                debug_function_calls();
#endif

                dbg(DBGL_SYS, DBGT_ERR, "Terminating with error code %d (%s-%s-rev%s)! Please notify a developer",
                        sig, BMX_BRANCH, BRANCH_VERSION, GIT_REV);

                if (initializing) {
                        dbg_sys(DBGT_ERR,
                        "check up-to-dateness of bmx libs in default lib path %s or customized lib path defined by %s !",
                        BMX_DEF_LIB_PATH, BMX_ENV_LIB_PATH);
                }

                if (!cleaning_up)
                        cleanup_all(CLEANUP_RETURN);

                dbg_sys(DBGT_ERR, "raising SIGSEGV again ...");

        } else {
                dbg(DBGL_SYS, DBGT_ERR, "Second SIGSEGV %d received, giving up! core contains second SIGSEV!", sig);
        }

        signal(SIGSEGV, SIG_DFL);
        errno=0;
	if ( raise( SIGSEGV ) ) {
		dbg_sys(DBGT_ERR, "raising SIGSEGV failed: %s...", strerror(errno) );
        }
}


void cleanup_all(int32_t status)
{
        TRACE_FUNCTION_CALL;

        if (status < 0) {
                segmentation_fault(status);
        }

        if (!cleaning_up) {

                dbgf_all(DBGT_INFO, "cleaning up (status %d)...", status);

                cleaning_up = YES;
                terminating = YES;

                // first, restore defaults...
                cb_plugin_hooks(PLUGIN_CB_TERM, NULL);

//		cleanup_schedule();
		

//              purge_link_route_orig_nodes(NULL);
		keyNodes_cleanup(-1, NULL);


		while (status_tree.items) {
			struct status_handl *handl = avl_remove_first_item(&status_tree, -300357);
			if (handl->data)
				debugFree(handl->data, -300359);
			debugFree(handl, -300363);
		}

		cleanup_plugin();
		cleanup_sec();
		cleanup_msg();
//		cleanup_node();
                cleanup_ip();
		cleanup_crypt();
		cleanup_config();
		cleanup_prof();
//		cleanup_avl();
//		cleanup_tools();
		cleanup_schedule();

		// last, close debugging system and check for forgotten resources...
		cleanup_control();

                checkLeak();

                if (status == CLEANUP_SUCCESS)
                        exit(EXIT_SUCCESS);

                dbgf_all(DBGT_INFO, "...cleaning up done");

                if (status == CLEANUP_RETURN)
                        return;

                exit(EXIT_FAILURE);
        }
}











/***********************************************************
 Configuration data and handlers
************************************************************/



static const int32_t field_standard_sizes[FIELD_TYPE_END] = FIELD_STANDARD_SIZES;

int64_t field_get_value(const struct field_format *format, uint32_t min_msg_size, uint8_t *data, uint32_t pos_bit, uint32_t bits)
{
        uint8_t host_order = format->field_host_order;

        assertion(-501221, (format->field_type == FIELD_TYPE_UINT || format->field_type == FIELD_TYPE_HEX || format->field_type == FIELD_TYPE_STRING_SIZE));
        assertion(-501222, (bits <= 32));

        if ((bits % 8) == 0) {

                assertion(-501223, (bits == 8 || bits == 16 || bits == 32));
                assertion(-501168, ((pos_bit % 8) == 0));

                if (bits == 8) {

                        return data[pos_bit / 8];

                } else if (bits == 16) {

                        if(host_order)
                                return *((uint16_t*) & data[pos_bit / 8]);
                        else
                                return ntohs(*((uint16_t*) & data[pos_bit / 8]));

                } else if (bits == 32) {

                        if(host_order)
                                return *((uint32_t*) & data[pos_bit / 8]);
                        else
                                return ntohl(*((uint32_t*) & data[pos_bit / 8]));
                }

        } else if (bits <= 16) {

		assertion(-502013, (bits<=8 || !host_order));

                uint8_t bit = 0;
                uint16_t result = 0;

                for (bit = 0; bit < bits; bit++) {
                        uint8_t val = bit_get(data, (8 * min_msg_size), (pos_bit + bit));
                        bit_set((uint8_t*)&result, 16, (16-bits)+bit, val);
                }

		if (host_order)
			return result;
		else
			return ntohs(result);
        }

        return FAILURE;
}

char *field_dbg_value(const struct field_format *format, uint32_t min_msg_size, uint8_t *data, uint32_t pos_bit, uint32_t bits)
{

        assertion(-501200, (format && min_msg_size && data));

        uint8_t field_type = format->field_type;
        char *val = NULL;
        void *p = (void*) (data + (pos_bit / 8));
        void **pp = (void**) (data + (pos_bit / 8)); // There is problem with pointer to pointerpointer casting!!!!

        uint8_t bytes = bits / 8;

        if (field_type == FIELD_TYPE_UINT || field_type == FIELD_TYPE_HEX || field_type == FIELD_TYPE_STRING_SIZE) {

		if (bits == 0) {

			val = "";

		} else if (bits <= 32) {

                        static char uint32_out[ 16 ] = {0};

                        int64_t field_val = field_get_value(format, min_msg_size, data, pos_bit, bits);

                        if (format->field_type == FIELD_TYPE_HEX)
                                snprintf(uint32_out, sizeof (uint32_out), "%jX", field_val);
                        else
                                snprintf(uint32_out, sizeof (uint32_out), "%ji", field_val);

                        assertion(-501243, (strlen(uint32_out) < sizeof (uint32_out)));
                        val = uint32_out;


                } else {
                        val = memAsHexString(p, bytes);
                }

        } else if (field_type == FIELD_TYPE_IP4) {

                val = ip4AsStr(*((IP4_T*) p));

        } else if (field_type == FIELD_TYPE_IPX4) {

                val =  ipXAsStr(AF_INET, (IPX_T*) p);

        } else if (field_type == FIELD_TYPE_IPX6) {

                val = ip6AsStr((IPX_T*) p);

        } else if (field_type == FIELD_TYPE_IPX) {

                val = ip6AsStr((IPX_T*) p);

        } else if (field_type == FIELD_TYPE_NETP) {

                val = *pp ? netAsStr(*((struct net_key**) pp)) : DBG_NIL;

        } else if (field_type == FIELD_TYPE_MAC) {

                val = macAsStr((MAC_T*) p);

        } else if (field_type == FIELD_TYPE_STRING_BINARY) {

                val =  memAsHexString(p, bytes);

        } else if (field_type == FIELD_TYPE_STRING_CHAR) {

                val = memAsCharString((char*)p, bytes);

        } else if (field_type == FIELD_TYPE_GLOBAL_ID) {

                val = cryptShaAsString(((SHA1_T*) p));

        } else if (field_type == FIELD_TYPE_UMETRIC) {

                val = umetric_to_human(*((UMETRIC_T*) p));

        } else if (field_type == FIELD_TYPE_FMETRIC8) {

                val = umetric_to_human(fmetric_u8_to_umetric(*((FMETRIC_U8_T*) p)));

        } else if (field_type == FIELD_TYPE_IPX6P) {

                val = *pp ? ip6AsStr(*((IPX_T**) pp)) : DBG_NIL;

        } else if (field_type == FIELD_TYPE_POINTER_CHAR) {

                val = *pp ? memAsCharString(*((char**) pp), strlen(*((char**) pp))) : DBG_NIL;

        } else if (field_type == FIELD_TYPE_POINTER_GLOBAL_ID) {

                val = *pp ? cryptShaAsString(*((SHA1_T**)pp)) : DBG_NIL;

        } else if (field_type == FIELD_TYPE_POINTER_SHORT_ID) {

                val = *pp ? cryptShaAsShortStr(*((SHA1_T**)pp)) : DBG_NIL;

        } else if (field_type == FIELD_TYPE_POINTER_UMETRIC) {

                val = *pp ? umetric_to_human(**((UMETRIC_T**) pp)) : DBG_NIL;

        } else {

                assertion(-501202, 0);
        }

        return val ? val : "ERROR";
}


uint32_t field_iterate(struct field_iterator *it)
{
        TRACE_FUNCTION_CALL;
        assertion(-501171, IMPLIES(it->data_size, it->data));

        const struct field_format *format;


        it->field = (it->field_bits || it->field) ? (it->field + 1) : 0;

        format = &(it->format[it->field]);

        if (format->field_type == FIELD_TYPE_END) {

                it->field = 0;
                it->msg_bit_pos += ((it->min_msg_size * 8) + it->var_bits);
                it->var_bits = 0;
                format = &(it->format[0]);
        }

        it->field_bit_pos = (format->field_pos == -1) ?
                it->field_bit_pos + it->field_bits : it->msg_bit_pos + format->field_pos;


	if (!format->field_bits && !it->var_bits)
		it->var_bits = it->data_size ? ((8*it->data_size)-it->field_bit_pos) : 0;

        uint8_t field_type = format->field_type;
        uint32_t field_bits = format->field_bits ? format->field_bits : it->var_bits;
        int32_t std_bits = field_standard_sizes[field_type];

        dbgf_all(DBGT_INFO,
                "fmt.field_name=%s data_size_bits=%d min_msg_size_bits=%d msg_bit_pos=%d data=%p "
                "it.field=%d it.field_bits=%d it.field_bit_pos=%d it.var_bits=%d field_bits=%d "
                "fmt.field_type=%d fmt.field_bits=%d std_bits=%d",
                format->field_name, (8 * it->data_size), (8 * it->min_msg_size), it->msg_bit_pos, it->data,
                it->field, it->field_bits, it->field_bit_pos, it->var_bits, field_bits,
                field_type, format->field_bits, std_bits);


        if (it->msg_bit_pos + (it->min_msg_size * 8) + it->var_bits <=
                8 * (it->data_size ? it->data_size : it->min_msg_size)) {

                //printf("msg_name=%s field_name=%s\n", handl->name, format->msg_field_name);

		assertion(-501172, IMPLIES(field_type == FIELD_TYPE_STRING_SIZE, !it->var_bits));
		assertion(-501203, IMPLIES(field_type == FIELD_TYPE_UINT, (field_bits <= 16 || field_bits == 32)));
		assertion(-501204, IMPLIES(field_type == FIELD_TYPE_HEX, (field_bits <= 16 || field_bits == 32)));
		assertion(-501205, IMPLIES(field_type == FIELD_TYPE_STRING_SIZE, (field_bits <= 16 || field_bits == 32)));

//		assertion(-501186, IMPLIES(it->fixed_msg_size && it->data_size, it->data_size % it->fixed_msg_size == 0));
//		assertion(-501187, IMPLIES(it->fixed_msg_size, field_type != FIELD_TYPE_STRING_SIZE || !format->field_bits));
//		assertion(-501188, IMPLIES(!format->field_bits && it->data_size, it->var_bits));
		assertion(-501189, IMPLIES(!format->field_bits, field_type == FIELD_TYPE_STRING_CHAR || field_type == FIELD_TYPE_STRING_BINARY));
		assertion(-501173, IMPLIES(field_bits == 0, format[1].field_type == FIELD_TYPE_END));
		assertion(-501174, (std_bits != 0));
		assertion(-501175, IMPLIES(std_bits > 0, (field_bits == (uint32_t) std_bits)));
		assertion(-501176, IMPLIES(std_bits < 0, !(field_bits % (-std_bits))));
//		assertion(-501206, IMPLIES(field_bits >= 8, !(field_bits % 8)));
//		assertion(-501177, IMPLIES((field_bits % 8), field_bits < 8));
//		assertion(-501178, IMPLIES(!(field_bits % 8), !(it->field_bit_pos % 8)));
//		assertion(-501182, (it->min_msg_size * 8 >= it->field_bit_pos + field_bits));
		assertion(-501183, IMPLIES(it->data_size, it->min_msg_size <= it->data_size));
//		assertion(-501184, IMPLIES(it->data_size, field_bits));
		assertion(-501185, IMPLIES(it->data_size, it->field_bit_pos + field_bits <= it->data_size * 8));
//		assertion(-501190, IMPLIES(!format->field_host_order, (field_bits == 16 || field_bits == 32)));
//		assertion(-501191, IMPLIES(!format->field_host_order, (field_type == FIELD_TYPE_UINT || field_type == FIELD_TYPE_HEX || field_type == FIELD_TYPE_STRING_SIZE)));
		assertion(-501192, IMPLIES((field_type == FIELD_TYPE_UINT || field_type == FIELD_TYPE_HEX || field_type == FIELD_TYPE_STRING_SIZE), field_bits <= 32));

                if (it->data_size) {

                        if (field_type == FIELD_TYPE_STRING_SIZE) {
                                int64_t var_bytes = field_get_value(format, it->min_msg_size, it->data, it->field_bit_pos, field_bits);
                                assertion(-501207, (var_bytes >= SUCCESS));
                                it->var_bits = 8 * var_bytes;
                        }

                        //msg_field_dbg(it->handl, it->field, it->data, it->pos_bit, field_bits, cn);
                }

                it->field_bits = field_bits;


                //dbgf_all(DBGT_INFO,

                return SUCCESS;
        }

        assertion(-501163, IMPLIES(!it->data_size, (it->field_bit_pos % (it->min_msg_size * 8) == 0)));
        assertion(-501164, IMPLIES(it->data_size, it->data_size * 8 == it->field_bit_pos));
        assertion(-501208, ((it->field_bit_pos % 8) == 0));

//        return (it->msg_bit_pos / 8);
        return (it->field_bit_pos / 8);
}

int16_t field_format_get_items(const struct field_format *format) {

        int16_t i=-1;

        while (format[++i].field_type != FIELD_TYPE_END) {
                assertion(-501244, (i < FIELD_FORMAT_MAX_ITEMS));
        }

        return i;
}

uint32_t fields_dbg_lines(struct ctrl_node *cn, uint16_t relevance, uint32_t data_size, uint8_t *data,
	uint32_t min_msg_size, const struct field_format *format)
{
        TRACE_FUNCTION_CALL;
        assertion(-501209, format);

        uint32_t msgs_size = 0;
        struct field_iterator it = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};

        while ((msgs_size = field_iterate(&it)) == SUCCESS) {

                if (data) {

                        if (cn && it.field == 0)
                                dbg_printf(cn, "\n   ");

                        if (format[it.field].field_relevance >= relevance) {
				if (cn) {
					dbg_printf(cn, " %s=%s", format[it.field].field_name,
						field_dbg_value(&format[it.field], min_msg_size, data, it.field_bit_pos, it.field_bits));
				} else {
					dbgf_track(DBGT_INFO, " %s=%s", format[it.field].field_name,
						field_dbg_value(&format[it.field], min_msg_size, data, it.field_bit_pos, it.field_bits));
				}
                        }

/*
                        if (format[it.field + 1].field_type == FIELD_TYPE_END)
                                dbg_printf(cn, "\n");
*/

                }
        }

        assertion(-501210, (data_size ? msgs_size == data_size : msgs_size == min_msg_size));

        return msgs_size;
}

void fields_dbg_table(struct ctrl_node *cn, uint16_t relevance, uint32_t data_size, uint8_t *data,
                          uint32_t min_msg_size, const struct field_format *format)
{
        TRACE_FUNCTION_CALL;
        assertion(-501255, (format && data && cn));

        uint16_t field_string_sizes[FIELD_FORMAT_MAX_ITEMS] = {0};
        uint32_t columns = field_format_get_items(format);
        uint32_t rows = 1/*the headline*/, bytes_per_row = 1/*the trailing '\n' or '\0'*/;

        assertion(-501256, (columns && columns <= FIELD_FORMAT_MAX_ITEMS));

        struct field_iterator i1 = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};

        while (field_iterate(&i1) == SUCCESS) {

                if (format[i1.field].field_relevance >= relevance) {

                        char *val = field_dbg_value(&format[i1.field], min_msg_size, data, i1.field_bit_pos, i1.field_bits);

                        field_string_sizes[i1.field] = max_i32(field_string_sizes[i1.field], strlen(val));

                        if (i1.field == 0) {
                                rows++;
                                bytes_per_row = 1;
                        }

                        if (rows == 2) {
                                field_string_sizes[i1.field] =
                                        max_i32(field_string_sizes[i1.field], strlen(format[i1.field].field_name));
                        }

                        bytes_per_row += field_string_sizes[i1.field] + 1/* the separating ' '*/;
                }
        }

        char * out = debugMalloc(((rows * bytes_per_row) + 1), -300383);
        memset(out, ' ', (rows * bytes_per_row));

        uint32_t i = 0, pos = 0;

        for (i = 0; i < columns; i++) {

                if (format[i].field_relevance >= relevance) {

                        memcpy(&out[pos], format[i].field_name, strlen(format[i].field_name));
                        pos += field_string_sizes[i] + 1;

                        //dbg_printf(cn, "%s", format[i].field_name);
                        //dbg_spaces(cn, field_string_sizes[i] - strlen(format[i].field_name) + (i == columns - 1 ? 0 : 1));
                }
                if (i == columns - 1) {
                        out[pos++] = '\n';
                        //dbg_printf(cn, "\n");
                }
        }



        struct field_iterator i2 = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};
        while(field_iterate(&i2) == SUCCESS) {

                if (format[i2.field].field_relevance >= relevance) {

                        char *val = field_dbg_value(&format[i2.field], min_msg_size, data, i2.field_bit_pos, i2.field_bits);

                        memcpy(&out[pos], val, strlen(val));
                        pos += field_string_sizes[i2.field]+ (i2.field == columns - 1 ? 0 : 1);

                        //dbg_spaces(cn, field_string_sizes[i2.field] - strlen(val));
                        //dbg_printf(cn, "%s%s", val, (i2.field == columns - 1 ? "" : " "));
                }

                if (i2.field == columns - 1) {
                        out[pos++] = '\n';
                        //dbg_printf(cn, "\n");
                }
        }
        out[pos++] = '\0';
        dbg_printf(cn, "%s", out);
        debugFree(out, -300384);
}



void register_status_handl(uint16_t min_msg_size, IDM_T multiline, const struct field_format* format, char *name,
                            int32_t(*creator) (struct status_handl *status_handl, void *data))
{
        struct status_handl *handl = debugMallocReset(sizeof (struct status_handl), -300364);

        handl->multiline = multiline;
        handl->min_msg_size = min_msg_size;
        handl->format = format;
        strcpy(handl->status_name, name);
        handl->frame_creator = creator;

        assertion(-501224, !avl_find(&status_tree, &handl->status_name));
        avl_insert(&status_tree, (void*) handl, -300357);
}

struct bmx_status {
	GLOBAL_ID_T *shortId;
	GLOBAL_ID_T *globalId;
	char* name;
	char *nodeKey;
	char *linkKey;
	DHASH_T *shortDhash;
	DHASH_T *dhash;
	char version[(sizeof(BMX_BRANCH) - 1) + (sizeof("-") - 1) + (sizeof(BRANCH_VERSION) - 1) + 1];
	uint16_t compat;
	char revision[9];
	IPX_T primaryIp;
	struct net_key *tun6Address;
	struct net_key *tun4Address;
	OGM_SQN_T ogmSqn;
	char *uptime;
	char cpu[6];
	char mem[22];
	char rxBpP[12];
	char txBpP[12];
	char txQ[12];
	uint32_t nbs;
	char nodes[24];
	char contents[16];
};

static const struct field_format bmx_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  bmx_status, shortId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, bmx_status, globalId,      1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      bmx_status, name,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      bmx_status, nodeKey,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      bmx_status, linkKey,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  bmx_status, shortDhash,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, bmx_status, dhash,         1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, version,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              bmx_status, compat,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, revision,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               bmx_status, primaryIp,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_NETP,              bmx_status, tun6Address,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_NETP,              bmx_status, tun4Address,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              bmx_status, ogmSqn,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      bmx_status, uptime,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, cpu,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, mem,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, txQ,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, rxBpP,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, txBpP,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              bmx_status, nbs,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, nodes,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       bmx_status, contents,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

static int32_t bmx_status_creator(struct status_handl *handl, void *data)
{
	struct tun_in_node *tin = avl_first_item(&tun_in_tree);
	struct bmx_status *status = (struct bmx_status *) (handl->data = debugRealloc(handl->data, sizeof(struct bmx_status), -300365));
	struct dsc_msg_pubkey *pkm;
	status->globalId = &myKey->kHash;
	status->shortId = &myKey->kHash;
	status->name = my_Hostname;
	status->shortDhash = &myKey->currOrig->descContent->dhn->dhash;
	status->dhash = &myKey->currOrig->descContent->dhn->dhash;
	status->nodeKey = (pkm = contents_data(myKey->currOrig->descContent, BMX_DSC_TLV_NODE_PUBKEY)) ? cryptKeyTypeAsString(pkm->type) : DBG_NIL;
	status->linkKey = (pkm = contents_data(myKey->currOrig->descContent, BMX_DSC_TLV_LINK_PUBKEY)) ? cryptKeyTypeAsString(pkm->type) : DBG_NIL;
	snprintf(status->version, sizeof(status->version), "%s-%s", BMX_BRANCH, BRANCH_VERSION);
	status->compat = my_compatibility;
	snprintf(status->revision, 8, "%s", GIT_REV);
	status->primaryIp = my_primary_ip;
	status->tun4Address = tin ? &tin->tunAddr46[1] : NULL;
	status->tun6Address = tin ? &tin->tunAddr46[0] : NULL;
	status->ogmSqn = myKey->currOrig->ogmSqn;
	status->uptime = get_human_uptime(0);
	snprintf(status->cpu, sizeof(status->cpu), "%d.%1d", s_curr_avg_cpu_load / 10, s_curr_avg_cpu_load % 10);
	snprintf(status->mem, sizeof(status->mem), "%dK/%d", debugMalloc_bytes / 1000, debugMalloc_objects);
	snprintf(status->rxBpP, sizeof(status->rxBpP), "%d/%.1f", (udpRxBytesMean / DEVSTAT_PRECISION), (((float) udpRxPacketsMean) / DEVSTAT_PRECISION));
	snprintf(status->txBpP, sizeof(status->txBpP), "%d/%.1f", (udpTxBytesMean / DEVSTAT_PRECISION), (((float) udpTxPacketsMean) / DEVSTAT_PRECISION));
	snprintf(status->txQ, sizeof(status->txQ), "%d/%d", txBucket / BUCKET_COIN_SCALE, txBucketSize);
	status->nbs = local_tree.items;
	snprintf(status->nodes, sizeof(status->nodes), "%d/%d/%d", orig_tree.items, key_tree.items, dhash_tree.items);
	snprintf(status->contents, sizeof(status->contents), "%d/%d", (content_tree.items - content_tree_unresolveds), content_tree.items);
	return sizeof(struct bmx_status);
}

struct orig_status {
	GLOBAL_ID_T *shortId;
	GLOBAL_ID_T *globalId;
	char* name;
	char *state;
	uint16_t pref;
	TIME_T brcTo;
	TIME_T signTo;
	TIME_T tAPTo;
	TIME_T nQTo;
	uint16_t friend;
	uint16_t recom;
	char S[2]; // supported by me
	char s[2]; // me supported by him
	char T[2]; // trusted by me;
	char t[2]; // me trusted by him
	char *nodeKey;
	DESC_SQN_T descSqn;
	char descSize[20];
	char contents[12]; //contentRefs
	char *linkKey;
	IPX_T primaryIp;
	char *dev;
	uint32_t nbIdx;
	IPX_T nbLocalIp;
	char* nbName;
	UMETRIC_T metric;
	OGM_SQN_T ogmSqn;
	uint32_t lastDesc;
	CRYPTSHA1_T *shortDHash;
	CRYPTSHA1_T *dHash;
	uint16_t rej;
	uint16_t lastRef;
	char nbs[12]; //neighRefs
};

static const struct field_format orig_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  orig_status, shortId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, orig_status, globalId,      1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      orig_status, name,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      orig_status, state,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, pref,          1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, brcTo,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, signTo,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, tAPTo,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, nQTo,          1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, friend,        1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, recom,         1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       orig_status, S,             1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       orig_status, s,             1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       orig_status, T,             1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       orig_status, t,             1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      orig_status, nodeKey,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, descSqn,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       orig_status, descSize,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       orig_status, contents,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      orig_status, linkKey,       1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               orig_status, primaryIp,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      orig_status, dev,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, nbIdx,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_IPX,               orig_status, nbLocalIp,     1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      orig_status, nbName,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UMETRIC,           orig_status, metric,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, ogmSqn,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, lastDesc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  orig_status, shortDHash,    1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, orig_status, dHash,         1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, rej,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              orig_status, lastRef,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       orig_status, nbs,           1, FIELD_RELEVANCE_MEDI),
        FIELD_FORMAT_END
};

STATIC_FUNC
uint8_t *key_status_page(uint8_t *sOut, uint32_t i, struct orig_node *on, struct desc_content *dc, struct key_node *kn, struct dhash_node *dhn)
{

	assertion(-502237, (!!on + !!dc + !!kn + !!dhn == 1));
	assertion(-502238, IMPLIES(dhn, !dhn->descContent));
	assertion(-502239, IMPLIES(kn, !kn->currOrig && !kn->nextDesc));
	assertion(-502240, IMPLIES(dc, !dc->orig));

	IDM_T S, s, T, t;
	struct dsc_msg_pubkey *pkm;
	struct orig_status *os = &(((struct orig_status*) (sOut = debugRealloc(sOut, ((i + 1) * sizeof(struct orig_status)), -300366)))[i]);
	memset(os, 0, sizeof(struct orig_status));

	dc = on ? on->descContent : dc;
	kn = dc ? dc->key : kn;
	dhn = dc ? dc->dhn : dhn;

	if (kn) {
		os->shortId = &kn->kHash;
		os->globalId = &kn->kHash;
		os->state = kn->bookedState->secName;
		os->pref = (*(kn->bookedState->prefGet))(kn);
		os->brcTo = kn->pktIdTime ? (((TIME_T) (link_purge_to - (bmx_time - kn->pktIdTime))) / 1000) : 0;
		os->signTo = kn->pktSignTime ? (((TIME_T) (link_purge_to - (bmx_time - kn->pktSignTime))) / 1000) : 0;
		os->tAPTo = kn->TAPTime ? (((TIME_T) (tracked_timeout - (bmx_time - kn->TAPTime))) / 1000) : 0;
		os->nQTo = kn->nQTime ? (((TIME_T) (neigh_qualifying_to - (bmx_time - kn->nQTime))) / 1000) : 0;
		os->friend = kn->dirFriend;
		os->recom = kn->recommendations_tree.items;
		os->S[0] = (S = supportedKnownKey(&kn->kHash)) == -1 ? 'A' : (S + '0');
		os->T[0] = (T = setted_pubkey(myKey->currOrig->descContent, BMX_DSC_TLV_TRUSTS, &kn->kHash)) == -1 ? 'A' : (T + '0');
		os->nodeKey = (kn->content && (kn->content->f_body_len >= sizeof(struct dsc_msg_pubkey))) ?
			cryptKeyTypeAsString(((struct dsc_msg_pubkey*) kn->content->f_body)->type) : DBG_NIL;
	} else {
		os->S[0] = '-';
		os->T[0] = '-';
	}

	if (dc) {
		os->s[0] = (s = setted_pubkey(dc, BMX_DSC_TLV_SUPPORTS, &myKey->kHash)) == -1 ? 'A' : (s + '0');
		os->t[0] = (t = setted_pubkey(dc, BMX_DSC_TLV_TRUSTS, &myKey->kHash)) == -1 ? 'A' : (t + '0');
		os->descSqn = dc->descSqn;
		snprintf(os->descSize, sizeof(os->descSize), "%d+%d", dc->desc_frame_len, dc->ref_content_len);
		snprintf(os->contents, sizeof(os->contents), "%d/%d", (dc->contentRefs_tree.items - dc->unresolvedContentCounter), dc->contentRefs_tree.items);
	} else {
		os->s[0] = '-';
		os->t[0] = '-';
		snprintf(os->contents, sizeof(os->contents), "---");
	}

	if (on) {
		os->linkKey = (pkm = contents_data(dc, BMX_DSC_TLV_LINK_PUBKEY)) ? cryptKeyTypeAsString(pkm->type) : DBG_NIL;
		os->name = on->k.hostname;
		os->primaryIp = on->primary_ip;
		os->dev = on->curr_rt_link && on->curr_rt_link->k.myDev ? on->curr_rt_link->k.myDev->name_phy_cfg.str : DBG_NIL;
		os->nbIdx = (on->curr_rt_link ? on->curr_rt_link->k.linkDev->key.devIdx : 0);
		os->nbLocalIp = (on->curr_rt_link ? on->curr_rt_link->k.linkDev->key.llocal_ip : ZERO_IP);
		os->nbName = (on->curr_rt_link ? on->curr_rt_link->k.linkDev->key.local->on->k.hostname : DBG_NIL);
		os->metric = on->ogmMetric;
		os->ogmSqn = on->ogmSqn;
		os->lastDesc = (bmx_time - on->updated_timestamp) / 1000;
	}

	if (dhn) {
		os->dHash = &dhn->dhash;
		os->shortDHash = &dhn->dhash;
		os->lastRef = (bmx_time - dhn->referred_by_others_timestamp) / 1000;
		os->rej = dhn->rejected;
	}

	snprintf(os->nbs, sizeof(os->nbs), "%d/%d", (kn ? kn->neighRefs_tree.items : 0), (dhn ? dhn->neighRefs_tree.items : 0));

	return sOut;
}

static int32_t orig_status_creator(struct status_handl *handl, void *data)
{
	uint32_t i = 0;

	if (data) {
		struct key_node *kn = data;
		handl->data = key_status_page(handl->data, 0, kn->currOrig, (!kn->currOrig ? kn->nextDesc : NULL), ((!kn->currOrig && !kn->nextDesc) ? kn : NULL), NULL);
	} else {
		struct avl_node *it;
		struct key_node *kn;
		struct orig_node *on;
		struct dhash_node *dhn;
		AVL_TREE(orig_name_tree, struct orig_node, k);

		for (it = NULL; (on = avl_iterate_item(&orig_tree, &it));)
			avl_insert(&orig_name_tree, on, -300744);

		while ((on = avl_remove_first_item(&orig_name_tree, -300745)))
			handl->data = key_status_page(handl->data, i++, on, NULL, NULL, NULL);

		for (it = NULL; (kn = avl_iterate_item(&key_tree, &it));) {
			if (kn->nextDesc)
				handl->data = key_status_page(handl->data, i++, NULL, kn->nextDesc, NULL, NULL);
			if (!kn->currOrig && !kn->nextDesc)
				handl->data = key_status_page(handl->data, i++, NULL, NULL, kn, NULL);
		}

		for (it = NULL; (dhn = avl_iterate_item(&dhash_tree, &it));) {
			if (!dhn->descContent)
				handl->data = key_status_page(handl->data, i++, NULL, NULL, NULL, dhn);
		}
	}
	return((i) * sizeof(struct orig_status));
}

struct ref_status {
	GLOBAL_ID_T *shortId;
	GLOBAL_ID_T *globalId;
	char *state;
	uint8_t claim;
	uint8_t desc;
	DESC_SQN_T descSqn;
	char contents[12]; //contentRefs
	char* name;
	uint16_t lastDesc;
	CRYPTSHA1_T *shortDHash;
	CRYPTSHA1_T *dHash;
	uint16_t rej;
	uint16_t lastRef;
	char nbs[12]; //neighRefs
	GLOBAL_ID_T *nbId;
	char* nbName;
	uint32_t rootLen;
	uint32_t virtLen;
	uint32_t unresolveds;
};


static const struct field_format ref_status_format[] = {
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  ref_status, shortId,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, ref_status, globalId,      1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      ref_status, state,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, claim,         1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, desc,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, descSqn,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       ref_status, contents,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      ref_status, name,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, lastDesc,      1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  ref_status, shortDHash,    1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_GLOBAL_ID, ref_status, dHash,         1, FIELD_RELEVANCE_LOW),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, rej,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, lastRef,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_STRING_CHAR,       ref_status, nbs,           1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_SHORT_ID,  ref_status, nbId,          1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_POINTER_CHAR,      ref_status, nbName,        1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, rootLen,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, virtLen,       1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_INIT(FIELD_TYPE_UINT,              ref_status, unresolveds,   1, FIELD_RELEVANCE_HIGH),
        FIELD_FORMAT_END
};

STATIC_FUNC
uint8_t *ref_status_page(uint8_t *sOut, uint32_t i, struct reference_node *ref, uint8_t shownSqn)
{
	struct dhash_node *dhn = ref->dhn;
	struct desc_content *dc = ref->dhn->descContent;
	struct key_node *kn = dc ? dc->key : ref->claimedKey;
	struct orig_node *on = kn ? kn->currOrig : NULL;

	assertion(-502496, (ref->shown != shownSqn));
	assertion(-502497, IMPLIES(dc && dc->key && ref->claimedKey, dc->key == ref->claimedKey)); //checked during refNode_update()
	assertion(-502498, IMPLIES(dc, ref->claimedDescSqn = dc->descSqn)); //checked during refNode_update()

	struct ref_status *rs = &(((struct ref_status*) (sOut = debugRealloc(sOut, ((i + 1) * sizeof(struct ref_status)), -300366)))[i]);
	memset(rs, 0, sizeof(struct ref_status));

	ref->shown = shownSqn;

	snprintf(rs->contents, sizeof(rs->contents), "---");
	snprintf(rs->nbs, sizeof(rs->nbs), "---");

	if (kn) {
		rs->shortId = &kn->kHash;
		rs->globalId = &kn->kHash;
		rs->state = kn->bookedState->secName;
		rs->claim = !!ref->claimedKey;
		rs->desc = !!ref->dhn->descContent;
	}

	if (dhn) {
		rs->dHash = &dhn->dhash;
		rs->shortDHash = &dhn->dhash;
		rs->descSqn = ref->claimedDescSqn;
		rs->rej = dhn->rejected;
		rs->lastRef = ((bmx_time - dhn->referred_by_others_timestamp) / 1000);
		rs->nbName = ref->neigh->on->k.hostname;
		rs->nbId = &ref->neigh->on->k.nodeId;
	}

	if (dc) {
		snprintf(rs->contents, sizeof(rs->contents), "%d/%d", (dc->contentRefs_tree.items - dc->unresolvedContentCounter), dc->contentRefs_tree.items);
		rs->rootLen = dc->desc_frame_len;
		rs->virtLen = dc->ref_content_len;
		rs->unresolveds = dc->unresolvedContentCounter;
	}

	snprintf(rs->nbs, sizeof(rs->nbs), "%d/%d", (kn ? kn->neighRefs_tree.items : 0), dhn->neighRefs_tree.items);

	if (on) {
		rs->name = on->k.hostname;
		rs->lastDesc = (bmx_time - on->updated_timestamp) / 1000;
	}

	return sOut;
}

static int32_t ref_status_creator(struct status_handl *handl, void *data)
{
	uint32_t i = 0;

	struct avl_node *it;
	struct avl_node *an;
	struct orig_node *on;
	struct reference_node *ref;
	struct key_node *kn;
	struct dhash_node *dhn;
	static uint8_t shownSqn = 0;

	shownSqn = ((uint8_t) (shownSqn + 1)) ? (shownSqn + 1) : (shownSqn + 2);

	AVL_TREE(orig_name_tree, struct orig_node, k);

	for (it = NULL; (on = avl_iterate_item(&orig_tree, &it));)
		avl_insert(&orig_name_tree, on, -300746);

	while ((on = avl_remove_first_item(&orig_name_tree, -300747))) {

		for (an = NULL; (ref = avl_iterate_item(&on->descContent->dhn->neighRefs_tree, &an));)
			handl->data = ref_status_page(handl->data, i++, ref, shownSqn);

		for (an = NULL; on->key->nextDesc && (ref = avl_iterate_item(&on->key->nextDesc->dhn->neighRefs_tree, &an));)
			handl->data = ref_status_page(handl->data, i++, ref, shownSqn);

	}

	uint32_t namedRefs = i;

	for (it = NULL; (kn = avl_iterate_item(&key_tree, &it));) {

		if (kn->nextDesc && !kn->currOrig) {

			for (an = NULL; (ref = avl_iterate_item(&kn->nextDesc->dhn->neighRefs_tree, &an));)
				handl->data = ref_status_page(handl->data, i++, ref, shownSqn);
		}
	}

	uint32_t descRefs = i - namedRefs;

	for (it = NULL; (kn = avl_iterate_item(&key_tree, &it));) {

		if (!kn->nextDesc && !kn->currOrig) {

			for (an = NULL; (ref = avl_iterate_item(&kn->neighRefs_tree, &an));)
				handl->data = ref_status_page(handl->data, i++, ref, shownSqn);
		}
	}

	uint32_t claimedRefs = i - (namedRefs + descRefs);

	uint32_t droppedDRefs = 0;
	uint32_t droppedSRefs = 0;
	uint32_t allRefs = 0;

	for (it = NULL; (dhn = avl_iterate_item(&dhash_tree, &it));) {

		allRefs += dhn->neighRefs_tree.items;

		if (dhn->descContent) {
			droppedDRefs += dhn->neighRefs_tree.items;
		} else {

			for (an = NULL; (ref = avl_iterate_item(&dhn->neighRefs_tree, &an));) {

				if (ref->shown == shownSqn)
					droppedSRefs++;
				else
					handl->data = ref_status_page(handl->data, i++, ref, shownSqn);
			}
		}
	}


	dbgf(droppedSRefs ? DBGL_CHANGES : DBGL_ALL, droppedSRefs ? DBGT_WARN : DBGT_INFO,
		"all=%d shown=%d != (%d = (named=%d + desc=%d + claimed=%d)) dDropped=%d sDropped=%d",
		allRefs, i, (namedRefs + descRefs + claimedRefs), namedRefs, descRefs, claimedRefs, droppedDRefs, droppedSRefs);

	assertion(-502510, (allRefs == i));

	return((i) * sizeof(struct ref_status));
}








STATIC_FUNC
int32_t opt_version(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd != OPT_APPLY )
		return SUCCESS;

        assertion(-501257, !strcmp(opt->name, ARG_VERSION));

        dbg_printf(cn, "%s-%s comPatibility=%d revision=%s\n",
                        BMX_BRANCH, BRANCH_VERSION, my_compatibility, GIT_REV);

        if (initializing)
                cleanup_all(CLEANUP_SUCCESS);

        return SUCCESS;
 }

int32_t opt_status(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        if ( cmd == OPT_CHECK || cmd == OPT_APPLY) {

                int32_t relevance = DEF_RELEVANCE;
                struct opt_child *c = NULL;

                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                        if (!strcmp(c->opt->name, ARG_RELEVANCE)) {
                                relevance = strtol(c->val, NULL, 10);
                        }
                }


                struct avl_node *it = NULL;
                struct status_handl *handl = NULL;
                uint32_t data_len;
                char status_name[sizeof (((struct status_handl *) NULL)->status_name)] = {0};
                if (patch->val)
                        strncpy(status_name, patch->val, sizeof (status_name));
                else
                        strncpy(status_name, opt->name, sizeof (status_name));

                if ((handl = avl_find_item(&status_tree, status_name))) {

                        if (cmd == OPT_APPLY) {

				prof_start( opt_status, main);

				if ((data_len = ((*(handl->frame_creator))(handl, NULL)))) {
					uint16_t i;
					char upper[strlen(handl->status_name)+1];
					for(i=0; (i <= strlen(handl->status_name)); i++)
						upper[i] = toupper(handl->status_name[i]);
					dbg_printf(cn, "%s:\n", upper);
					fields_dbg_table(cn, relevance, data_len, handl->data, handl->min_msg_size, handl->format);
				}

				prof_stop();
                        }

                } else {

                        dbg_printf(cn, "requested %s must be one of: ", ARG_VALUE_FORM);
                        while ((handl = avl_iterate_item(&status_tree, &it))) {
                                dbg_printf(cn, "%s ", handl->status_name);
                        }
                        dbg_printf(cn, "\n");
                        return FAILURE;
                }
	}
	return SUCCESS;
}

int32_t opt_flush_all(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	TRACE_FUNCTION_CALL;

	if (cmd == OPT_APPLY) {
		purge_tx_task_tree(NULL, NULL, NULL, YES);
		keyNodes_cleanup(-1, myKey);
	}

	return SUCCESS;
}




STATIC_FUNC
int32_t opt_hostname(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	static uint8_t checked = NO;

	if ( (cmd == OPT_SET_POST) && initializing && !checked ) {

		checked = YES;

		if (gethostname(my_Hostname, MAX_HOSTNAME_LEN))
			return FAILURE;

		my_Hostname[MAX_HOSTNAME_LEN - 1] = 0;

		if (validate_name_string(my_Hostname, MAX_HOSTNAME_LEN, NULL) == FAILURE) {
			dbg_sys(DBGT_ERR, "illegal hostname %s", my_Hostname);
			return FAILURE;
		}
	}

	return SUCCESS;
}

DESC_SQN_T newDescriptionSqn( char* newPath, uint8_t exitIfFailure )
{
	static DESC_SQN_T currSqn = 0;
	static char path[MAX_PATH_SIZE];
	FILE* file = NULL;
	int ret;
	char *goto_error_code = NULL;

	assertion(-502014, XOR(newPath, strlen(path) ));

	if (!strlen(path)) {

		strcpy(path, newPath);

		if (wordlen(path) + 1 >= MAX_PATH_SIZE || path[0] != '/')
			goto_error(finish, "path has illegal format");

		char *slash = strrchr(path, '/');
		if (slash) {
			*slash = 0;
			if (check_dir(path, YES, YES) == FAILURE)
				goto_error(finish, "dir can not be created");
			*slash = '/';
		}
	}

	if (currSqn==0) {

		if ((file = fopen(path, "r+"))) {
			if ((fscanf(file, "%u", &currSqn) == 1) && (fseek(file, 0, SEEK_SET) == 0) &&
				(currSqn = (((currSqn + DESC_SQN_SAVE_INTERVAL) / DESC_SQN_SAVE_INTERVAL) * DESC_SQN_SAVE_INTERVAL) + DESC_SQN_REBOOT_ADDS) &&
				((ret = fprintf(file, "%u", currSqn)) > 0) &&
				(fclose(file) == 0) && (truncate(path, ret) == 0)) {
				dbgf_sys(DBGT_INFO, "Updating existing %s=%s descSqn=%d", ARG_DSQN_PATH, path, currSqn );
				file=NULL;
			} else {
				goto_error(finish, "has illegal content");
			}
		} else if ((file = fopen(path, "w"))) {
			if (
				(currSqn = DESC_SQN_REBOOT_ADDS) &&
				(ret = fprintf(file, "%u", currSqn)) > 0) {
				dbgf_sys(DBGT_WARN, "Created new %s=%s starting with descSqn=%d", ARG_DSQN_PATH, path, currSqn );
			} else {
				goto_error(finish, "new file can not be updated!");
			}
		} else {
			goto_error(finish, "can not be created!");
		}

	} else if ((++currSqn)%DESC_SQN_SAVE_INTERVAL) {

		dbgf_track(DBGT_INFO, "Not Updating existing %s=%s", ARG_DSQN_PATH, path);

	} else if ((file = fopen(path, "w")) && ((ret = fprintf(file, "%u", currSqn)) > 0)) {

		dbgf_track(DBGT_INFO, "Updating existing %s=%s", ARG_DSQN_PATH, path);

	} else {
		goto_error(finish, "old file can not be updated!");
	}

finish: {

	if(file)
		fclose(file);

	if (goto_error_code) {
		dbgf_sys(DBGT_ERR, "%s=%s %s! errno=%s", ARG_DSQN_PATH, path, goto_error_code, strerror(errno));
		if (exitIfFailure)
			cleanup_all(-502015);
		return 0;
	}

	dbgf_track(DBGT_INFO, "New descSqn=%d", currSqn);
	return htonl(currSqn);
}
}



static struct opt_type bmx_options[]=
{
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

	{ODI,0,ARG_VERSION,		'v',9,2,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_version,
			0,		"show version"},

        {ODI,0,ARG_COMPATIBILITY,       0,  3,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,   &my_compatibility,MIN_COMPATIBILITY,MAX_COMPATIBILITY,DEF_COMPATIBILITY,0, 0,
			ARG_VALUE_FORM,	"set (elastic) compatibility version"},
//order must be after ARG_KEY_PATH and before ARG_AUTO_IP6_PREFIX and ARG_TUN_IN_DEV (which use self, initialized from init_self, called from opt_hostname):
	{ODI,0,ARG_HOSTNAME,		0,  5,0,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		        0,		        0,0,	opt_hostname,
			ARG_VALUE_FORM,	"set advertised hostname of node"},

	{ODI,0,ARG_SHOW,		's', 9,1,A_PS1N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			ARG_VALUE_FORM,		"show status information about given context. E.g.:" ARG_STATUS ", " ARG_INTERFACES ", " ARG_LINKS ", " ARG_ORIGINATORS " " ARG_CREDITS ", ..." "\n"},
	{ODI,ARG_SHOW,ARG_RELEVANCE,'r',9,1,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,	0,	       MIN_RELEVANCE,   MAX_RELEVANCE,  DEF_RELEVANCE,0, opt_status,
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE}
        ,

	{ODI,0,ARG_STATUS,		0,  9,1,A_PS0,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show status\n"},

	{ODI,0,ARG_ORIGINATORS,	        0,  9,1,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show originators\n"}
        ,
	{ODI,0,ARG_DESCREFS,	        0,  9,1,A_PS0N,A_USR,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_status,
			0,		"show description references\n"}
        ,
	{ODI,0,"flushAll",		0,  9,1,A_PS0,A_ADM,A_DYN,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_flush_all,
			0,		"purge all neighbors and routes on the fly"}
        ,
#ifndef LESS_OPTIONS
	{ODI,0,ARG_DAD_TO,        	0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&dad_to,	MIN_DAD_TO,	MAX_DAD_TO,	DEF_DAD_TO,0,	0,
			ARG_VALUE_FORM,	"duplicate address (DAD) detection timout in ms"}
#endif
};



STATIC_FUNC
void bmx(void)
{

        struct avl_node *an;
	struct dev_node *dev;
	TIME_T frequent_timeout, seldom_timeout;

	TIME_T s_last_cpu_time = 0, s_curr_cpu_time = 0;

	frequent_timeout = seldom_timeout = bmx_time;

        update_my_description();

        initializing = NO;

        while (!terminating) {

		TIME_T wait = task_next( );

		if ( wait )
			wait4Event( XMIN( wait, MAX_SELECT_TIMEOUT_MS ) );

//                if (my_description_changed)
//                        update_my_description_adv();

		// The regular tasks...
		if ( U32_LT( frequent_timeout + 1000,  bmx_time ) ) {

			// check for changed interface konfigurations...
                        for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));) {

				if ( dev->active )
                                        sysctl_config( dev );

                        }


			close_ctrl_node( CTRL_CLEANUP, NULL );

/*
	                struct list_node *list_pos;
			list_for_each( list_pos, &dbgl_clients[DBGL_ALL] ) {

				struct ctrl_node *cn = (list_entry( list_pos, struct dbgl_node, list ))->cn;

				dbg_printf( cn, "------------------ DEBUG ------------------ \n" );

				check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_STATUS ), 0, cn );
				check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_LINKS ), 0, cn );
				check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_LOCALS ), 0, cn );
                                check_apply_parent_option( ADD, OPT_APPLY, 0, get_option( 0, 0, ARG_ORIGINATORS ), 0, cn );
				dbg_printf( cn, "--------------- END DEBUG ---------------\n" );
			}
*/

			/* preparing the next debug_timeout */
			frequent_timeout = bmx_time;
		}


		if ( U32_LT( seldom_timeout + 5000, bmx_time ) ) {

			//node_tasks();

			// check for corrupted memory..
			checkIntegrity();


			/* generating cpu load statistics... */
			s_curr_cpu_time = (TIME_T)clock();
			s_curr_avg_cpu_load = ( (s_curr_cpu_time - s_last_cpu_time) / (TIME_T)(bmx_time - seldom_timeout) );
			s_last_cpu_time = s_curr_cpu_time;

			seldom_timeout = bmx_time;
		}
	}
}

int main(int argc, char *argv[])
{
#ifdef CORE_LIMIT
#include <sys/time.h>
#include <sys/resource.h>

	struct rlimit rlim = {.rlim_cur = (CORE_LIMIT * 1024), .rlim_max = (CORE_LIMIT * 1024) };

	if (setrlimit(RLIMIT_CORE, &rlim) != 0) {
		printf("setrlimit RLIMIT_CORE=%d failed: %s\n", (CORE_LIMIT * 1024), strerror(errno));
	}

#endif
	My_pid = getpid();


	signal( SIGINT, handler );
	signal( SIGTERM, handler );
	signal( SIGPIPE, SIG_IGN );
	signal( SIGSEGV, segmentation_fault );

#ifdef TEST_DEBUG_MALLOC
        debugMalloc(1, -300525); //testing debugMalloc
#endif


	init_control();
	init_schedule();

        init_tools();
        init_avl();

	init_prof();
//	init_config();
	init_crypt();
        init_ip();
	init_msg();
	init_desc();
	init_content();
	init_sec();
	init_key();
//	init_node();
	init_ogm();
	
        if (init_plugin() == SUCCESS) {

                activate_plugin((metrics_get_plugin()), NULL, NULL);
                activate_plugin((link_get_plugin()), NULL, NULL);
                activate_plugin((hna_get_plugin()), NULL, NULL);

#ifdef TRAFFIC_DUMP
                struct plugin * dump_get_plugin(void);
                activate_plugin((dump_get_plugin()), NULL, NULL);
#endif

        } else {
                assertion(-500809, (0));
	}

	prof_start( main, NULL );

	register_options_array(bmx_options, sizeof( bmx_options), CODE_CATEGORY_NAME);

	register_status_handl(sizeof(struct bmx_status), 0, bmx_status_format, ARG_STATUS, bmx_status_creator);
	register_status_handl(sizeof(struct orig_status), 1, orig_status_format, ARG_ORIGINATORS, orig_status_creator);
	register_status_handl(sizeof(struct ref_status), 1, ref_status_format, ARG_DESCREFS, ref_status_creator);



	apply_init_args( argc, argv );

        bmx();

	cleanup_all( CLEANUP_SUCCESS );

	return -1;
}


