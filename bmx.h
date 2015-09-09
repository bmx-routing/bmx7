/*
 * Copyright (c) 2010  BMX protocol contributor(s):
 * Axel Neumann  <neumann at cgws dot de>
 *
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

#include <sys/time.h>
#include <time.h>

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>


typedef int8_t IDM_T; // smallest int which size does NOT matter

/*
 * from other headers:
 * TODO: partly move this to system.h
 * dont touch this for compatibility reasons:
 */

/* Android has these under a different name since the NDK target android-8:
 *
 * glibc defines dprintf(int, const char*, ...), which is poorly named
 * and likely to conflict with locally defined debugging printfs
 * fdprintf is a better name, and some programs that use fdprintf use a
 * #define fdprintf dprintf for compatibility
 */
#ifdef __ANDROID__
#define dprintf fdprintf
#define vdprintf vfdprintf
#endif

#define BMX_BRANCH "BMX6"
#define BRANCH_VERSION "0.1-alpha" //put exactly one distinct word inside the string like "0.3-pre-alpha" or "0.3-rc1" or "0.3"

#define cv16 16 // deployed cv16..cv16, announces 16, uses cv16, accepts 16..16, processes cv16..cv16, finished cv16=CV16     , developing CV17+

#define CV16 16 // deployed cv16..CV16, announces 16, uses cv16, accepts 15..17, processes CV15..CV17, finished CV17=CV18=CV19
#define CV17 17 // deployed CV16..CV17, announces 17, uses CV16, accepts 16..18, processes CV16..CV18, finished CV17=CV18=CV19
#define CV18 18 // deployed CV17..CV18, announces 18, uses CV17, accepts 17..19, processes CV17..CV19, finished CV17=CV18=CV19, developing CV20+

#define CV19 19 // deployed CV18..CV19, announces 19, uses CV18, accepts 18..20, processes CV18..CV20, finished CV20=CV21=CV22
#define CV20 20 // deployed CV19..CV20, announces 20, uses CV19, accepts 19..21, processes CV19..CV21, finished CV20=CV21=CV22
#define CV21 21 // deployed CV20..CV11, announces 21, uses CV20, accepts 20..22, processes CV20..CV22, finished CV20=CV21=CV22, developing CV23+
//and so on...


#define MIN_COMPATIBILITY CV17
#define MAX_COMPATIBILITY CV18
#define DEF_COMPATIBILITY CV17
#define ARG_COMPATIBILITY "compatibility"
extern int32_t my_compatibility;

#define MIN_CONFORMANCE_TOLERANCE 0
#define MAX_CONFORMANCE_TOLERANCE 1
#define DEF_CONFORMANCE_TOLERANCE 1
#define ARG_CONFORMANCE_TOLERANCE "conformanceTolerance"

extern int32_t my_conformance_tolerance;
extern uint32_t my_runtimeKey;

#define MAX_HOSTNAME_LEN 32
extern char my_Hostname[];

#ifndef GIT_REV
#define GIT_REV "0"             // to be incremented after each critical code change
#endif
extern uint32_t rev_u32;


/*
 * from ip.h:
 */

#define GEN_ADDR_LEN 20
#define IP6_ADDR_LEN 16
#define IP4_ADDR_LEN 4
#define MAC_ADDR_LEN 6

//#define INET_ADDRSTRLEN INET_ADDRSTRLEN     // from in.h
//#define INET6_ADDRSTRLEN INET6_ADDRSTRLEN    // from in.h

#define IPX_STR_LEN INET6_ADDRSTRLEN
#define IPX_PREFIX_STR_LEN (INET6_ADDRSTRLEN + 4)


typedef struct in6_addr LOCAL_IP_T;

typedef uint32_t IP4_T;

typedef struct in6_addr IP6_T;

typedef IP6_T IPX_T;

struct net_key {
        uint8_t af;   //family
	uint8_t mask; //prefixlen
	IPX_T ip;     //address
} __attribute__((packed));


typedef union {
	uint8_t   u8[GEN_ADDR_LEN];
	uint16_t u16[GEN_ADDR_LEN / sizeof(uint16_t)];
	uint32_t u32[GEN_ADDR_LEN / sizeof(uint32_t)];
	uint64_t u64[GEN_ADDR_LEN / sizeof(uint64_t)];
} ADDR_T;


typedef union {
	uint8_t   u8[MAC_ADDR_LEN];
	uint16_t u16[MAC_ADDR_LEN / sizeof(uint16_t)];
} MAC_T;

extern const IPX_T  ZERO_IP;
extern const MAC_T  ZERO_MAC;
extern const ADDR_T ZERO_ADDR;

#define ZERO_NET_KEY_INIT {.af = 0}
extern const struct net_key ZERO_NET_KEY;
#define ZERO_NET4_KEY_INIT {.af = AF_INET}
extern const struct net_key ZERO_NET4_KEY;
#define ZERO_NET6_KEY_INIT {.af = AF_INET6}
extern const struct net_key ZERO_NET6_KEY;


/*
 * from hna.h:
 */



/*
 * from bmx.h:
 */



#define ARG_HOSTNAME "hostname"








#define MY_DESC_CAPABILITIES_CV16 0x0200 //capability flag for compatibility with CV16 txInterval field
#define MY_DESC_CAPABILITIES (MY_DESC_CAPABILITIES_CV16 | 0)
extern uint16_t my_desc_capabilities;

#define DEF_DAD_TO 20000//(MAX_OGM_INTERVAL + MAX_TX_INTERVAL)
#define MIN_DAD_TO 100
#define MAX_DAD_TO 360000000
#define ARG_DAD_TO "dadTimeout"
extern int32_t dad_to;



#define MIN_DHASH_TO 300000
#define DHASH_TO_TOLERANCE_FK 10




/*
 * from msg.h:
 */


// deprecated:
typedef uint16_t SQN_T;
#define SQN_MAX ((SQN_T)-1)
#define MAX_SQN_RANGE 8192 // the maxumim of all .._SQN_RANGE ranges, should never be more than SQN_MAX/4

typedef uint32_t PKT_SQN_T;
#define PKT_SQN_MAX ((PKT_SQN_T)-1)


// OGMs:
typedef uint16_t OGM_SQN_T;
#define OGM_SQN_BIT_SIZE (16)
#define OGM_SQN_MASK     ((1<<OGM_SQN_BIT_SIZE)-1)
#define OGM_SQN_MAX      OGM_SQN_MASK

#define OGM_IIDOFFST_BIT_SIZE 6
#define OGM_IIDOFFST_MASK ((1<<OGM_IIDOFFST_BIT_SIZE)-1)


// aggregations of OGMs:
typedef uint16_t AGGREG_SQN_T;
#define AGGREG_SQN_BIT_SIZE (16)
#define AGGREG_SQN_MASK     ((1<<AGGREG_SQN_BIT_SIZE)-1)
#define AGGREG_SQN_MAX      AGGREG_SQN_MASK

#define AGGREG_SQN_CACHE_MASK  0xFF
#define AGGREG_SQN_CACHE_RANGE (AGGREG_SQN_CACHE_MASK+1) //32




typedef uint16_t INT_NEIGH_ID_T;
#define INT_NEIGH_ID_BIT_SIZE (12)

#define LOCALS_MAX (1<<INT_NEIGH_ID_BIT_SIZE) // because each local needs a bit to be indicated in the ogm.dest_field







// hello and hello reply messages:
typedef uint16_t HELLO_SQN_T;

#define HELLO_SQN_BIT_SIZE (sizeof(HELLO_SQN_T)*8)
#define HELLO_SQN_MASK ((HELLO_SQN_T)-1)
#define HELLO_SQN_MAX       HELLO_SQN_MASK

#define HELLO_SQN_TOLERANCE 4

#define MAX_HELLO_SQN_WINDOW 128
#define MIN_HELLO_SQN_WINDOW 1
#define DEF_HELLO_SQN_WINDOW 48
#define ARG_HELLO_SQN_WINDOW "linkWindow"
//extern int32_t my_link_window; // my link window size used to quantify the link qualities to direct neighbors
//#define RP_PURGE_ITERATIONS MAX_LINK_WINDOW



typedef uint32_t BURST_SQN_T;


// descriptions 
typedef uint32_t DESC_SQN_T;
#define DESC_SQN_SAVE_INTERVAL 100
#define DESC_SQN_REBOOT_ADDS 10





#define FRAME_TYPE_BIT_SIZE    (5)
#define FRAME_TYPE_MASK        ((1<<FRAME_TYPE_BIT_SIZE)-1)
#define FRAME_TYPE_ARRSZ       (FRAME_TYPE_MASK+1)

#define BMX_DSC_TLV_MIN         0x00
#define BMX_DSC_TLV_MAX_KNOWN   (FRAME_TYPE_ARRSZ-1)
#define BMX_DSC_TLV_MAX         (FRAME_TYPE_ARRSZ-1)
#define BMX_DSC_TLV_ARRSZ       (FRAME_TYPE_ARRSZ)
#define BMX_DSC_TLV_INVALID     (FRAME_TYPE_ARRSZ)






#define MAX_UDPD_SIZE (1280 /*min IPv6 MTU*/ - sizeof(struct ip6_hdr) - sizeof(struct udphdr))














#define BMX_ENV_LIB_PATH "BMX6_LIB_PATH"
#define BMX_DEF_LIB_PATH "/usr/lib"
// e.g. sudo BMX_LIB_PATH="$(pwd)/lib" ./bmx6 -d3 eth0:bmx
#define BMX_ENV_DEBUG "BMX6_DEBUG"





#define ARG_HELP		"help"
#define ARG_VERBOSE_HELP	"verboseHelp"

#define ARG_VERSION		"version"

#define ARG_TEST		"test"
#define ARG_SHOW_PARAMETER 	"parameters"



#define ARG_SHOW "show"
#define ARG_ORIGINATORS "originators"
#define ARG_STATUS "status"
#define ARG_CREDITS "credits"
#define ARG_DESCREFS "references"

#define MAX_DBG_STR_SIZE 2000
#define OUT_SEQNO_OFFSET 1

enum NoYes {
	NO,
	YES
};

extern const IDM_T CONST_YES;
extern const IDM_T CONST_NO;



enum ADGSN {
	ADD,
	DEL,
	GET,
	SET,
	NOP
};


#define SUCCESS 0
#define FAILURE -1


#define MAX_SELECT_TIMEOUT_MS 1100 /* MUST be smaller than (1000/2) to fit into max tv_usec */
#define MAX_SELECT_SAFETY_MS 200 /* MUST be smaller than (1000/2) to fit into max tv_usec */
#define CRITICAL_PURGE_TIME_DRIFT 20


#define XMAX( a, b ) ( (a>b) ? (a) : (b) )
#define XMIN( a, b ) ( (a<b) ? (a) : (b) )

#define XOR2( a, b )       ( (a) ? (a) : (b) )
#define XOR3( a, b, c )    ( (a) ? (a) : ( (b) ? (b) : (c) ) )
#define XOR4( a, b, c, d ) ( (a) ? (a) : ( (b) ? (b) : ( (c) ? (c) : (d) ) ) )

#define U64_MAX ((uint64_t)(-1))
#define U32_MAX ((uint32_t)(-1))
#define I32_MAX ((U32_MAX>>1))
#define U16_MAX ((uint16_t)(-1))
#define I16_MAX ((U16_MAX>>1))
#define U8_MAX  ((uint8_t)(-1))
#define I8_MAX  ((U8_MAX>>1))


#define U32_LT( a, b )  ( ((uint32_t)( (a) - (b) ) ) >  I32_MAX )
#define U32_LE( a, b )  ( ((uint32_t)( (b) - (a) ) ) <= I32_MAX )
#define U32_GT( a, b )  ( ((uint32_t)( (b) - (a) ) ) >  I32_MAX )
#define U32_GE( a, b )  ( ((uint32_t)( (a) - (b) ) ) <= I32_MAX )

#define UXX_LT( mask, a, b )  ( ((mask)&( (a) - (b) ) ) >  (((mask)&U32_MAX)>>1) )
#define UXX_LE( mask, a, b )  ( ((mask)&( (b) - (a) ) ) <= (((mask)&U32_MAX)>>1) )
#define UXX_GT( mask, a, b )  ( ((mask)&( (b) - (a) ) ) >  (((mask)&U32_MAX)>>1) )
#define UXX_GE( mask, a, b )  ( ((mask)&( (a) - (b) ) ) <= (((mask)&U32_MAX)>>1) )

#define MAX_UXX( mask, a, b ) ( (UXX_GT(mask,a,b)) ? (a) : (b) )
#define MIN_UXX( mask, a, b ) ( (UXX_LT(mask,a,b)) ? (a) : (b) )


#define UXX_GET_MAX(mask, a, b ) ( (UXX_GT( (mask), (a), (b) )) ? (a) : (b) )




#define WARNING_PERIOD 20000

#define MAX_PATH_SIZE 300
#define MAX_ARG_SIZE 200


extern TIME_T bmx_time;
extern TIME_SEC_T bmx_time_sec;

extern IDM_T initializing;
extern IDM_T terminating;
extern IDM_T cleaning_up;


extern uint32_t s_curr_avg_cpu_load;

extern IDM_T my_description_changed;



/**
 * The most important data structures
 */

enum {
	FIELD_TYPE_UINT,
	FIELD_TYPE_HEX,
	FIELD_TYPE_STRING_SIZE,
	FIELD_TYPE_STRING_CHAR,
	FIELD_TYPE_STRING_BINARY,
	FIELD_TYPE_POINTER_CHAR,
        FIELD_TYPE_POINTER_GLOBAL_ID,
        FIELD_TYPE_POINTER_SHORT_ID,
        FIELD_TYPE_GLOBAL_ID,
        FIELD_TYPE_UMETRIC,
        FIELD_TYPE_POINTER_UMETRIC,
        FIELD_TYPE_FMETRIC8,
	FIELD_TYPE_IP4,
	FIELD_TYPE_IPX,
	FIELD_TYPE_IPX4,
	FIELD_TYPE_IPX6,
	FIELD_TYPE_IPX6P,
	FIELD_TYPE_NETP,
	FIELD_TYPE_MAC,

	FIELD_TYPE_END
};

#define FIELD_STANDARD_SIZES {-1,-1,-1,-8,-8,(8*sizeof(char*)), \
                              (8*sizeof(GLOBAL_ID_T*)),(8*sizeof(GLOBAL_ID_T*)),(8*sizeof(GLOBAL_ID_T)), \
                              (8*sizeof(UMETRIC_T)),(8*sizeof(UMETRIC_T*)),(8*sizeof(FMETRIC_U8_T)), \
                              (8*sizeof(IP4_T)), (8*sizeof(IPX_T)), (8*sizeof(IPX_T)), (8*sizeof(IP6_T)), \
                              (8*sizeof(IP6_T*)), (8*sizeof(struct net_key*)), (8*sizeof(MAC_T))}
// negative values mean size must be multiple of negativ value, positive values mean absolute bit sizes

#define FIELD_FORMAT_MAX_ITEMS 100
enum {
        FIELD_RELEVANCE_LOW,
        FIELD_RELEVANCE_MEDI,
        FIELD_RELEVANCE_HIGH
};

#define ARG_RELEVANCE "relevance"
#define DEF_RELEVANCE FIELD_RELEVANCE_HIGH
#define MAX_RELEVANCE FIELD_RELEVANCE_HIGH
#define MIN_RELEVANCE FIELD_RELEVANCE_LOW
#define HLP_ARG_RELEVANCE        "filter for given minimum relevance"


struct field_format {
	uint16_t field_type;
        int32_t field_pos; // -1 means relative to previous 
	uint32_t field_bits;
	uint8_t field_host_order;
        uint8_t field_relevance;
	const char * field_name;
};

#define FIELD_FORMAT_END {FIELD_TYPE_END, 0, 0, 0, FIELD_RELEVANCE_LOW, NULL}
#define FIELD_STR_VALUE(name) #name
#define FIELD_FORMAT_INIT(f_type, f_struct_name, f_struct_field, f_host_order, f_relevance) { \
.field_type = f_type, \
.field_pos = (((unsigned long)&(((struct f_struct_name*) NULL)->f_struct_field))*8), \
.field_bits = (sizeof( (((struct f_struct_name *) NULL)->f_struct_field) ) * 8), \
.field_host_order = f_host_order, \
.field_relevance = f_relevance, \
.field_name = FIELD_STR_VALUE(f_struct_field) \
}

struct field_iterator {
        const struct field_format *format;
//        char * msg_name;
        uint8_t *data;
        uint32_t data_size;
        uint32_t min_msg_size;
//        uint8_t fixed_msg_size;

        uint32_t field;
        uint32_t field_bits;
        uint32_t var_bits;
        uint32_t field_bit_pos;
        uint32_t msg_bit_pos;

};

struct status_handl {
        uint16_t min_msg_size;
        IDM_T multiline;
        char status_name[16];
        uint8_t *data;

	int32_t (*frame_creator) (struct status_handl *status_handl, void *data);

	const struct field_format *format;
};

extern struct avl_tree status_tree;


int16_t field_format_get_items(const struct field_format *format);

int64_t field_get_value(const struct field_format *format, uint32_t min_msg_size, uint8_t *data, uint32_t pos_bit, uint32_t bits);

char *field_dbg_value(const struct field_format *format, uint32_t min_msg_size, uint8_t *data, uint32_t pos_bit, uint32_t bits);

uint32_t fields_dbg_lines(struct ctrl_node *cn, uint16_t relevance, uint32_t data_size, uint8_t *data,
	uint32_t min_msg_size, const struct field_format *format);


uint32_t field_iterate(struct field_iterator *it);

void register_status_handl(uint16_t min_msg_size, IDM_T multiline, const struct field_format* format, char *name,
                            int32_t(*creator) (struct status_handl *status_handl, void *data));








#define timercpy(d, a) (d)->tv_sec = (a)->tv_sec; (d)->tv_usec = (a)->tv_usec;



enum {
	CLEANUP_SUCCESS,
	CLEANUP_FAILURE,
	CLEANUP_MY_SIGSEV,
	CLEANUP_RETURN
};



/***********************************************************
 Runtime Infrastructure
************************************************************/


#define goto_error( where, what ) do { goto_error_code=what; goto where; }while(0)
#define goto_error_return( where, what, ret ) do { goto_error_code=what; goto_error_ret=ret; goto where; }while(0)

#ifdef NO_ASSERTIONS
#define paranoia( ... )
#define assertion( ... )
#define assertion_dbg( ... )
#define ASSERTION( ... )
#define EXITERROR( ... )
#define CHECK_INTEGRITY( ... )

#else//NO_ASSERTIONS

/*
 * ASSERTION / PARANOIA ERROR CODES:
 * Negative numbers are used as SIGSEV error codes !
 * Currently used numbers are: -500000 -500001 ... -502518
 */

//#define paranoia( code , problem ) do { if ( (problem) ) { cleanup_all( code ); } }while(0)
#define assertion( code , condition ) do { if ( !(condition) ) { cleanup_all( code ); } }while(0)
#define assertion_dbg( code , condition, ... ) do { if ( !(condition) ) { dbgf_sys(DBGT_ERR, __VA_ARGS__ ); cleanup_all( code ); } }while(0)

#ifdef EXTREME_PARANOIA
#define ASSERTION( code , condition ) do { if ( !(condition) ) { cleanup_all( code ); } }while(0)
#define CHECK_INTEGRITY( ) checkIntegrity()
#else
#define CHECK_INTEGRITY( )
#define ASSERTION( code , condition )
#endif

#ifdef EXIT_ON_ERROR
#define EXITERROR( code , condition )                                                                                  \
  do {                                                                                                                 \
      if ( !(condition) ) {                                                                                            \
        dbgf(DBGL_SYS, DBGT_ERR, "This is paranoid! Disable EXIT_ON_ERROR to not exit due to others' misbehavior !!"); \
           cleanup_all( code );                                                                                        \
      }                                                                                                                \
  }while(0)
#else
#define EXITERROR( code , condition )
#endif

#define TEST_FUNCTION(X) ( ((void(*)(void*))&(X)) != NULL )
#define TEST_VALUE(X) (((uint32_t)X) != 1234543210)
#define TEST_STRUCT(X) (sizeof(X) > 0)
#define TEST_VARIABLE(X) ((void*)&X != NULL )

#endif//NO_ASSERTIONS


#ifndef PROFILING
#define STATIC_FUNC static
#define STATIC_INLINE_FUNC static inline
#else
#define STATIC_FUNC
#define STATIC_INLINE_FUNC
#endif

#ifdef STATIC_VARIABLES
#define STATIC_VAR static
#else
#define STATIC_VAR
#endif


#ifndef NO_TRACE_FUNCTION_CALLS

#define FUNCTION_CALL_BUFFER_SIZE 64

void trace_function_call(const char *);

#define TRACE_FUNCTION_CALL trace_function_call ( __FUNCTION__ )

#else

#define TRACE_FUNCTION_CALL

#endif


void wait_sec_msec( TIME_SEC_T sec, TIME_T msec );

void cleanup_all( int32_t status );

char *get_human_uptime( uint32_t reference );

DESC_SQN_T newDescriptionSqn( char* newPath, uint8_t ass );


/***********************************************************
 Configuration data and handlers
************************************************************/



IDM_T validate_param(int32_t probe, int32_t min, int32_t max, char *name);

int32_t opt_status(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn);
int32_t opt_flush_all(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn);
