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
//#include "math.h"


#include "bmx.h"
#include "msg.h"
#include "ip.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "metrics.h"



static int32_t my_path_algo = DEF_METRIC_ALGO;
static int32_t my_path_rp_exp_numerator = DEF_PATH_RP_EXP_NUMERATOR;
static int32_t my_path_rp_exp_divisor = DEF_PATH_RP_EXP_DIVISOR;
static int32_t my_path_tp_exp_numerator = DEF_PATH_TP_EXP_NUMERATOR;
static int32_t my_path_tp_exp_divisor = DEF_PATH_TP_EXP_DIVISOR;

static int32_t my_path_metric_flags = DEF_PATH_METRIC_FLAGS;
static int32_t my_path_umetric_min = DEF_PATH_UMETRIC_MIN;
static int32_t my_path_window = DEF_PATH_WINDOW;
static int32_t my_path_lounge = DEF_PATH_LOUNGE;
static int32_t my_path_regression = DEF_PATH_REGRESSION_SLOW;
static int32_t my_path_hystere = DEF_PATH_HYST;
static int32_t my_hop_penalty = DEF_HOP_PENALTY;
static int32_t my_late_penalty = DEF_LATE_PENAL;

static int32_t new_rt_dismissal_div100 = DEF_NEW_RT_DISMISSAL;

static int32_t my_link_window = DEF_HELLO_SQN_WINDOW;

int32_t link_ignore_min = DEF_LINK_IGNORE_MIN;

int32_t link_ignore_max = DEF_LINK_IGNORE_MAX;



//TODO: evaluate my_fmetric_exp_offset based on max configured dev_metric_max:
//static int32_t my_fmetric_exp_offset = DEF_FMETRIC_EXP_OFFSET;
//TODO: reevaluate my_dev_metric_max based on deduced my_fmetric_exp_offset (see above)
//UMETRIC_T my_dev_metric_max = umetric_max(DEF_FMETRIC_EXP_OFFSET);

static
void (*path_metric_algos[BIT_METRIC_ALGO_ARRSZ])
(UMETRIC_T *path_out, struct link_dev_node *link, UMETRIC_T lp) = {NULL};

static UMETRIC_T UMETRIC_MAX_SQRT;
static UMETRIC_T U64_MAX_HALF_SQRT;
#define U64_MAX_HALF             (U64_MAX>>1)
#define UMETRIC_MAX_SQRT_SQUARE  (UMETRIC_MAX_SQRT * UMETRIC_MAX_SQRT)
#define U64_MAX_HALF_SQRT_SQUARE (U64_MAX_HALF_SQRT * U64_MAX_HALF_SQRT)


//TODO: remove:
UMETRIC_T UMETRIC_NBDISCOVERY_MIN = (UMETRIC_MAX/10);



FMETRIC_U16_T fmetric(uint8_t mantissa, uint8_t exp)
{

        FMETRIC_U16_T fm;
        fm.val.f.mantissa_fm16 = mantissa;
        fm.val.f.exp_fm16 = exp;

        return fm;
}

UMETRIC_T umetric(uint8_t mantissa, uint8_t exp)
{
	return fmetric_to_umetric(fmetric(mantissa, exp));
}





IDM_T is_umetric_valid(const UMETRIC_T *um)
{
        assertion(-500704, (um));
        return ( *um <= UMETRIC_MAX);
}


IDM_T is_fmetric_valid(FMETRIC_U16_T fm)
{
        return fm.val.f.mantissa_fm16 <= OGM_MANTISSA_MASK && (
                fm.val.f.exp_fm16 < OGM_EXPONENT_MAX || (
                fm.val.f.exp_fm16 == OGM_EXPONENT_MAX && fm.val.f.mantissa_fm16 <= OGM_MANTISSA_MAX));
}



IDM_T fmetric_cmp(FMETRIC_U16_T a, unsigned char cmp, FMETRIC_U16_T b)
{


        assertion(-500706, (is_fmetric_valid(a) && is_fmetric_valid(b)));

        switch (cmp) {

        case '!':
                return (a.val.u16 != b.val.u16);
        case '<':
                return (a.val.u16 < b.val.u16);
        case '[':
                return (a.val.u16 <= b.val.u16);
        case '=':
                return (a.val.u16 == b.val.u16);
        case ']':
                return (a.val.u16 >= b.val.u16);
        case '>':
                return (a.val.u16 > b.val.u16);
        }

        assertion(-500707, (0));
        return FAILURE;
}


UMETRIC_T fmetric_to_umetric(FMETRIC_U16_T fm)
{
        TRACE_FUNCTION_CALL;

        assertion(-500680, (is_fmetric_valid(fm)));

        return (((UMETRIC_T) 1) << (fm.val.f.exp_fm16 + OGM_EXPONENT_OFFSET)) +
                (((UMETRIC_T) fm.val.f.mantissa_fm16) << (fm.val.f.exp_fm16));
}



FMETRIC_U16_T umetric_to_fmetric(UMETRIC_T val)
{

        TRACE_FUNCTION_CALL;

        FMETRIC_U16_T fm = {.val.u16 = 0};

        if( val < UMETRIC_MIN__NOT_ROUTABLE ) {

                //assign minimum possible value:
                fm.val.f.exp_fm16 = 0;
                fm.val.f.mantissa_fm16 = OGM_MANTISSA_INVALID;

        } else if ( val >= UMETRIC_MAX ) {

                //assign maximum possible value:
                fm.val.f.exp_fm16 = OGM_EXPONENT_MAX;
                fm.val.f.mantissa_fm16 = OGM_MANTISSA_MAX;

        } else {

                uint8_t exp_sum = 0;
                UMETRIC_T tmp = 0;
                tmp = val + (val/UMETRIC_TO_FMETRIC_INPUT_FIX);

                LOG2(exp_sum, tmp, UMETRIC_T);

                fm.val.f.exp_fm16 = (exp_sum - OGM_EXPONENT_OFFSET);
                fm.val.f.mantissa_fm16 = ( (tmp>>(exp_sum-OGM_MANTISSA_BIT_SIZE)) - (1<<OGM_MANTISSA_BIT_SIZE) );

                assertion(-501025, (tmp >= val));
                assertion(-501026, (val > (1<<OGM_EXPONENT_OFFSET)));
                assertion(-501027, (exp_sum >= OGM_EXPONENT_OFFSET));
                assertion(-501028, ((tmp>>(exp_sum-OGM_MANTISSA_BIT_SIZE)) >= (1<<OGM_EXPONENT_OFFSET)));
        }

/*
        #ifdef EXTREME_PARANOIA
                UMETRIC_T reverse = fmetric_to_umetric(fm);
                int32_t failure = - ((int32_t)((val<<10)/(val?val:1))) + ((int32_t)((reverse<<10)/(val?val:1)));

                dbgf_track(DBGT_INFO, "val=%-12ju tmp=%-12ju reverse=%-12ju failure=%5d/1024 exp_sum=%2d exp=%d mantissa=%d",
                        val, tmp, reverse, failure, exp_sum, fm.val.fu16_exp, fm.val.fu16_mantissa);
        #endif
*/

        assertion(-500681, (is_fmetric_valid(fm)));

        return fm;
}


char *umetric_to_human(UMETRIC_T val) {
#define UMETRIC_TO_HUMAN_ARRAYS 4
        static char out[UMETRIC_TO_HUMAN_ARRAYS][12] = {{0},{0},{0},{0}};
        static uint8_t p=0;
        p = ((p + 1) % UMETRIC_TO_HUMAN_ARRAYS);

        if (val < UMETRIC_MIN__NOT_ROUTABLE) {
                sprintf(out[p], "INVALID");
        } else if (val <= UMETRIC_MIN__NOT_ROUTABLE) {
                sprintf(out[p], "noROUTE");
        } else if (val <= UMETRIC_ROUTABLE) {
                sprintf(out[p], "ROUTE  ");
        } else if (val > UMETRIC_MAX) {
                sprintf(out[p], "INFINTE");
        } else {

                if (val < 100000) {
                        sprintf(out[p], "%5ju b", val);
                } else if (val < 100000000) {
                        sprintf(out[p], "%5ju K", val/1000);
                } else if (val < 100000000000) {
                        sprintf(out[p], "%5ju M", val/1000000);
                } else if (val < 100000000000000) {
                        sprintf(out[p], "%5ju G", val/1000000000);
                }
        }
        return out[p];
}

FMETRIC_U16_T fmetric_u8_to_fmu16( FMETRIC_U8_T fmu8 ) {

        FMETRIC_U16_T fm = {.val.f =
                {
                        .mantissa_fm16 = (fmu8.val.f.mantissa_fmu8<<(OGM_MANTISSA_BIT_SIZE - FM8_MANTISSA_BIT_SIZE)),
                        .exp_fm16 = fmu8.val.f.exp_fmu8
                }
        };

        assertion(-501032, (is_fmetric_valid(fm)));

        return fm;
}

FMETRIC_U8_T fmetric_to_fmu8( FMETRIC_U16_T fm ) {

        assertion(-501035, (is_fmetric_valid(fm)));

        FMETRIC_U8_T fmu8 = {.val.f =
                {
                        .mantissa_fmu8 = (FM8_MANTISSA_MASK & ((fm.val.f.mantissa_fm16) >> (OGM_MANTISSA_BIT_SIZE - FM8_MANTISSA_BIT_SIZE))),
                        .exp_fmu8 = fm.val.f.exp_fm16
                }
        };

        return fmu8;
}

FMETRIC_U8_T umetric_to_fmu8( UMETRIC_T *um )
{
        return fmetric_to_fmu8(umetric_to_fmetric(*um));
}



STATIC_INLINE_FUNC
FMETRIC_U16_T fmetric_substract_min(FMETRIC_U16_T f)
{

        if (f.val.f.mantissa_fm16) {
                
                f.val.f.mantissa_fm16--;

        } else if (f.val.f.exp_fm16) {
                
                f.val.f.mantissa_fm16 = OGM_MANTISSA_MASK;
                f.val.f.exp_fm16--;
        }
        
        return f;
}

STATIC_INLINE_FUNC
UMETRIC_T umetric_substract_min(const UMETRIC_T *val)
{
        return fmetric_to_umetric(fmetric_substract_min(umetric_to_fmetric(*val)));
}


STATIC_INLINE_FUNC
UMETRIC_T umetric_multiply_normalized(UMETRIC_T a, UMETRIC_T b)
{
        if (b < UMETRIC_MULTIPLY_MAX)
                return (a * b) / UMETRIC_MAX;
        else
                return (a * ((b << UMETRIC_SHIFT_MAX) / UMETRIC_MAX)) >> UMETRIC_SHIFT_MAX;
}




STATIC_INLINE_FUNC
UMETRIC_T umetric_fast_sqrt(float x)
{
        return (((1.0f) / fast_inverse_sqrt(x)) + 0.5f);
}


STATIC_INLINE_FUNC
UMETRIC_T umetric_multiply_sqrt(UMETRIC_T um, UMETRIC_T x)
{
        ASSERTION(-501076, (x <= UMETRIC_MAX));

        return (um * umetric_fast_sqrt(x)) / UMETRIC_MAX_SQRT;
}

UMETRIC_T umetric_to_the_power_of_n(UMETRIC_T x, uint8_t n_exp_numerator, uint8_t n_exp_divisor)
{

        assertion(-501077, (n_exp_divisor == 1 || n_exp_divisor == 2));

        switch ( n_exp_numerator ) {

        case 0:
                return UMETRIC_MAX;
        case 1:
                return (n_exp_divisor == 1 ? x : umetric_fast_sqrt(x) * UMETRIC_MAX_SQRT);
        case 2:
                return (n_exp_divisor == 1 ? umetric_multiply_normalized(x, x) : x);
        case 3:
                return (n_exp_divisor == 1 ?
                        umetric_multiply_normalized(x, umetric_multiply_normalized(x, x)) :
                        (x * umetric_fast_sqrt(x)) / UMETRIC_MAX_SQRT);
        }

        return 0;
}

STATIC_FUNC
void path_metricalgo_MultiplyQuality(UMETRIC_T *path, struct link_dev_node *lndev, UMETRIC_T linkQuality)
{
        *path = umetric_multiply_normalized(*path, linkQuality);
}

STATIC_FUNC
void path_metricalgo_ExpectedQuality(UMETRIC_T *path, struct link_dev_node *lndev, UMETRIC_T linkQuality)
{
        if (*path < 2 || linkQuality < 2)
                *path = UMETRIC_MIN__NOT_ROUTABLE;
        else
                *path = (U64_MAX / ((U64_MAX / *path) + (U64_MAX / linkQuality)));
}

STATIC_FUNC
void path_metricalgo_MultiplyBandwidth(UMETRIC_T *path, struct link_dev_node *lndev, UMETRIC_T linkQuality)
{
        *path = umetric_multiply_normalized(MIN(*path, lndev->key.dev->umetric_max), linkQuality);
}

STATIC_FUNC
void path_metricalgo_ExpectedBandwidth(UMETRIC_T *path, struct link_dev_node *lndev, UMETRIC_T linkQuality)
{
        UMETRIC_T linkBandwidth = umetric_multiply_normalized(lndev->key.dev->umetric_max, linkQuality);

        if (*path < 2 || linkBandwidth < 2)
                *path = UMETRIC_MIN__NOT_ROUTABLE;
        else
                *path = (U64_MAX / ((U64_MAX / *path) + (U64_MAX / linkBandwidth)));
}

STATIC_FUNC
void path_metricalgo_VectorBandwidth(UMETRIC_T *path, struct link_dev_node *lndev, UMETRIC_T linkQuality)
{
        assertion(-501085, (*path > UMETRIC_MIN__NOT_ROUTABLE));

        UMETRIC_T inverseSquaredPathBandwidth = 0;
        UMETRIC_T inverseSquaredLinkQuality = 0;
        UMETRIC_T rootOfSum = 0;
        UMETRIC_T path_out = UMETRIC_MIN__NOT_ROUTABLE;

        UMETRIC_T linkBandwidth = umetric_multiply_normalized(lndev->key.dev->umetric_max, linkQuality);
        
        UMETRIC_T maxPrecisionScaler = MIN(*path, linkBandwidth) * U64_MAX_HALF_SQRT;


        if (linkQuality > UMETRIC_MIN__NOT_ROUTABLE) {


                inverseSquaredPathBandwidth = ((maxPrecisionScaler / *path) * (maxPrecisionScaler / *path));
                inverseSquaredLinkQuality = ((maxPrecisionScaler / linkBandwidth) * (maxPrecisionScaler / linkBandwidth));

                rootOfSum = umetric_fast_sqrt(inverseSquaredPathBandwidth + inverseSquaredLinkQuality);
                path_out = maxPrecisionScaler / rootOfSum;
        }

        dbgf_all( DBGT_INFO,
                "pb=%-12ju max_extension=%-19ju (me/pb)^2=%-19ju lp=%-12ju link=%-12ju lb=%-12ju (me/lb)^2=%-19ju ufs=%-12ju UMETRIC_MIN=%ju -> path_out=%ju",
                *path, maxPrecisionScaler, inverseSquaredPathBandwidth, linkQuality, lndev->key.dev->umetric_max,
                linkBandwidth, inverseSquaredLinkQuality, rootOfSum, UMETRIC_MIN__NOT_ROUTABLE, path_out);
        
       *path = path_out;
}



STATIC_FUNC
void register_path_metricalgo(uint8_t algo_type_bit, void (*algo) (UMETRIC_T *path_out, struct link_dev_node *lndev, UMETRIC_T lp))
{
        assertion(-500838, (!path_metric_algos[algo_type_bit]));
        assertion(-500839, (algo_type_bit < BIT_METRIC_ALGO_ARRSZ));
        path_metric_algos[algo_type_bit] = algo;
}

STATIC_FUNC
UMETRIC_T apply_metric_algo(struct link_dev_node *lndev, const UMETRIC_T *path, struct host_metricalgo *algo)
{
        TRACE_FUNCTION_CALL;


        assertion(-500823, (lndev->key.dev->umetric_max));
        assertion(-501037, ((*path & ~UMETRIC_MASK) == 0));
        assertion(-501038, (*path <= UMETRIC_MAX));
        assertion(-501039, (*path >= UMETRIC_MIN__NOT_ROUTABLE));

        ALGO_T unsupported_algos = 0;
        ALGO_T algo_type = algo->algo_type;
        UMETRIC_T max_out = umetric_substract_min(path);
        UMETRIC_T path_out = *path;

        UMETRIC_T tq = umetric_to_the_power_of_n(lndev->timeaware_tx_probe, algo->algo_tp_exp_numerator, algo->algo_tp_exp_divisor);
        UMETRIC_T rq = umetric_to_the_power_of_n(lndev->timeaware_rx_probe, algo->algo_rp_exp_numerator, algo->algo_rp_exp_divisor);
        UMETRIC_T tr = umetric_multiply_normalized(tq,rq);

        if (max_out <= UMETRIC_MIN__NOT_ROUTABLE)
                return UMETRIC_MIN__NOT_ROUTABLE;

        if (algo_type) {

                while (algo_type) {

                        uint8_t algo_type_bit;
                        LOG2(algo_type_bit, algo_type, ALGO_T);

                        algo_type -= (0x01 << algo_type_bit);

                        if (path_metric_algos[algo_type_bit]) {

                                (*(path_metric_algos[algo_type_bit])) (&path_out, lndev, tr);

                                dbgf_all( DBGT_INFO, "algo=%d rp=%-3ju%% tp=%-3ju%% in=%-12ju=%7s  out=%-12ju=%7s UMETRIC_MAX=%-12ju UMETRIC_LP_MAX=%-12ju",
                                        algo_type_bit, 
                                        ((lndev->timeaware_rx_probe * 100) / UMETRIC_MAX),
                                        ((lndev->timeaware_tx_probe * 100) / UMETRIC_MAX),
                                        *path, umetric_to_human(*path), path_out, umetric_to_human(path_out),
                                        UMETRIC_MAX, UMETRIC_MAX );

                        } else {
                                unsupported_algos |= (0x01 << algo_type_bit);
                        }
                }

                if (unsupported_algos) {
                        uint8_t i = bits_count(unsupported_algos);

                        dbgf_sys(DBGT_WARN,
                                "unsupported %s=%d (0x%X) - Need an update?! - applying pessimistic ETTv0 %d times",
                                ARG_PATH_METRIC_ALGO, unsupported_algos, unsupported_algos, i);

                        while (i--)
                                (*(path_metric_algos[BIT_METRIC_ALGO_EB])) (&path_out, lndev, tr);
                }
        }

        if (algo->hop_penalty)
                path_out = (path_out * ((UMETRIC_T) (MAX_HOP_PENALTY - algo->hop_penalty))) >> MAX_HOP_PENALTY_PRECISION_EXP;

        if (path_out <= UMETRIC_MIN__NOT_ROUTABLE)
                return UMETRIC_MIN__NOT_ROUTABLE;



        if (path_out > max_out) {
                dbgf_all(DBGT_WARN,
                        "out=%ju > out_max=%ju, %s=%d, path=%ju, dev=%s, link_MAX=%ju, RP=%ju, TP=%ju",
                        path_out, max_out, ARG_PATH_METRIC_ALGO, algo->algo_type, *path,
                        lndev->key.dev->label_cfg.str, lndev->key.dev->umetric_max,
                        lndev->timeaware_rx_probe, lndev->timeaware_tx_probe);
        }


        return MIN(path_out, max_out); // ensure out always decreases
}

STATIC_FUNC
void _reconfigure_metric_record_position(const char *f, struct metric_record *rec, struct host_metricalgo *alg,
        SQN_T min, SQN_T in, uint8_t sqn_bit_size, uint8_t reset)
{
        TRACE_FUNCTION_CALL;
        assertion(-500737, (XOR(sqn_bit_size, rec->sqn_bit_mask)));

        if (sqn_bit_size)
                rec->sqn_bit_mask = (~(SQN_MAX << sqn_bit_size));

        assertion(-500738, (rec->sqn_bit_mask == U16_MAX || rec->sqn_bit_mask == U8_MAX ||
                rec->sqn_bit_mask == HELLO_SQN_MAX));


        if (rec->clr && /*alg->window_size > 1 &&*/ ((rec->sqn_bit_mask)&(in - rec->clr)) > (alg->lounge_size + 1)) {
                dbgf_track(DBGT_WARN, "reset_metric=%d sqn_bit_size=%d sqn_bit_mask=0x%X umetric=%ju clr=%d to ((in=%d) - (lounge=%d))=%d",
                        reset, sqn_bit_size, rec->sqn_bit_mask, rec->umetric, rec->clr, in, alg->lounge_size, ((rec->sqn_bit_mask)& (in - alg->lounge_size)));
        }

        rec->clr = MAX_UXX(rec->sqn_bit_mask, min, ((rec->sqn_bit_mask)&(in - alg->lounge_size)));

        rec->set = ((rec->sqn_bit_mask)&(rec->clr - 1));

        if (reset) {
                rec->umetric = 0;
        }

        dbgf_all(DBGT_WARN, "%s reset_metric=%d sqn_bit_size=%d sqn_bit_mask=0x%X min=%d in=%d lounge_size=%d umetric=%ju clr=%d",
                f, reset, sqn_bit_size, rec->sqn_bit_mask, min, in, alg->lounge_size, rec->umetric, rec->clr);

}

#define reconfigure_metric_record_position(rec, alg, min, in, sqn_bit_size, reset) \
  _reconfigure_metric_record_position(__FUNCTION__, rec, alg, min, in, sqn_bit_size, reset)

STATIC_FUNC
IDM_T update_metric_record(struct orig_node *on, struct router_node *rt, SQN_T in, const UMETRIC_T *probe)
{
        TRACE_FUNCTION_CALL;
        char *scenario = NULL;
        
        struct metric_record *rec = &rt->mr;
        struct host_metricalgo *alg = on->path_metricalgo;
        SQN_T range = on->ogmSqn_rangeSize;
        SQN_T min = on->ogmSqn_rangeMin;

        SQN_T i, purge = 0;
        SQN_T dbg_clr;
        SQN_T dbg_set;
        dbg_clr = rec->clr; // avoid unused warning
        dbg_set = rec->set; // avoid unused warning

        ASSERTION(-500739, (!((~(rec->sqn_bit_mask))&(min))));
        ASSERTION(-500740, (!((~(rec->sqn_bit_mask))&(in))));
        ASSERTION(-500741, (!((~(rec->sqn_bit_mask))&(rec->clr))));
        ASSERTION(-500742, (!((~(rec->sqn_bit_mask))&(rec->set))));

        assertion(-500743, (range <= MAX_SQN_RANGE));
        assertion(-500908, (is_umetric_valid(&rec->umetric)));
        assertion(-500174, (IMPLIES(probe, (*probe <= UMETRIC_MAX))));


        if (((rec->sqn_bit_mask)&(rec->clr - min)) >= range) {

                if (rec->clr) {
                        dbgf_track(DBGT_ERR, "sqn_bit_mask=0x%X clr=%d out of range, in=%d valid_min=%d defined_range=%d",
                                rec->sqn_bit_mask, rec->clr, in, min, range);
                }

                reconfigure_metric_record_position(rec, alg, min, in, 0, YES/*reset_metric*/);
        }

        if (probe && !is_umetric_valid(probe)) {

                scenario = "probe contains illegal value";
                goto update_metric_error;

        } else if (((rec->sqn_bit_mask)&(in - min)) >= range) {

                scenario = "in out of defined_range (sector J)";
                goto update_metric_error;

        } else if (((rec->sqn_bit_mask)&(rec->clr - min)) >= range) {

                scenario = "clr out of defined_range (sector J)";
                goto update_metric_error;

        } else if (((rec->sqn_bit_mask)&(rec->clr - rec->set)) > 1) {

                scenario = "set invalid (compared to clr)";
                goto update_metric_error;
        }


        if (UXX_LE(rec->sqn_bit_mask, in, (rec->clr - alg->window_size))) {

                scenario = "in within valid past (sector I|H)";
                goto update_metric_success;

        } else if (in == rec->set) {

//                assertion(-501071, (in == rec->clr));
                if ( probe ) {

                        if ((*probe == 0 || *probe > rec->umetric))
                                rec->umetric = *probe;
                }

        } else if (UXX_LE(rec->sqn_bit_mask, in, rec->set)) {

                scenario = "in within (closed) window, in < set (sector F|G)";
                goto update_metric_success;

        } else if (probe) {

                dbgf_all(DBGT_INFO,"in=%d min=%d range=%d clr=%d", in, min, range, rec->clr);
                assertion(-500708, (UXX_LE(rec->sqn_bit_mask, in, min + range)));
                assertion(-500721, (UXX_GE(rec->sqn_bit_mask, in, rec->clr)));

                purge = ((rec->sqn_bit_mask)&(in - rec->clr));

                if (purge > 2) {
                        // scenario = "resetting and updating: probe!=NULL, in within lounge or valid future (sector E|D|C|B|A)";
                }

                if (alg->regression == 1 /*|| alg->flags & TYP_METRIC_FLAG_STRAIGHT*/) {

                        rec->umetric = *probe;

                } else {

                        if (purge < alg->window_size) {

                                for (i = 0; i < purge; i++)
                                        rec->umetric -= (rec->umetric / alg->regression);
                        } else {
                                reconfigure_metric_record_position(rec, alg, min, in, 0, YES/*reset_metric*/);
                        }

                        if ((rec->umetric += (*probe / alg->regression)) > *probe) {
                                dbgf_track(DBGT_WARN, "resulting path metric=%ju > probe=%ju", rec->umetric, *probe);
                                rec->umetric = *probe;
                        }
                }

                rec->clr = rec->set = in;


        } else if (UXX_LE(rec->sqn_bit_mask, in, rec->clr + alg->lounge_size)) {

                //scenario = "ignoring: probe==NULL, in within lounge (sector E,D,C)";

        } else {

                assertion(-500709, (UXX_LE(rec->sqn_bit_mask, in, min + range)));
//[20609  1347921] ERROR metric_record_init: reset_metric=0 sqn_bit_size=0 sqn_bit_mask=0xFF clr=186 to ((in=188) - (lounge=1))=187

                purge = ((rec->sqn_bit_mask)&((in - alg->lounge_size) - rec->clr));

                if (purge > 2)
                        scenario = "purging: probe==NULL, in within valid future (sector B|A)";

                assertion(-500710, (purge > 0));

                if (purge >= alg->window_size) {

                        reconfigure_metric_record_position(rec, alg, min, in, 0, YES/*reset_metric*/);

                } else {

                        for (i = 0; i < purge; i++)
                                rec->umetric -= (rec->umetric / alg->regression);

                        reconfigure_metric_record_position(rec, alg, min, in, 0, NO/*reset_metric*/);
                }
        }

        assertion(-500711, (is_umetric_valid(&rec->umetric)));

        goto update_metric_success;



        IDM_T ret = FAILURE;

update_metric_success:
        ret = SUCCESS;

update_metric_error:

        if (scenario) {
                dbgf_track(ret == FAILURE ? DBGT_ERR : DBGT_WARN,
                        "[%s] sqn_bit_mask=0x%X in=%d clr=%d>%d set=%d>%d valid_min=%d range=%d lounge=%d window=%d purge=%d probe=%ju ",
                        scenario, rec->sqn_bit_mask, in, dbg_clr, rec->clr, dbg_set, rec->set, min, range, alg->lounge_size, alg->window_size, purge, probe ? *probe : 0);
        }


        EXITERROR(-500712, (ret != FAILURE));

        if (on && on->curr_rt_local == rt && rec->umetric < on->path_metricalgo->umetric_min)
                set_ogmSqn_toBeSend_and_aggregated(on, on->ogmMetric_next, on->ogmSqn_send, on->ogmSqn_send);

        return ret;
}

STATIC_FUNC
UMETRIC_T timeaware_rx_probe(struct link_dev_node *lndev)
{
        if (((TIME_T) (bmx_time - lndev->rx_probe_record.time_max)) < RP_ADV_DELAY_TOLERANCE)
                return lndev->rx_probe_record.umetric;

        if (((TIME_T) (bmx_time - lndev->rx_probe_record.time_max)) < RP_ADV_DELAY_RANGE) {
                return (lndev->rx_probe_record.umetric *
                        ((UMETRIC_T) (RP_ADV_DELAY_RANGE - (bmx_time - lndev->rx_probe_record.time_max)))) /
                        RP_ADV_DELAY_RANGE;
        }

        return 0;
}

STATIC_FUNC
UMETRIC_T timeaware_tx_probe(struct link_dev_node *lndev)
{
        if (((TIME_T) (bmx_time - lndev->key.link->local->rp_adv_time)) < TP_ADV_DELAY_TOLERANCE)
                return lndev->tx_probe_umetric;

        if (((TIME_T) (bmx_time - lndev->key.link->local->rp_adv_time)) < TP_ADV_DELAY_RANGE) {
                return (lndev->tx_probe_umetric *
                        ((UMETRIC_T) (TP_ADV_DELAY_RANGE - (bmx_time - lndev->key.link->local->rp_adv_time)))) /
                        TP_ADV_DELAY_RANGE;
        }

        return 0;
}


void lndev_assign_best(struct local_node *only_local, struct link_dev_node *only_lndev )
{
        TRACE_FUNCTION_CALL;

        assertion(-501133, (IMPLIES(only_lndev, only_local && only_local == only_lndev->key.link->local)));
        ASSERTION(-500792, (IMPLIES(only_lndev, only_lndev->key.link == avl_find_item(&only_local->link_tree, &only_lndev->key.link->key.dev_idx))));

        dbgf_all(DBGT_INFO, "only_local=%X only_lndev.link=%s only_lndev.dev=%s",
                only_local ? ntohl(only_local->local_id) : 0,
                only_lndev ? ipXAsStr(af_cfg, &only_lndev->key.link->link_ip): "---",
                only_lndev ? only_lndev->key.dev->label_cfg.str : "---");

        struct avl_node *local_an = NULL;
        struct local_node *local;

        while ((local = only_local) || (local = avl_iterate_item(&local_tree, &local_an))) {

                assertion(-500794, (local->link_tree.items));

                struct link_node *link = NULL;
                struct avl_node *link_an = NULL;

                if (local->best_rp_lndev)
                        local->best_rp_lndev->timeaware_rx_probe = timeaware_rx_probe(local->best_rp_lndev);

                if (local->best_tp_lndev)
                        local->best_tp_lndev->timeaware_tx_probe = timeaware_tx_probe(local->best_tp_lndev);


                dbgf_all(DBGT_INFO, "local_id=%X", ntohl(local->local_id));

                while ((only_lndev && (link = only_lndev->key.link)) || (link = avl_iterate_item(&local->link_tree, &link_an))) {

                        struct link_dev_node *lndev = NULL;
                        struct link_dev_node *prev_lndev = NULL;

                        dbgf_all(DBGT_INFO, "link=%s", ipXAsStr(af_cfg, &link->link_ip));

                        while ((only_lndev && (lndev = only_lndev)) || (lndev = list_iterate(&link->lndev_list, lndev))) {

                                dbgf_all(DBGT_INFO, "lndev=%s items=%d",
                                        lndev->key.dev->label_cfg.str, link->lndev_list.items);

                                lndev->timeaware_rx_probe = timeaware_rx_probe(lndev);
                                lndev->timeaware_tx_probe = timeaware_tx_probe(lndev);


                                if (!local->best_rp_lndev || local->best_rp_lndev->timeaware_rx_probe < lndev->timeaware_rx_probe)
                                        local->best_rp_lndev = lndev;

                                if (!local->best_tp_lndev || local->best_tp_lndev->timeaware_tx_probe < lndev->timeaware_tx_probe)
                                        local->best_tp_lndev = lndev;

                                if (only_lndev)
                                        break;

                                assertion(-501134, (prev_lndev != lndev));
                                prev_lndev = lndev;
                        }

                        if (only_lndev)
                                break;
                }


                assertion(-500406, (local->best_rp_lndev));
                assertion(-501086, (local->best_tp_lndev));

                if (local->best_tp_lndev->timeaware_tx_probe == 0)
                        local->best_tp_lndev = local->best_rp_lndev;

                local->best_lndev = (local->best_tp_lndev == local->best_rp_lndev) ? local->best_rp_lndev : NULL;


                if(only_local)
                        break;
        }
}



void update_link_probe_record(struct link_dev_node *lndev, HELLO_SQN_T sqn, uint8_t probe)
{

        TRACE_FUNCTION_CALL;
        struct link_node *link = lndev->key.link;
        struct link_probe_record *lpr = &lndev->rx_probe_record;

        ASSERTION(-501049, ((sizeof (((struct link_probe_record*) NULL)->probe_array)) * 8 == MAX_HELLO_SQN_WINDOW));
        assertion(-501050, (probe <= 1));
        ASSERTION(-501055, (bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1) == lpr->probe_sum));

        if ((link->rp_time_max || link->rp_hello_sqn_max) && link->rp_hello_sqn_max != sqn &&
                ((HELLO_SQN_MASK)&(link->rp_hello_sqn_max - sqn)) < HELLO_SQN_TOLERANCE)
                return;


        if (((HELLO_SQN_MASK)&(sqn - lpr->sqn_max)) >= my_link_window) {

                memset(lpr->probe_array, 0, MAX_HELLO_SQN_WINDOW/8);

                ASSERTION(-500159, is_zero(lpr->probe_array, MAX_HELLO_SQN_WINDOW / 8));

                if (probe)
                        bit_set(lpr->probe_array, MAX_HELLO_SQN_WINDOW, sqn, 1);

                lpr->probe_sum = probe;
                dbgf_all(DBGT_INFO, "probe=%d probe_sum=%d %d",
                        probe, lpr->probe_sum, bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1));
                
                ASSERTION(-501058, (bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1) == lpr->probe_sum));

        } else {
                if (sqn != lpr->sqn_max) {
                        HELLO_SQN_T prev_sqn_min = (HELLO_SQN_MASK)&(lpr->sqn_max + 1 - ((HELLO_SQN_T) my_link_window));
                        HELLO_SQN_T new_sqn_min_minus_one = (HELLO_SQN_MASK)&(sqn - ((HELLO_SQN_T) my_link_window));

                        dbgf_all(DBGT_INFO, "prev_min=%5d prev_max=%d new_min=%5d sqn=%5d sum=%3d bits=%3d %s",
                                prev_sqn_min,lpr->sqn_max, new_sqn_min_minus_one+1, sqn, lpr->probe_sum,
                                bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1),
                                bits_print(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1));

                        lpr->probe_sum -= bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, prev_sqn_min, new_sqn_min_minus_one);

                        dbgf_all(DBGT_INFO, "prev_min=%5d prev_max=%d new_min=%5d sqn=%5d sum=%3d bits=%3d %s",
                                prev_sqn_min,lpr->sqn_max, new_sqn_min_minus_one+1, sqn, lpr->probe_sum, 
                                bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1),
                                bits_print(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1));
                        
                        bits_clear(lpr->probe_array, MAX_HELLO_SQN_WINDOW, prev_sqn_min, new_sqn_min_minus_one);

                        dbgf_all(DBGT_INFO, "prev_min=%5d prev_max=%d new_min=%5d sqn=%5d sum=%3d bits=%3d %s\n",
                                prev_sqn_min,lpr->sqn_max, new_sqn_min_minus_one+1, sqn, lpr->probe_sum,
                                bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1),
                                bits_print(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1));

                }

                ASSERTION(-501057, (bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1) == lpr->probe_sum));

                if (!bit_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, sqn) && probe) {
                        bit_set(lpr->probe_array, MAX_HELLO_SQN_WINDOW, sqn, 1);
                        lpr->probe_sum++;
                }
                
                ASSERTION(-501056, (bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1) == lpr->probe_sum));
        }

        lpr->sqn_max = sqn;
        lpr->umetric = (UMETRIC_MAX / my_link_window) * lpr->probe_sum;
        lpr->time_max = bmx_time;

        link->rp_hello_sqn_max = sqn;
        link->rp_time_max = bmx_time;

        lndev_assign_best(link->local, lndev);

        dbgf_all(DBGT_INFO, "%s metric %ju", ipXAsStr(af_cfg, &link->link_ip), lndev->timeaware_rx_probe);
}


STATIC_FUNC
struct router_node * router_node_create(struct local_node *local, struct orig_node *on, OGM_SQN_T ogm_sqn_max)
{
        struct router_node* rt = debugMalloc(sizeof (struct router_node), -300222);

        memset(rt, 0, sizeof (struct router_node));

        rt->local_key = local;

        reconfigure_metric_record_position(&rt->mr, on->path_metricalgo, on->ogmSqn_rangeMin, ogm_sqn_max, OGM_SQN_BIT_SIZE, YES/*reset_metric*/);

        avl_insert(&on->rt_tree, rt, -300223);

        return rt;
}



STATIC_FUNC
UMETRIC_T lndev_best_via_router(struct local_node *local, struct orig_node *on, UMETRIC_T *ogm_metric, struct link_dev_node **path_lndev_best)
{

        UMETRIC_T metric_best = 0;
        // find best path lndev for this local router:
        if (local->best_lndev) {

                metric_best = apply_metric_algo(local->best_lndev, ogm_metric, on->path_metricalgo);
                *path_lndev_best = local->best_lndev;

        } else {

                struct avl_node *link_an = NULL;
                struct link_node *link;

                while ((link = avl_iterate_item(&local->link_tree, &link_an))) {

                        struct link_dev_node *lndev_tmp = NULL;

                        while ((lndev_tmp = list_iterate(&link->lndev_list, lndev_tmp))) {

                                UMETRIC_T um = apply_metric_algo(lndev_tmp, ogm_metric, on->path_metricalgo);

                                if (metric_best <= um) {
                                        metric_best = um;
                                        *path_lndev_best = lndev_tmp;
                                }
                        }
                }
        }

        assertion(-501088, (*path_lndev_best));
        return metric_best;
}


IDM_T update_path_metrics(struct packet_buff *pb, struct orig_node *on, OGM_SQN_T ogm_sqn, UMETRIC_T *ogm_metric)
{
        TRACE_FUNCTION_CALL;
        assertion(-500876, (!on->blocked));
        assertion(-500734, (on->path_metricalgo));
        assertion(-501052, ((((OGM_SQN_MASK)&(ogm_sqn - on->ogmSqn_rangeMin)) < on->ogmSqn_rangeSize)));

        OGM_SQN_T ogm_sqn_max = UXX_GET_MAX(OGM_SQN_MASK, on->ogmSqn_maxRcvd, ogm_sqn);

        dbgf_all(DBGT_INFO, "%s orig_sqn %d via neigh %s", on->id.name, ogm_sqn, pb->i.llip_str);


        if (UXX_LT(OGM_SQN_MASK, ogm_sqn, (OGM_SQN_MASK & (ogm_sqn_max - on->path_metricalgo->lounge_size)))) {
                dbgf_track(DBGT_WARN, "dropping late sqn=%d via neigh=%s from orig=%s", ogm_sqn, pb->i.llip_str, on->id.name);
                return SUCCESS;
        }

        if (UXX_LT(OGM_SQN_MASK, ogm_sqn, on->ogmSqn_next) || (ogm_sqn == on->ogmSqn_next && *ogm_metric <= on->ogmMetric_next)) {
                dbgf_all(DBGT_WARN, "dropping already scheduled sqn=%d via neigh=%s from orig=%s", ogm_sqn, pb->i.llip_str, on->id.name);
                return SUCCESS;
        }

        struct local_node *local = pb->i.lndev->key.link->local;
        struct router_node *next_rt = NULL;
        struct router_node *prev_rt = on->curr_rt_local;
        IDM_T is_ogm_sqn_new = UXX_GT(OGM_SQN_MASK, ogm_sqn, on->ogmSqn_maxRcvd);
        struct link_dev_node *best_rt_lndev = NULL;
        UMETRIC_T best_rt_metric = lndev_best_via_router(local, on, ogm_metric, &best_rt_lndev);
        struct router_node *rt = NULL;

        if (is_ogm_sqn_new || (prev_rt && prev_rt->local_key == local && prev_rt->mr.umetric > best_rt_metric)) {

                struct router_node *rt_tmp;
                struct avl_node *rt_an;

                for (rt_an = NULL; (rt_tmp = avl_iterate_item(&on->rt_tree, &rt_an));) {

                        if (is_ogm_sqn_new)
                                update_metric_record(on, rt_tmp, ogm_sqn_max, NULL);

                        if (rt_tmp->local_key == local)
                                rt = rt_tmp;

                        if (!next_rt || next_rt->mr.umetric < rt_tmp->mr.umetric)
                                next_rt = rt_tmp;
                }

        } else {
                rt = avl_find_item(&on->rt_tree, &local);
        }

        on->ogmSqn_maxRcvd = ogm_sqn_max;

        if (rt) {
                if (UXX_LT(OGM_SQN_MASK, ogm_sqn, rt->ogm_sqn_last) ||
                        (ogm_sqn == rt->ogm_sqn_last &&
                        (*ogm_metric <= rt->ogm_umetric_last || best_rt_metric <= rt->path_metric_best))) {
                        dbgf_track(DBGT_WARN, "dropping already rcvd sqn=%d via neigh=%s from orig=%s", ogm_sqn, pb->i.llip_str, on->id.name);
                        return SUCCESS;
                }

        } else if (!on->curr_rt_local || (((on->curr_rt_local->mr.umetric * new_rt_dismissal_div100) / 100) <= best_rt_metric)) {

                rt = router_node_create(local, on, ogm_sqn_max);

                dbg_track(DBGT_INFO, "new router via %s to %s metric=%ju (curr_rt=%s metric=%ju total %d)",
                        ipXAsStr(af_cfg, &best_rt_lndev->key.link->link_ip), on->id.name, best_rt_metric,
                        on->curr_rt_lndev ? ipXAsStr(af_cfg, &on->curr_rt_lndev->key.link->link_ip) : "---",
                        on->curr_rt_lndev ? on->curr_rt_local->mr.umetric : 0, on->rt_tree.items);

        }

        if (rt) {
                update_metric_record(on, rt, ogm_sqn, &best_rt_metric);
                rt->ogm_sqn_last = ogm_sqn;
                rt->ogm_umetric_last = *ogm_metric;
                rt->path_metric_best = best_rt_metric;
                rt->path_lndev_best = best_rt_lndev;

                if (!next_rt || next_rt->mr.umetric < rt->mr.umetric)
                        next_rt = rt;
        }

        if (!next_rt || (on->curr_rt_local && next_rt->mr.umetric <= on->curr_rt_local->mr.umetric))
                next_rt = on->curr_rt_local;

        assertion(-501136, (next_rt));

        if ((((OGM_SQN_MASK) & (next_rt->mr.set - on->ogmSqn_rangeMin)) < on->ogmSqn_rangeSize) && //after description update all mr.set are invalid
                (UXX_GT(OGM_SQN_MASK, next_rt->mr.set, on->ogmSqn_next) ||
                (next_rt->mr.set == on->ogmSqn_next && next_rt->mr.umetric > on->ogmMetric_next))) {

                if (next_rt->mr.umetric >= on->path_metricalgo->umetric_min) {

                        if (next_rt->mr.set == on->ogmSqn_next)
                                set_ogmSqn_toBeSend_and_aggregated(on, 0, ((OGM_SQN_T) (on->ogmSqn_next - 1)), ((OGM_SQN_T) (on->ogmSqn_next - 1)));

                        set_ogmSqn_toBeSend_and_aggregated(on, next_rt->mr.umetric, next_rt->mr.set, on->ogmSqn_send);

                        assertion(-501139, ((((OGM_SQN_MASK) & (on->ogmSqn_next - on->ogmSqn_rangeMin)) < on->ogmSqn_rangeSize)));

                        if (next_rt != on->curr_rt_local || on->curr_rt_local->path_lndev_best != on->curr_rt_lndev ) {

                                dbg_track(DBGT_INFO, "changed route to %s %s via %s %s metric=%s   (prev %s %s metric=%s sqn_max=%d sqn_in=%d)",
                                        on->id.name, on->primary_ip_str, ipXAsStr(af_cfg,
                                        &next_rt->path_lndev_best->key.link->link_ip),
                                        next_rt->path_lndev_best->key.dev->label_cfg.str,
                                        umetric_to_human(next_rt->mr.umetric),
                                        ipXAsStr(af_cfg, on->curr_rt_lndev ? &on->curr_rt_lndev->key.link->link_ip : &ZERO_IP),
                                        on->curr_rt_lndev ? on->curr_rt_lndev->key.dev->label_cfg.str : "---",
                                        umetric_to_human(on->curr_rt_local ? on->curr_rt_local->mr.umetric : 0),
                                        ogm_sqn_max, ogm_sqn);

                                if (on->curr_rt_local)
                                        cb_route_change_hooks(DEL, on);

                                on->curr_rt_local = next_rt;
                                on->curr_rt_lndev = next_rt->path_lndev_best;

                                cb_route_change_hooks(ADD, on);
                        }

                } else {

                        if (on->curr_rt_local)
                                cb_route_change_hooks(DEL, on);

                        on->curr_rt_local = NULL;
                        on->curr_rt_lndev = NULL;
                }
        }

        return SUCCESS;
}











STATIC_FUNC
IDM_T validate_metricalgo(struct host_metricalgo *ma, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        if (
                validate_param((ma->algo_type), MIN_METRIC_ALGO, MAX_METRIC_ALGO, ARG_PATH_METRIC_ALGO) ||
                validate_param((ma->algo_rp_exp_numerator), MIN_PATH_XP_EXP_NUMERATOR, MAX_PATH_XP_EXP_NUMERATOR, ARG_PATH_RP_EXP_NUMERATOR) ||
                validate_param((ma->algo_rp_exp_divisor), MIN_PATH_XP_EXP_DIVISOR, MAX_PATH_XP_EXP_DIVISOR, ARG_PATH_RP_EXP_DIVISOR) ||
                validate_param((ma->algo_tp_exp_numerator), MIN_PATH_XP_EXP_NUMERATOR, MAX_PATH_XP_EXP_NUMERATOR, ARG_PATH_TP_EXP_NUMERATOR) ||
                validate_param((ma->algo_tp_exp_divisor), MIN_PATH_XP_EXP_DIVISOR, MAX_PATH_XP_EXP_DIVISOR, ARG_PATH_TP_EXP_DIVISOR) ||
                validate_param((ma->flags),      MIN_METRIC_FLAGS, MAX_METRIC_FLAGS, ARG_PATH_METRIC_FLAGS) ||
                validate_param((ma->window_size), MIN_PATH_WINDOW, MAX_PATH_WINDOW, ARG_PATH_WINDOW) ||
                validate_param((ma->lounge_size), MIN_PATH_LOUNGE, MAX_PATH_LOUNGE, ARG_PATH_LOUNGE) ||
                validate_param((ma->regression), MIN_PATH_REGRESSION_SLOW, MAX_PATH_REGRESSION_SLOW, ARG_PATH_REGRESSION_SLOW) ||
                validate_param((ma->hystere), MIN_PATH_HYST, MAX_PATH_HYST, ARG_PATH_HYST) ||
                validate_param((ma->hop_penalty), MIN_HOP_PENALTY, MAX_HOP_PENALTY, ARG_HOP_PENALTY) ||
                validate_param((ma->late_penalty), MIN_LATE_PENAL, MAX_LATE_PENAL, ARG_LATE_PENAL) ||

                !is_umetric_valid(&ma->umetric_min) || !is_fmetric_valid(ma->fmetric_u16_min) ||
                ma->umetric_min != fmetric_to_umetric(ma->fmetric_u16_min) || ma->umetric_min < UMETRIC_MIN__NOT_ROUTABLE ||

                0) {

                EXITERROR(-500755, (0));

                return FAILURE;
        }


        return SUCCESS;
}


STATIC_FUNC
IDM_T metricalgo_tlv_to_host(struct description_tlv_metricalgo *tlv_algo, struct host_metricalgo *host_algo, uint16_t size)
{
        TRACE_FUNCTION_CALL;
        memset(host_algo, 0, sizeof (struct host_metricalgo));

        if (size < sizeof (struct mandatory_tlv_metricalgo))
                return FAILURE;

        host_algo->fmetric_u16_min.val.u16 = ntohs(tlv_algo->m.fmetric_u16_min.val.u16);
        host_algo->umetric_min = fmetric_to_umetric(host_algo->fmetric_u16_min);
	host_algo->algo_type = ntohs(tlv_algo->m.algo_type);
        host_algo->flags = ntohs(tlv_algo->m.flags);
        host_algo->algo_rp_exp_numerator = tlv_algo->m.rp_exp_numerator;
        host_algo->algo_rp_exp_divisor = tlv_algo->m.rp_exp_divisor;
        host_algo->algo_tp_exp_numerator = tlv_algo->m.tp_exp_numerator;
        host_algo->algo_tp_exp_divisor = tlv_algo->m.tp_exp_divisor;
        host_algo->window_size = tlv_algo->m.path_window_size;
        host_algo->lounge_size = tlv_algo->m.path_lounge_size;
        host_algo->regression = tlv_algo->m.regression;
        host_algo->hystere = tlv_algo->m.hystere;
	host_algo->hop_penalty = tlv_algo->m.hop_penalty;
	host_algo->late_penalty = tlv_algo->m.late_penalty;

        if (validate_metricalgo(host_algo, NULL) == FAILURE)
                return FAILURE;

/*

        host_algo->umetric_min = MAX(
                umetric(host_algo->fmetric_min.val.fu16_mantissa, host_algo->fmetric_min.val.fu16_exp),
                umetric(FMETRIC_MANTISSA_ROUTABLE, 0));
*/

        return SUCCESS;
}


STATIC_FUNC
int create_description_tlv_metricalgo(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        struct description_tlv_metricalgo tlv_algo;

        dbgf_track(DBGT_INFO, " size %zu", sizeof (struct description_tlv_metricalgo));

        memset(&tlv_algo, 0, sizeof (struct description_tlv_metricalgo));

        tlv_algo.m.fmetric_u16_min = umetric_to_fmetric(my_path_umetric_min);

        tlv_algo.m.fmetric_u16_min.val.u16 = htons(tlv_algo.m.fmetric_u16_min.val.u16);
        tlv_algo.m.algo_type = htons(my_path_algo); //METRIC_ALGO
        tlv_algo.m.flags = htons(my_path_metric_flags);
        tlv_algo.m.rp_exp_numerator = my_path_rp_exp_numerator;
        tlv_algo.m.rp_exp_divisor = my_path_rp_exp_divisor;
        tlv_algo.m.tp_exp_numerator = my_path_tp_exp_numerator;
        tlv_algo.m.tp_exp_divisor = my_path_tp_exp_divisor;
        tlv_algo.m.path_window_size = my_path_window;
        tlv_algo.m.path_lounge_size = my_path_lounge;
        tlv_algo.m.regression = my_path_regression;
        tlv_algo.m.hystere = my_path_hystere;
        tlv_algo.m.hop_penalty = my_hop_penalty;
        tlv_algo.m.late_penalty = my_late_penalty;

        if (self.path_metricalgo)
                debugFree(self.path_metricalgo, -300282);

        self.path_metricalgo = debugMalloc(sizeof ( struct host_metricalgo), -300283);


        if (metricalgo_tlv_to_host(&tlv_algo, self.path_metricalgo, sizeof (struct description_tlv_metricalgo)) == FAILURE)
                cleanup_all(-500844);

        if (tx_iterator_cache_data_space(it) < ((int) sizeof (struct description_tlv_metricalgo))) {

                dbgf_sys(DBGT_ERR, "unable to announce metric due to limiting --%s", ARG_UDPD_SIZE);
                return TLV_TX_DATA_FAILURE;
        }

        memcpy(((struct description_tlv_metricalgo *) tx_iterator_cache_msg_ptr(it)), &tlv_algo,
                sizeof (struct description_tlv_metricalgo));

        return sizeof (struct description_tlv_metricalgo);
}


STATIC_FUNC
void dbg_metrics_status(int32_t cb_id, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        dbg_printf(cn, "%s=%d %s=%d\n",
                ARG_HELLO_SQN_WINDOW, my_link_window, ARG_NEW_RT_DISMISSAL, new_rt_dismissal_div100);

        process_description_tlvs(NULL, &self, self.desc, TLV_OP_DEBUG, BMX_DSC_TLV_METRIC, cn);

}

STATIC_FUNC
void dbg_metricalgo(struct ctrl_node *cn, struct host_metricalgo *host_algo)
{
        TRACE_FUNCTION_CALL;

        dbg_printf(cn, "%s=%ju %s=%d %s=0x%X %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d %s=%d\n",
                ARG_PATH_UMETRIC_MIN, host_algo->umetric_min,
                ARG_PATH_METRIC_ALGO, host_algo->algo_type,
                ARG_PATH_METRIC_FLAGS, host_algo->flags,
                ARG_PATH_RP_EXP_NUMERATOR, host_algo->algo_rp_exp_numerator,
                ARG_PATH_RP_EXP_DIVISOR, host_algo->algo_rp_exp_divisor,
                ARG_PATH_TP_EXP_NUMERATOR, host_algo->algo_tp_exp_numerator,
                ARG_PATH_TP_EXP_DIVISOR, host_algo->algo_tp_exp_divisor,
                ARG_PATH_REGRESSION_SLOW, host_algo->regression,
                ARG_PATH_LOUNGE, host_algo->lounge_size,
                ARG_PATH_WINDOW, host_algo->window_size,
                ARG_PATH_HYST, host_algo->hystere,
                ARG_HOP_PENALTY, host_algo->hop_penalty,
                ARG_LATE_PENAL, host_algo->late_penalty);
}

STATIC_FUNC
int process_description_tlv_metricalgo(struct rx_frame_iterator *it )
{
        TRACE_FUNCTION_CALL;
        assertion(-500683, (it->frame_type == BMX_DSC_TLV_METRIC));
        assertion(-500684, (it->on));

        struct orig_node *on = it->on;
        IDM_T op = it->op;

        struct description_tlv_metricalgo *tlv_algo = (struct description_tlv_metricalgo *) (it->frame_data);
        struct host_metricalgo host_algo;

        dbgf_all( DBGT_INFO, "%s ", tlv_op_str(op));

        if (op == TLV_OP_DEL) {

                if (on->path_metricalgo) {
                        debugFree(on->path_metricalgo, -300285);
                        on->path_metricalgo = NULL;
                }

                if (on->metricSqnMaxArr) {
                        debugFree(on->metricSqnMaxArr, -300307);
                        on->metricSqnMaxArr = NULL;
                }


        } else if (!(op == TLV_OP_TEST || op == TLV_OP_ADD || op == TLV_OP_DEBUG)) {

                return it->frame_msgs_length;
        }

        if (metricalgo_tlv_to_host(tlv_algo, &host_algo, it->frame_msgs_length) == FAILURE)
                return FAILURE;


        if (op == TLV_OP_ADD) {

                assertion(-500684, (!on->path_metricalgo));

                on->path_metricalgo = debugMalloc(sizeof (struct host_metricalgo), -300286);

                memcpy(on->path_metricalgo, &host_algo, sizeof (struct host_metricalgo));

                on->metricSqnMaxArr = debugMalloc(((on->path_metricalgo->lounge_size + 1) * sizeof (UMETRIC_T)), -300308);
                memset(on->metricSqnMaxArr, 0, ((on->path_metricalgo->lounge_size + 1) * sizeof (UMETRIC_T)));

                // migrate current router_nodes->mr.clr position to new sqn_range:
                struct router_node *rn;
                struct avl_node *an;

                for (an = NULL; (rn = avl_iterate_item(&on->rt_tree, &an));) {

                        reconfigure_metric_record_position(&rn->mr, on->path_metricalgo, on->ogmSqn_rangeMin, on->ogmSqn_rangeMin, 0, NO);

/*
                        OGM_SQN_T in = ((OGM_SQN_MASK)&(on->ogmSqn_rangeMin + on->path_metricalgo->lounge_size));
                        reconfigure_metric_record(&rn->mr, on->path_metricalgo, on->ogmSqn_rangeMin, in, 0, NO);
*/

                }


        } else if (op == TLV_OP_DEBUG) {

                dbg_metricalgo(it->cn, &host_algo);

        }

        return it->frame_msgs_length;
}







STATIC_FUNC
int32_t opt_link_metric(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;
        static int32_t my_link_window_prev = DEF_HELLO_SQN_WINDOW;

        if (cmd == OPT_APPLY && !strcmp(opt->long_name, ARG_HELLO_SQN_WINDOW)) {

                struct link_dev_node *lndev;
                struct avl_node *an;

                for (an = NULL; (lndev = avl_iterate_item(&link_dev_tree, &an));) {

                        struct link_probe_record *lpr = &lndev->rx_probe_record;

                        if (my_link_window < my_link_window_prev) {

                                HELLO_SQN_T prev_sqn_min = (HELLO_SQN_MASK)&(lpr->sqn_max + 1 - my_link_window_prev);
                                HELLO_SQN_T new_sqn_min_minus_one = (HELLO_SQN_MASK)&(lpr->sqn_max - my_link_window);

                                lpr->probe_sum -= bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, prev_sqn_min, new_sqn_min_minus_one);
                                bits_clear(lpr->probe_array, MAX_HELLO_SQN_WINDOW, prev_sqn_min, new_sqn_min_minus_one);
                        }

                        assertion(-501053, (bits_get(lpr->probe_array, MAX_HELLO_SQN_WINDOW, 0, MAX_HELLO_SQN_WINDOW - 1) == lpr->probe_sum));
                        assertion(-501061, (lpr->probe_sum <= ((uint32_t)my_link_window)));

                        lpr->umetric = (UMETRIC_MAX / my_link_window) * lpr->probe_sum;
                }


                lndev_assign_best(NULL, NULL);


                my_link_window_prev = my_link_window;
        }

        return SUCCESS;
}



STATIC_FUNC
int32_t opt_path_metricalgo(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        if (cmd == OPT_REGISTER || cmd == OPT_CHECK || cmd == OPT_APPLY) {

                struct host_metricalgo test_algo;
                memset(&test_algo, 0, sizeof (struct host_metricalgo));

                // only options with a non-zero MIN value and those with illegal compinations must be tested
                // other illegal option configurations will be cached by their MIN_... MAX_.. control.c architecture

                test_algo.window_size = (cmd == OPT_REGISTER || strcmp(opt->long_name, ARG_PATH_WINDOW)) ?
                        my_path_window : strtol(patch->p_val, NULL, 10);

                test_algo.regression = (cmd == OPT_REGISTER || strcmp(opt->long_name, ARG_PATH_REGRESSION_SLOW)) ?
                        my_path_regression : strtol(patch->p_val, NULL, 10);

                test_algo.umetric_min = (cmd == OPT_REGISTER || strcmp(opt->long_name, ARG_PATH_UMETRIC_MIN)) ?
                        my_path_umetric_min : strtol(patch->p_val, NULL, 10);

                test_algo.fmetric_u16_min = umetric_to_fmetric(test_algo.umetric_min);


                if (cmd == OPT_REGISTER || strcmp(opt->long_name, ARG_PATH_METRIC_ALGO)) {

                        test_algo.algo_type = my_path_algo;
                        test_algo.algo_rp_exp_numerator = my_path_rp_exp_numerator;
                        test_algo.algo_rp_exp_divisor = my_path_rp_exp_divisor;
                        test_algo.algo_tp_exp_numerator = my_path_tp_exp_numerator;
                        test_algo.algo_tp_exp_divisor = my_path_tp_exp_divisor;

                } else {

                        test_algo.algo_type = DEF_METRIC_ALGO;
                        test_algo.algo_rp_exp_numerator = DEF_PATH_RP_EXP_NUMERATOR;
                        test_algo.algo_rp_exp_divisor = DEF_PATH_RP_EXP_DIVISOR;
                        test_algo.algo_tp_exp_numerator = DEF_PATH_TP_EXP_NUMERATOR;
                        test_algo.algo_tp_exp_divisor = DEF_PATH_TP_EXP_DIVISOR;

                        if (patch->p_diff != DEL) {

                                test_algo.algo_type = strtol(patch->p_val, NULL, 10);

                                struct opt_child *c = NULL;
                                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                                        if (!c->c_val)
                                                continue;

                                        int32_t val = strtol(c->c_val, NULL, 10);

                                        if (!strcmp(c->c_opt->long_name, ARG_PATH_RP_EXP_NUMERATOR))
                                                test_algo.algo_rp_exp_numerator = val;

                                        if (!strcmp(c->c_opt->long_name, ARG_PATH_RP_EXP_DIVISOR))
                                                test_algo.algo_rp_exp_divisor = val;

                                        if (!strcmp(c->c_opt->long_name, ARG_PATH_TP_EXP_NUMERATOR))
                                                test_algo.algo_tp_exp_numerator = val;

                                        if (!strcmp(c->c_opt->long_name, ARG_PATH_TP_EXP_DIVISOR))
                                                test_algo.algo_tp_exp_divisor = val;
                                }
                        }
                }

                if (validate_metricalgo(&test_algo, cn) == FAILURE)
                        return FAILURE;

                if (cmd == OPT_APPLY) {
                        my_path_window = test_algo.window_size;
                        my_path_regression = test_algo.regression;
                        my_path_umetric_min = test_algo.umetric_min;

                        my_path_algo = test_algo.algo_type;
                        my_path_rp_exp_numerator = test_algo.algo_rp_exp_numerator;
                        my_path_rp_exp_divisor = test_algo.algo_rp_exp_divisor;
                        my_path_tp_exp_numerator = test_algo.algo_tp_exp_numerator;
                        my_path_tp_exp_divisor = test_algo.algo_tp_exp_divisor;

                        my_description_changed = YES;
                }
        }


	return SUCCESS;
}


STATIC_FUNC
struct opt_type metrics_options[]=
{
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

	{ODI, 0,0,                         0,  0,0,0,0,0,0,                          0,                 0,                  0,                 0,                   0,
			0,		"\nMetric options:"}
,
#ifdef WITH_UNUSED
	{ODI, 0, ARG_PATH_HYST,   	   0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_path_hystere,MIN_PATH_HYST,	MAX_PATH_HYST,	DEF_PATH_HYST,	opt_path_metricalgo,
			ARG_VALUE_FORM,	"use hysteresis to delay route switching to alternative next-hop neighbors with better path metric"}
        ,
        // there SHOULD! be a minimal lateness_penalty >= 1 ! Otherwise a shorter path with equal path-cost than a longer path will never dominate
	{ODI, 0, ARG_LATE_PENAL,  	   0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_late_penalty,MIN_LATE_PENAL,MAX_LATE_PENAL, DEF_LATE_PENAL, opt_path_metricalgo,
			ARG_VALUE_FORM,	"penalize non-first rcvd OGMs "}
        ,

#endif
#ifndef LESS_OPTIONS
        {ODI, 0, ARG_PATH_METRIC_ALGO, CHR_PATH_METRIC_ALGO,  5, A_PMN, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_algo,MIN_METRIC_ALGO,    MAX_METRIC_ALGO,    DEF_METRIC_ALGO,    opt_path_metricalgo,
                ARG_VALUE_FORM, HELP_PATH_METRIC_ALGO}
        ,
        {ODI, ARG_PATH_METRIC_ALGO, ARG_PATH_RP_EXP_NUMERATOR, CHR_PATH_RP_EXP_NUMERATOR, 5, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_rp_exp_numerator, MIN_PATH_XP_EXP_NUMERATOR, MAX_PATH_XP_EXP_NUMERATOR, DEF_PATH_RP_EXP_NUMERATOR, opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, ARG_PATH_METRIC_ALGO, ARG_PATH_RP_EXP_DIVISOR, CHR_PATH_RP_EXP_DIVISOR, 5, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_rp_exp_divisor, MIN_PATH_XP_EXP_DIVISOR, MAX_PATH_XP_EXP_DIVISOR, DEF_PATH_RP_EXP_DIVISOR, opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, ARG_PATH_METRIC_ALGO, ARG_PATH_TP_EXP_NUMERATOR, CHR_PATH_TP_EXP_NUMERATOR, 5, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_tp_exp_numerator, MIN_PATH_XP_EXP_NUMERATOR, MAX_PATH_XP_EXP_NUMERATOR, DEF_PATH_TP_EXP_NUMERATOR, opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, ARG_PATH_METRIC_ALGO, ARG_PATH_TP_EXP_DIVISOR, CHR_PATH_TP_EXP_DIVISOR, 5, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_tp_exp_divisor, MIN_PATH_XP_EXP_DIVISOR, MAX_PATH_XP_EXP_DIVISOR, DEF_PATH_TP_EXP_DIVISOR, opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, 0, ARG_PATH_UMETRIC_MIN, 0,  5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_umetric_min,MIN_PATH_UMETRIC_MIN,MAX_PATH_UMETRIC_MIN,DEF_PATH_UMETRIC_MIN,    opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, 0, ARG_PATH_WINDOW, 0, 5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_window, MIN_PATH_WINDOW, MAX_PATH_WINDOW, DEF_PATH_WINDOW, opt_path_metricalgo,
			ARG_VALUE_FORM,	"set path window size (PWS) for end2end path-quality calculation (path metric)"}
        ,
#endif
	{ODI, 0, ARG_PATH_LOUNGE,          0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_path_lounge, MIN_PATH_LOUNGE,MAX_PATH_LOUNGE,DEF_PATH_LOUNGE, opt_path_metricalgo,
			ARG_VALUE_FORM, "set default PLS buffer size to artificially delay my OGM processing for ordered path-quality calulation"}
        ,
	{ODI, 0, ARG_PATH_REGRESSION_SLOW, 0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_path_regression,MIN_PATH_REGRESSION_SLOW,MAX_PATH_REGRESSION_SLOW,DEF_PATH_REGRESSION_SLOW,opt_path_metricalgo,
			ARG_VALUE_FORM,	"set (slow) path regression "}
        ,
	{ODI, 0, ARG_HOP_PENALTY,	   0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_hop_penalty, MIN_HOP_PENALTY, MAX_HOP_PENALTY, DEF_HOP_PENALTY, opt_path_metricalgo,
			ARG_VALUE_FORM,	"penalize non-first rcvd OGMs in 1/255 (each hop will substract metric*(VALUE/255) from current path-metric)"}
        ,
        {ODI,0,ARG_HELLO_SQN_WINDOW,       0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_link_window,	MIN_HELLO_SQN_WINDOW, 	MAX_HELLO_SQN_WINDOW,DEF_HELLO_SQN_WINDOW,    opt_link_metric,
			ARG_VALUE_FORM,	"set link window size (LWS) for link-quality calculation (link metric)"}
        ,
        {ODI, 0, ARG_NEW_RT_DISMISSAL,     0, 5, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &new_rt_dismissal_div100, MIN_NEW_RT_DISMISSAL, MAX_NEW_RT_DISMISSAL, DEF_NEW_RT_DISMISSAL, 0,
			ARG_VALUE_FORM,	HLP_NEW_RT_DISMISSAL}

};



STATIC_FUNC
int32_t init_metrics( void )
{
        UMETRIC_MAX_SQRT = umetric_fast_sqrt(UMETRIC_MAX);
        U64_MAX_HALF_SQRT = umetric_fast_sqrt(U64_MAX_HALF);

#ifndef NO_ASSERTIONS
        dbgf_all(DBGT_INFO, "um_fm8_min=%ju um_max=%ju um_mask=%ju um_shift_max=%zu um_multiply_max=%ju um_max_sqrt=%ju u32_max=%u u64_max=%ju u64_max_half_sqrt=%ju ",
                UMETRIC_FM8_MIN, UMETRIC_MAX, UMETRIC_MASK, UMETRIC_SHIFT_MAX, UMETRIC_MULTIPLY_MAX, UMETRIC_MAX_SQRT, U32_MAX, U64_MAX, U64_MAX_HALF_SQRT);

        FMETRIC_U16_T a = {.val.f= {.mantissa_fm16 = 5, .exp_fm16 = 2}}, b = {.val.f = {.mantissa_fm16 = 2, .exp_fm16 = 5}};
        assertion(-500930, (a.val.u16 < b.val.u16));

        FMETRIC_U8_T a8 = {.val.f = {.mantissa_fmu8 = 5, .exp_fmu8 = 2}}, b8 = {.val.f = {.mantissa_fmu8 = 2, .exp_fmu8 = 5}};
        assertion(-500931, (a8.val.u8 < b8.val.u8));

        assertion(-501021, ((UMETRIC_MAX << UMETRIC_SHIFT_MAX) >> UMETRIC_SHIFT_MAX == UMETRIC_MAX));
        assertion(-501022, ((UMETRIC_MASK << UMETRIC_SHIFT_MAX) >> UMETRIC_SHIFT_MAX == UMETRIC_MASK));

        assertion(-501078, (((UMETRIC_T) (UMETRIC_MAX * UMETRIC_MAX)) / UMETRIC_MAX != UMETRIC_MAX));    // verify overflow!
        assertion(-501079, (((UMETRIC_T) (UMETRIC_MAX * UMETRIC_MAX_SQRT)) / UMETRIC_MAX == UMETRIC_MAX_SQRT)); //verify: NO overflow
        assertion(-501080, (((UMETRIC_T) (UMETRIC_MAX * UMETRIC_MULTIPLY_MAX)) / UMETRIC_MAX == UMETRIC_MULTIPLY_MAX)); //verify: NO overflow

        // is this fast-inverse-sqrt hack working on this plattform and are constants correct?:

        assertion(-501082, ((MAX(UMETRIC_MAX_SQRT_SQUARE, UMETRIC_MAX) - MIN(UMETRIC_MAX_SQRT_SQUARE, UMETRIC_MAX))     < (UMETRIC_MAX    / 300000))); // validate precision
        assertion(-501083, ((MAX(U64_MAX_HALF_SQRT_SQUARE, U64_MAX_HALF) - MIN(U64_MAX_HALF_SQRT_SQUARE, U64_MAX_HALF)) < ((U64_MAX_HALF) / 3000000))); // validate precision
#endif

#ifdef  TEST_UMETRIC_TO_FMETRIC

        UMETRIC_T val;
        uint32_t c=0;
        uint16_t steps = 8;

        
        uint32_t err_sqrt_sum_square = 0;
        uint32_t err_sqrt_sum = 0;
        int32_t err_sqrt_min = 10000;
        int32_t err_sqrt_max = 0;
        uint32_t err_sum_square = 0;
        uint32_t err_sum = 0;
        int32_t err_min = 10000;
        int32_t err_max = 0;

        for (val = UMETRIC_MAX; val <= UMETRIC_MAX; val += MAX(1, val >> steps)) {

                c++;

                UMETRIC_T usqrt = umetric_fast_sqrt(val);
                int32_t failure_sqrt = -((int32_t) ((val *10000) / (val ? val : 1))) + ((int32_t) (((usqrt*usqrt) *10000) / (val ? val : 1)));
                failure_sqrt = MAX((-failure_sqrt), failure_sqrt);
                err_sqrt_min = MIN(err_sqrt_min, failure_sqrt);
                err_sqrt_max = MAX(err_sqrt_max, failure_sqrt);
                err_sqrt_sum_square += (failure_sqrt * failure_sqrt);
                err_sqrt_sum += failure_sqrt;

/*
                dbgf_sys(DBGT_INFO, "val: %12s %-12ju square(usqrt)=%-12ju diff=%7ld usqrt=%-12ju failure=%5d/10000",
                        umetric_to_human(val), val, (usqrt * usqrt), (((int64_t)val) - ((int64_t)(usqrt * usqrt))), usqrt, failure_sqrt);
*/


/*
                FMETRIC_U16_T fm = umetric_to_fmetric(val);
                UMETRIC_T reverse = fmetric_to_umetric(fm);
                int32_t failure = -((int32_t) ((val *10000) / (val ? val : 1))) + ((int32_t) ((reverse *10000) / (val ? val : 1)));
                failure = MAX(-failure, failure);
                err_min = MIN(err_min, failure);
                err_max = MAX(err_max, failure);
                err_sum_square += (failure * failure);
                err_sum += failure;
                dbgf_sys(DBGT_INFO, "val: %12s %-12ju reverse=%-12ju failure=%5d/10000 exp=%d mantissa=%d",
                        umetric_to_human(val), val, reverse, failure, fm.val.fu16_exp, fm.val.fu16_mantissa);
*/
        }
        dbgf_all(DBGT_INFO, "counts=%d steps=%d err_square=%d err=%d err_min=%d err_max=%d",
                 c, steps, err_sqrt_sum_square / c, err_sqrt_sum / c, err_sqrt_min, err_sqrt_max);

        dbgf_all(DBGT_INFO, "add=%d counts=%d steps=%d err_square=%d err=%d err_min=%d err_max=%d",
                UMETRIC_TO_FMETRIC_INPUT_FIX, c, steps, err_sum_square / c, err_sum / c, err_min, err_max);
#endif

        struct frame_handl metric_handl;
        memset( &metric_handl, 0, sizeof(metric_handl));
        metric_handl.fixed_msg_size = 0;
        metric_handl.is_relevant = 1;
        metric_handl.min_msg_size = sizeof (struct mandatory_tlv_metricalgo);
        metric_handl.name = "desc_tlv_metric0";
        metric_handl.tx_frame_handler = create_description_tlv_metricalgo;
        metric_handl.rx_frame_handler = process_description_tlv_metricalgo;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_METRIC, &metric_handl);

        
        register_path_metricalgo(BIT_METRIC_ALGO_MP, path_metricalgo_MultiplyQuality);
        register_path_metricalgo(BIT_METRIC_ALGO_EP, path_metricalgo_ExpectedQuality);
        register_path_metricalgo(BIT_METRIC_ALGO_MB, path_metricalgo_MultiplyBandwidth);
        register_path_metricalgo(BIT_METRIC_ALGO_EB, path_metricalgo_ExpectedBandwidth);
        register_path_metricalgo(BIT_METRIC_ALGO_VB, path_metricalgo_VectorBandwidth);

        register_options_array(metrics_options, sizeof (metrics_options));

        return SUCCESS;
}

STATIC_FUNC
void cleanup_metrics( void )
{
        if (self.path_metricalgo) {
                debugFree(self.path_metricalgo, -300281);
                self.path_metricalgo = NULL;
        }
}





struct plugin *metrics_get_plugin( void ) {

	static struct plugin metrics_plugin;
	memset( &metrics_plugin, 0, sizeof ( struct plugin ) );

	metrics_plugin.plugin_name = "bmx6_metric_plugin";
	metrics_plugin.plugin_size = sizeof ( struct plugin );
        metrics_plugin.plugin_code_version = CODE_VERSION;
        metrics_plugin.cb_init = init_metrics;
	metrics_plugin.cb_cleanup = cleanup_metrics;
        metrics_plugin.cb_plugin_handler[PLUGIN_CB_STATUS] = (void (*) (int32_t, void*)) dbg_metrics_status;

        return &metrics_plugin;
}
