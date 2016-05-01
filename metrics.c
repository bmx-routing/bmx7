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


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "sec.h"
#include "metrics.h"
#include "ogm.h"
#include "msg.h"
#include "content.h"
#include "ip.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "allocate.h"

#define CODE_CATEGORY_NAME "metric"


static int32_t descMetricalgo = DEF_DESC_METRICALGO;

static int32_t my_ogm_path_algo = DEF_METRIC_ALGO;
static int32_t my_path_rp_exp_numerator = DEF_PATH_RP_EXP_NUMERATOR;
static int32_t my_path_rp_exp_divisor = DEF_PATH_RP_EXP_DIVISOR;
static int32_t my_path_tp_exp_numerator = DEF_PATH_TP_EXP_NUMERATOR;
static int32_t my_path_tp_exp_divisor = DEF_PATH_TP_EXP_DIVISOR;

static int32_t my_path_lq_tx_r255 = DEF_PATH_LQ_TX_R255;
static int32_t my_path_lq_ty_r255 = DEF_PATH_LQ_TY_R255;
static int32_t my_path_lq_t1_r255 = DEF_PATH_LQ_T1_R255;
static int32_t my_ogm_link_rate_efficiency = DEF_OGM_LINK_RATE_EFFICIENCY;
static int32_t my_path_metric_flags = DEF_PATH_METRIC_FLAGS;
static int32_t my_path_umetric_min = DEF_PATH_UMETRIC_MIN;
static int32_t my_ogm_metric_hyst_new_path = DEF_OGM_METRIC_HYST_NEW_PATH;
static int32_t my_ogm_metric_hyst_old_path = DEF_OGM_METRIC_HYST_OLD_PATH;
static int32_t my_ogm_sqn_best_hyst = DEF_OGM_SQN_BEST_HYST;
static int32_t my_ogm_sqn_late_hyst_100ms = DEF_OGM_SQN_LATE_HYST;
static int32_t my_ogm_hop_penalty = DEF_OGM_HOP_PENALTY;
static int32_t my_ogm_hops_max = DEF_OGM_HOPS_MAX;
static int32_t my_ogm_hop_hisotry_size = DEF_OGM_HOP_HISTORY_SZ;

static int32_t new_rt_dismissal_div100 = DEF_NEW_RT_DISMISSAL;

struct host_metricalgo my_hostmetricalgo;





static const struct path_interference_parameter DEF_OGM_PATH_INTERFERENCE_PARAMETER[MAX_PATH_IFR_PARAMETERS] = DEF_PATH_IFR_PARAMETER;

struct path_interference_parameter my_path_interference_parameter[MAX_PATH_IFR_PARAMETERS];

//TODO: evaluate my_fmetric_exp_offset based on max configured dev_metric_max:
//static int32_t my_fmetric_exp_offset = DEF_FMETRIC_EXP_OFFSET;
//TODO: reevaluate my_dev_metric_max based on deduced my_fmetric_exp_offset (see above)
//UMETRIC_T my_dev_metric_max = umetric_max(DEF_FMETRIC_EXP_OFFSET);

static
void (*path_metric_algos[BIT_METRIC_ALGO_ARRSZ])
(struct NeighPath *neighPath, struct NeighRef_node *ref, struct host_metricalgo *algo) = {NULL};

static UMETRIC_T UMETRIC_MAX_SQRT;
static UMETRIC_T U64_MAX_HALF_SQRT;
#define U64_MAX_HALF             (U64_MAX>>1)
#define UMETRIC_MAX_SQRT_SQUARE  (UMETRIC_MAX_SQRT * UMETRIC_MAX_SQRT)
#define U64_MAX_HALF_SQRT_SQUARE (U64_MAX_HALF_SQRT * U64_MAX_HALF_SQRT)



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

                LOG2(exp_sum, val, UMETRIC_T);


                fm.val.f.exp_fm16 = (exp_sum - OGM_EXPONENT_OFFSET);
                fm.val.f.mantissa_fm16 = ( (val>>(fm.val.f.exp_fm16)) & OGM_MANTISSA_MASK );

                assertion(-501026, (val > (1<<OGM_EXPONENT_OFFSET)));
		assertion(-502563, ((val >> exp_sum) == 1)); //ensure log2 works fine
                assertion(-501027, (exp_sum >= OGM_EXPONENT_OFFSET));
		assertion(-501028, ((val >> (exp_sum - OGM_MANTISSA_BIT_SIZE)) >= (1 << OGM_EXPONENT_OFFSET)));
		assertion_dbg(-502637, ((val >= fmetric_to_umetric(fm)) && (val < (((65*64)*fmetric_to_umetric(fm))/(64*64)))), "in=%ju outExp=%d outMant=%d outU16=%d check=%ju ! Otherwise OGM metrics may return larger than send",
			val, fm.val.f.exp_fm16, fm.val.f.mantissa_fm16, fm.val.u16, fmetric_to_umetric(fm));
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

        if (val < UMETRIC_MIN__NOT_ROUTABLE) {
                return "-1";
        } else if (val <= UMETRIC_MIN__NOT_ROUTABLE) {
                return "0";
        } else {
                p = ((p + 1) % UMETRIC_TO_HUMAN_ARRAYS);

                if (val < 100000) {
                        sprintf(out[p], "%ju", val);
                } else if (val < 100000000) {
                        sprintf(out[p], "%juK", val/1000);
                } else if (val < 100000000000) {
                        sprintf(out[p], "%juM", val/1000000);
                } else {
                        sprintf(out[p], "%juG", val/1000000000);
                }

                return out[p];
        }
        return NULL;
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

UMETRIC_T fmetric_u8_to_umetric( FMETRIC_U8_T fmu8 ) {
        return fmetric_to_umetric(fmetric_u8_to_fmu16(fmu8));
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

STATIC_FUNC
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
UMETRIC_T apply_lq_threshold_curve(UMETRIC_T lm, struct host_metricalgo *algo)
{
	/*
	UMETRIC_T tx = (algo->lq_tx_point_r255 * UMETRIC_MAX) / 255;
	UMETRIC_T ty = (algo->lq_ty_point_r255 * UMETRIC_MAX) / 255;
	UMETRIC_T t1 = (algo->lq_t1_point_r255 * UMETRIC_MAX) / 255;
	 */
	uint32_t max = 255;
	uint32_t lq = ((lm * ((UMETRIC_T)max))/UMETRIC_MAX);
	uint32_t tx = algo->lq_tx_point_r255;
	uint32_t ty = algo->lq_ty_point_r255;
	uint32_t t1 = algo->lq_t1_point_r255;

	if (lq >= t1) {
		lq = max;
	} else if (lq >= tx && lq < t1) {
//		lq = ty + (((lq-tx)/(t1-tx))*(max-ty));
		lq = ty + (((lq-tx)*(max-ty))/(t1-tx));
	} else {
//		lq = ((lq/tx)*(ty));
		lq = ((lq*ty)/tx);
	}

	return ((((UMETRIC_T)lq) * UMETRIC_MAX)/((UMETRIC_T)max));
}

STATIC_FUNC
void path_metricalgo_MultiplyQuality(struct NeighPath *np, struct NeighRef_node *ref, struct host_metricalgo *algo)
{
	UMETRIC_T tq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_tq_probe)) / LQ_MAX), algo->algo_tp_exp_numerator, algo->algo_tp_exp_divisor);
        UMETRIC_T rq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_rq_probe)) / LQ_MAX), algo->algo_rp_exp_numerator, algo->algo_rp_exp_divisor);
	UMETRIC_T lq = apply_lq_threshold_curve(umetric_multiply_normalized(tq, rq), algo);

        np->um = umetric_multiply_normalized(np->um, lq);
}

STATIC_FUNC
void path_metricalgo_ExpectedQuality(struct NeighPath *np, struct NeighRef_node *ref, struct host_metricalgo *algo)
{
	UMETRIC_T tq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_tq_probe)) / LQ_MAX), algo->algo_tp_exp_numerator, algo->algo_tp_exp_divisor);
        UMETRIC_T rq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_rq_probe)) / LQ_MAX), algo->algo_rp_exp_numerator, algo->algo_rp_exp_divisor);
	UMETRIC_T lq = apply_lq_threshold_curve(umetric_multiply_normalized(tq, rq), algo);

        if (np->um < 2 || lq < 2)
                np->um = UMETRIC_MIN__NOT_ROUTABLE;
        else
                np->um = (U64_MAX / ((U64_MAX / np->um) + (U64_MAX / lq)));
}

STATIC_FUNC
void path_metricalgo_MultiplyBandwidth(struct NeighPath *np, struct NeighRef_node *ref, struct host_metricalgo *algo)
{
	UMETRIC_T *lMax = &np->link->k.myDev->umetric_max;
	UMETRIC_T tq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_tq_probe)) / LQ_MAX), algo->algo_tp_exp_numerator, algo->algo_tp_exp_divisor);
        UMETRIC_T rq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_rq_probe)) / LQ_MAX), algo->algo_rp_exp_numerator, algo->algo_rp_exp_divisor);
	UMETRIC_T lq = apply_lq_threshold_curve(umetric_multiply_normalized(tq, rq), algo);

	UMETRIC_T linkBandwidth = ((umetric_multiply_normalized(*lMax, lq)* ((UMETRIC_T) (np->link->k.myDev->linklayer == TYP_DEV_LL_WIFI ? algo->ogm_link_rate_efficiency: 100))) / 100);

        np->um = umetric_multiply_normalized(np->um, linkBandwidth);
}

STATIC_FUNC
void path_metricalgo_ExpectedBandwidth(struct NeighPath *np, struct NeighRef_node *ref, struct host_metricalgo *algo)
{
	UMETRIC_T tq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_tq_probe)) / LQ_MAX), algo->algo_tp_exp_numerator, algo->algo_tp_exp_divisor);
        UMETRIC_T rq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_rq_probe)) / LQ_MAX), algo->algo_rp_exp_numerator, algo->algo_rp_exp_divisor);
	UMETRIC_T lq = apply_lq_threshold_curve(umetric_multiply_normalized(tq, rq), algo);

	UMETRIC_T linkBandwidth = ((umetric_multiply_normalized(np->link->k.myDev->umetric_max, lq)* ((UMETRIC_T) (np->link->k.myDev->linklayer == TYP_DEV_LL_WIFI ? algo->ogm_link_rate_efficiency: 100))) / 100);

        if (np->um < 2 || linkBandwidth < 2)
                np->um = UMETRIC_MIN__NOT_ROUTABLE;
        else
                np->um = (U64_MAX / ((U64_MAX / np->um) + (U64_MAX / linkBandwidth)));
}

STATIC_FUNC
void path_metricalgo_VectorBandwidth(struct NeighPath *np, struct NeighRef_node *ref, struct host_metricalgo *algo)
{
        assertion(-501085, (np->um > UMETRIC_MIN__NOT_ROUTABLE));
        UMETRIC_T linkTP;
	
	if (np->link->wifiStats.txRateAvg) {
		linkTP = ((np->link->wifiStats.txRateAvg * ((UMETRIC_T) (np->link->k.myDev->linklayer == TYP_DEV_LL_WIFI ? algo->ogm_link_rate_efficiency: 100))) / 100);
	} else {
		UMETRIC_T tq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_tq_probe)) / LQ_MAX), algo->algo_tp_exp_numerator, algo->algo_tp_exp_divisor);
		UMETRIC_T rq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_rq_probe)) / LQ_MAX), algo->algo_rp_exp_numerator, algo->algo_rp_exp_divisor);
		UMETRIC_T lq = apply_lq_threshold_curve(umetric_multiply_normalized(tq, rq), algo);
		linkTP = ((umetric_multiply_normalized(np->link->k.myDev->umetric_max, lq)* ((UMETRIC_T) (np->link->k.myDev->linklayer == TYP_DEV_LL_WIFI ? algo->ogm_link_rate_efficiency: 100))) / 100);
	}

        UMETRIC_T inverseSquaredPathBandwidth = 0;
        UMETRIC_T inverseSquaredLinkQuality = 0;
        UMETRIC_T rootOfSum = 0;
        UMETRIC_T path_out = UMETRIC_MIN__NOT_ROUTABLE;

        
        UMETRIC_T maxPrecisionScaler = XMIN(np->um, linkTP) * U64_MAX_HALF_SQRT;


        if (linkTP > UMETRIC_MIN__NOT_ROUTABLE) {

                inverseSquaredPathBandwidth = ((maxPrecisionScaler / np->um) * (maxPrecisionScaler / np->um));
                inverseSquaredLinkQuality = ((maxPrecisionScaler / linkTP) * (maxPrecisionScaler / linkTP));

                rootOfSum = umetric_fast_sqrt(inverseSquaredPathBandwidth + inverseSquaredLinkQuality);
                path_out = maxPrecisionScaler / rootOfSum;
        }

        dbgf_all( DBGT_INFO, "in=%12ju scalar=%19ju invSquaredPath=%19ju linkTP=%19ju invSquaredLink=%12ju rootSum=%ju UMETRIC_MIN=%ju -> path_out=%ju",
		np->um, maxPrecisionScaler, inverseSquaredPathBandwidth, linkTP, inverseSquaredLinkQuality, rootOfSum, UMETRIC_MIN__NOT_ROUTABLE, path_out);
        
       np->um = path_out;
}


struct sub_path_metric {
	uint8_t channel;
	uint8_t hop;
	UMETRIC_T linkTime;
	UMETRIC_T pathTime;
};

STATIC_FUNC
void spmSet( struct sub_path_metric *spmArr, uint8_t channel, uint8_t hopPos, UMETRIC_T *linkTP ) {
	spmArr[hopPos].channel = channel;
	spmArr[hopPos].hop = hopPos;
	spmArr[hopPos].linkTime = (UMETRIC_MAX_MAX / *linkTP);
	spmArr[hopPos].pathTime = 1;
}


STATIC_FUNC
UMETRIC_T subPathArrMaxTime (struct sub_path_metric *a, uint16_t arrSize, struct host_metricalgo *algo)
{
	UMETRIC_T maxPathTime = 1;
	
	uint8_t t,i;

	for (t = 0; t < arrSize; t++) {

		a[t].pathTime = a[t].linkTime;

		if (a[t].channel != TYP_DEV_CHANNEL_EXCLUSIVE) {

			for (i = 0; i < arrSize; i++) {

				if (t != i && a[i].channel != TYP_DEV_CHANNEL_EXCLUSIVE) {

					uint8_t maxIndependence = MIN_PATH_IFR_INDEPENDENCE;

					if (a[t].channel != TYP_DEV_CHANNEL_SHARED && a[i].channel != TYP_DEV_CHANNEL_SHARED ) {

						uint8_t channelDistance = XMAX(a[t].channel, a[i].channel) - XMIN(a[t].channel, a[i].channel);
						uint8_t hopDistance = XMAX(a[t].hop, a[i].hop) - XMIN(a[t].hop, a[i].hop);

						uint8_t p;

						for (p = 0; p < MAX_PATH_IFR_PARAMETERS; p++) {

							struct path_interference_parameter *pip = &algo->pip[p];

							if (pip->channelDistance) {

								if (channelDistance >= pip->channelDistance && hopDistance >= pip->hopDistance)
									maxIndependence = XMAX(maxIndependence, pip->independence);
							} else {
								break;
							}
						}
					}
					uint8_t interference = MAX_PATH_IFR_INDEPENDENCE - maxIndependence;

					a[t].pathTime += (a[i].linkTime * ((UMETRIC_T) interference)) / MAX_PATH_IFR_INDEPENDENCE;
				}
			}
		}

		maxPathTime = XMAX(maxPathTime, a[t].pathTime);
	}


	return maxPathTime;
}

STATIC_FUNC
void path_metricalgo_Capacity(struct NeighPath *np, struct NeighRef_node *ref, struct host_metricalgo *algo)
{
	assertion(-500000, ((ref->ogmSqnMaxPathMetricsByteSize % sizeof(struct msg_ogm_adv_metric_t0))==0));

	uint16_t inHPos, outHPos = 0, outIfrPos = 0;
	uint16_t inHSz = ref->ogmSqnMaxPathMetricsByteSize / sizeof(struct msg_ogm_adv_metric_t0);
	uint16_t inHMax = XMIN(inHSz, algo->ogm_hop_history);
	static struct sub_path_metric subPathArr[MAX_OGM_HOP_HISTORY_SZ + 1];
	UMETRIC_T linkTP;
	UMETRIC_T pathMaxTP = np->um;
	UMETRIC_T maxPathTime = 1;
	UMETRIC_T tq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_tq_probe)) / LQ_MAX), algo->algo_tp_exp_numerator, algo->algo_tp_exp_divisor);
	UMETRIC_T rq = umetric_to_the_power_of_n((((UMETRIC_MAX)*((UMETRIC_T) np->link->timeaware_rq_probe)) / LQ_MAX), algo->algo_rp_exp_numerator, algo->algo_rp_exp_divisor);
	UMETRIC_T lq = apply_lq_threshold_curve(umetric_multiply_normalized(tq, rq), algo);

	
	if (np->link->wifiStats.txRateAvg) {
		//linkTP = ((np->link->wifiStats.txRateAvg * ((UMETRIC_T)(np->link->k.myDev->linklayer == TYP_DEV_LL_WIFI ? algo->ogm_link_rate_efficiency: 100))) / 100);

		linkTP = ((umetric_multiply_normalized(np->link->wifiStats.txRateAvg, lq) * ((UMETRIC_T) (np->link->k.myDev->linklayer == TYP_DEV_LL_WIFI ? algo->ogm_link_rate_efficiency: 100))) / 100);
	} else {
		linkTP = ((umetric_multiply_normalized(np->link->k.myDev->umetric_max, lq) * ((UMETRIC_T) (np->link->k.myDev->linklayer == TYP_DEV_LL_WIFI ? algo->ogm_link_rate_efficiency: 100))) / 100);
	}
	linkTP = XMAX(linkTP, UMETRIC_MIN__NOT_ROUTABLE);
	pathMaxTP = XMIN(pathMaxTP, linkTP);

	np->pathMetricsByteSize = 0;
	
	if (np->link->k.myDev->channel != TYP_DEV_CHANNEL_EXCLUSIVE) {

		spmSet(subPathArr, np->link->k.myDev->channel, outIfrPos++, &linkTP);
		maxPathTime += (UMETRIC_MAX_MAX / linkTP);

		if (algo->ogm_hop_history > outHPos) {
			FMETRIC_U16_T linkFm = umetric_to_fmetric(linkTP);
			np->pathMetrics[outHPos].u.f.type = 0;
			np->pathMetrics[outHPos].u.f.directional = 0;
			np->pathMetrics[outHPos].channel = np->link->k.myDev->channel;
			np->pathMetrics[outHPos].u.f.metric_exp = linkFm.val.f.exp_fm16;
			np->pathMetrics[outHPos].u.f.metric_mantissa = linkFm.val.f.mantissa_fm16;
			np->pathMetrics[outHPos].u.f.more = 0;
			np->pathMetricsByteSize += sizeof(struct msg_ogm_adv_metric_t0);
			outHPos++;
		}
	}

	dbgf_track(DBGT_INFO, "msg: linkTP=%ju pathMaxTP=%ju maxPathTime=%ju inHMax=%d o=%d p=%d",
		linkTP, pathMaxTP, maxPathTime, inHMax, outHPos, outIfrPos);

	for (inHPos = 0; inHPos < inHMax; inHPos++) {

		assertion(-500000, (ref->ogmSqnMaxPathMetrics[inHPos].u.f.type == 0));

		FMETRIC_U16_T fm = {.val = {.f = {.exp_fm16 = ref->ogmSqnMaxPathMetrics[inHPos].u.f.metric_exp, .mantissa_fm16 = ref->ogmSqnMaxPathMetrics[inHPos].u.f.metric_mantissa}}};

		linkTP = fmetric_to_umetric(fm);
		linkTP = XMAX(linkTP, UMETRIC_MIN__NOT_ROUTABLE);
		pathMaxTP = XMIN(pathMaxTP, linkTP);

		if (ref->ogmSqnMaxPathMetrics[inHPos].channel != TYP_DEV_CHANNEL_EXCLUSIVE) {

			spmSet(subPathArr, ref->ogmSqnMaxPathMetrics[inHPos].channel, outIfrPos++, &linkTP);
			maxPathTime += (UMETRIC_MAX_MAX / linkTP);
			
			if (algo->ogm_hop_history > outHPos) {

				np->pathMetrics[outHPos] = ref->ogmSqnMaxPathMetrics[inHPos];
				np->pathMetrics[outHPos].u.f.more = 0;

				if (outHPos >= 1)
					np->pathMetrics[outHPos - 1].u.f.more = 1;

				np->pathMetricsByteSize += sizeof(struct msg_ogm_adv_metric_t0);
				outHPos++;
			}
		}

		dbgf_track(DBGT_INFO, "hops linkTP=%ju pathMaxTP=%ju maxPathTime=%ju subTreeTime=%ju i=%d o=%d p=%d",
			linkTP, pathMaxTP, maxPathTime, subPathArrMaxTime(subPathArr, outIfrPos, algo), inHPos, outHPos, outIfrPos);
	}

	UMETRIC_T subTreeTime = subPathArrMaxTime(subPathArr, outIfrPos, algo);

	assertion_dbg(-500000, (subTreeTime <= maxPathTime), "subTreeTime=%ju !<= maxPathTime=%ju", subTreeTime, maxPathTime);

	np->um = XMIN(pathMaxTP, (UMETRIC_MAX_MAX / subTreeTime));
}

STATIC_FUNC
void register_path_metricalgo(uint8_t algo_type_bit, void (*algo) (struct NeighPath *neighPath, struct NeighRef_node *ref, struct host_metricalgo *algo))
{
        assertion(-500838, (!path_metric_algos[algo_type_bit]));
        assertion(-500839, (algo_type_bit < BIT_METRIC_ALGO_ARRSZ));
        path_metric_algos[algo_type_bit] = algo;
}

struct NeighPath *apply_metric_algo(struct NeighRef_node *ref, LinkNode *link, struct host_metricalgo *algo)
{
        TRACE_FUNCTION_CALL;
	UMETRIC_T refMetric = fmetric_to_umetric(ref->ogmSqnMaxClaimedMetric);

        assertion(-500823, (link->k.myDev->umetric_max));

        ALGO_T unsupported_algos = 0;
        ALGO_T algo_type = algo->algo_type;
        UMETRIC_T max_out = umetric_substract_min(&refMetric);

	static struct NeighPath neighPath;

	neighPath.link = link;
	neighPath.um = refMetric;
	neighPath.pathMetricsByteSize = 0;

        if (algo_type) {

                while (algo_type && neighPath.um > UMETRIC_MIN__NOT_ROUTABLE) {

                        uint8_t algo_type_bit;
                        LOG2(algo_type_bit, algo_type, ALGO_T);

                        algo_type -= (0x01 << algo_type_bit);

                        if (path_metric_algos[algo_type_bit]) {

                                (*(path_metric_algos[algo_type_bit])) (&neighPath, ref, algo);

                                dbgf_track(DBGT_INFO, "algo=%d in=%-12ju=%7s  out=%-12ju=%7s",
                                        algo_type_bit, refMetric, umetric_to_human(refMetric), neighPath.um, umetric_to_human(neighPath.um));

                        } else {
                                unsupported_algos |= (0x01 << algo_type_bit);
                        }
                }

                if (unsupported_algos) {
                        uint8_t i = bits_count(unsupported_algos);

                        dbgf_sys(DBGT_WARN,
                                "unsupported %s=%d (0x%X) - Need an update?! - applying pessimistic ETTv0 %d times",
                                ARG_PATH_METRIC_ALGO, unsupported_algos, unsupported_algos, i);

                        while (i-- && neighPath.um > UMETRIC_MIN__NOT_ROUTABLE)
                                (*(path_metric_algos[BIT_METRIC_ALGO_EB])) (&neighPath, ref, algo);
                }
        }

        if (algo->ogm_hop_penalty)
                neighPath.um = (neighPath.um * ((UMETRIC_T) (MAX_OGM_HOP_PENALTY - algo->ogm_hop_penalty))) >> MAX_OGM_HOP_PENALTY_PRECISION_EXP;

        if (neighPath.um > max_out) {
		dbgf_track(DBGT_WARN, "out=%ju > out_max=%ju, %s=%d, path=%ju", neighPath.um, max_out, ARG_PATH_METRIC_ALGO, algo->algo_type, refMetric);
		neighPath.um = max_out;
        }

	if (neighPath.um < algo->umetric_min || neighPath.um == UMETRIC_MIN__NOT_ROUTABLE) {
		neighPath.um = UMETRIC_MIN__NOT_ROUTABLE;
		neighPath.pathMetricsByteSize = 0;
		neighPath.link = NULL;
	}

	assertion(-500000, IMPLIES(neighPath.um != UMETRIC_MIN__NOT_ROUTABLE, umetric_to_fmetric(neighPath.um).val.u16 < umetric_to_fmetric(refMetric).val.u16));

	return &neighPath;
}


STATIC_FUNC
IDM_T validate_metricalgo(struct host_metricalgo *ma, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        if (
                validate_param((ma->algo_type), MIN_METRIC_ALGO, MAX_METRIC_ALGO_RESERVED, ARG_PATH_METRIC_ALGO) ||
                validate_param((ma->algo_rp_exp_numerator), MIN_PATH_XP_EXP_NUMERATOR, MAX_PATH_XP_EXP_NUMERATOR, ARG_PATH_RP_EXP_NUMERATOR) ||
                validate_param((ma->algo_rp_exp_divisor), MIN_PATH_XP_EXP_DIVISOR, MAX_PATH_XP_EXP_DIVISOR, ARG_PATH_RP_EXP_DIVISOR) ||
                validate_param((ma->algo_tp_exp_numerator), MIN_PATH_XP_EXP_NUMERATOR, MAX_PATH_XP_EXP_NUMERATOR, ARG_PATH_TP_EXP_NUMERATOR) ||
                validate_param((ma->algo_tp_exp_divisor), MIN_PATH_XP_EXP_DIVISOR, MAX_PATH_XP_EXP_DIVISOR, ARG_PATH_TP_EXP_DIVISOR) ||
                validate_param((ma->flags),      MIN_METRIC_FLAGS, MAX_METRIC_FLAGS, ARG_PATH_METRIC_FLAGS) ||
                validate_param((ma->ogm_metric_hystere_new_path), MIN_OGM_METRIC_HYST_NEW_PATH, MAX_OGM_METRIC_HYST_NEW_PATH, ARG_OGM_METRIC_HYST_NEW_PATH) ||
                validate_param((ma->ogm_metric_hystere_old_path), MIN_OGM_METRIC_HYST_OLD_PATH, MAX_OGM_METRIC_HYST_OLD_PATH, ARG_OGM_METRIC_HYST_OLD_PATH) ||
                validate_param((ma->ogm_sqn_best_hystere), MIN_OGM_SQN_BEST_HYST, MAX_OGM_SQN_BEST_HYST, ARG_OGM_SQN_BEST_HYST) ||
                validate_param((ma->ogm_sqn_late_hystere_100ms), MIN_OGM_SQN_LATE_HYST, MAX_OGM_SQN_LATE_HYST, ARG_OGM_SQN_LATE_HYST) ||
                validate_param((ma->ogm_hop_penalty), MIN_OGM_HOP_PENALTY, MAX_OGM_HOP_PENALTY, ARG_OGM_HOP_PENALTY) ||
                validate_param((ma->ogm_hops_max), MIN_OGM_HOPS_MAX, MAX_OGM_HOPS_MAX, ARG_OGM_HOPS_MAX) ||
                validate_param((ma->ogm_hop_history), MIN_OGM_HOP_HISTORY_SZ, MAX_OGM_HOP_HISTORY_SZ, ARG_OGM_HOP_HISTORY_SZ) ||
		validate_param((ma->lq_tx_point_r255), MIN_PATH_LQ_TX_R255, MAX_PATH_LQ_TX_R255, ARG_PATH_LQ_TX_R255) ||
		validate_param((ma->lq_ty_point_r255), MIN_PATH_LQ_TY_R255, MAX_PATH_LQ_TY_R255, ARG_PATH_LQ_TY_R255) ||
		validate_param((ma->lq_t1_point_r255), MIN_PATH_LQ_T1_R255, MAX_PATH_LQ_T1_R255, ARG_PATH_LQ_T1_R255) ||
		validate_param((ma->ogm_link_rate_efficiency), MIN_OGM_LINK_RATE_EFFICIENCY, MAX_OGM_LINK_RATE_EFFICIENCY, ARG_OGM_LINK_RATE_EFFICIENCY) ||
		ma->lq_t1_point_r255 <= ma->lq_tx_point_r255 ||
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
	host_algo->lq_tx_point_r255 = tlv_algo->m.lq_tx_point_r255;
	host_algo->lq_ty_point_r255 = tlv_algo->m.lq_ty_point_r255;
	host_algo->lq_t1_point_r255 = tlv_algo->m.lq_t1_point_r255;
	host_algo->ogm_link_rate_efficiency = tlv_algo->m.ogm_link_rate_efficiency;
        host_algo->ogm_sqn_best_hystere = tlv_algo->m.ogm_sqn_best_hystere;
        host_algo->ogm_sqn_late_hystere_100ms = tlv_algo->m.ogm_sqn_late_hystere_100ms;
        host_algo->ogm_metric_hystere_new_path = ntohs(tlv_algo->m.ogm_metric_hystere_new_path);
        host_algo->ogm_metric_hystere_old_path = ntohs(tlv_algo->m.ogm_metric_hystere_old_path);
	host_algo->ogm_hop_penalty = tlv_algo->m.hop_penalty;
	host_algo->ogm_hops_max = tlv_algo->m.hops_max;
	host_algo->ogm_hop_history = tlv_algo->m.hops_history;
	memcpy(host_algo->pip, tlv_algo->m.pip, sizeof(tlv_algo->m.pip));

	assertion(-500000, ((MAX_PATH_IFR_PARAMETERS * sizeof(struct path_interference_parameter)) == sizeof(my_path_interference_parameter)));
	assertion(-500000, ((MAX_PATH_IFR_PARAMETERS * sizeof(struct path_interference_parameter)) == sizeof(host_algo->pip)));
	assertion(-500000, ((MAX_PATH_IFR_PARAMETERS * sizeof(struct path_interference_parameter)) == sizeof(tlv_algo->m.pip)));
	assertion(-500000, ((MAX_PATH_IFR_PARAMETERS * sizeof(struct path_interference_parameter)) == sizeof(DEF_OGM_PATH_INTERFERENCE_PARAMETER)));


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
        tlv_algo.m.algo_type = htons(my_ogm_path_algo); //METRIC_ALGO
        tlv_algo.m.flags = htons(my_path_metric_flags);
        tlv_algo.m.rp_exp_numerator = my_path_rp_exp_numerator;
        tlv_algo.m.rp_exp_divisor = my_path_rp_exp_divisor;
        tlv_algo.m.tp_exp_numerator = my_path_tp_exp_numerator;
        tlv_algo.m.tp_exp_divisor = my_path_tp_exp_divisor;
	tlv_algo.m.lq_tx_point_r255 = my_path_lq_tx_r255;
	tlv_algo.m.lq_ty_point_r255 = my_path_lq_ty_r255;
	tlv_algo.m.lq_t1_point_r255 = my_path_lq_t1_r255;
	tlv_algo.m.ogm_link_rate_efficiency = my_ogm_link_rate_efficiency;
        tlv_algo.m.ogm_metric_hystere_new_path = htons(my_ogm_metric_hyst_new_path);
        tlv_algo.m.ogm_metric_hystere_old_path = htons(my_ogm_metric_hyst_old_path);
        tlv_algo.m.ogm_sqn_best_hystere = my_ogm_sqn_best_hyst;
        tlv_algo.m.ogm_sqn_late_hystere_100ms = my_ogm_sqn_late_hyst_100ms;
        tlv_algo.m.hop_penalty = my_ogm_hop_penalty;
	tlv_algo.m.hops_max = my_ogm_hops_max;
	tlv_algo.m.hops_history = my_ogm_hop_hisotry_size;
	memcpy(tlv_algo.m.pip, my_path_interference_parameter, sizeof(my_path_interference_parameter));


        memset(&my_hostmetricalgo, 0, sizeof (struct host_metricalgo));

        if (metricalgo_tlv_to_host(&tlv_algo, &my_hostmetricalgo, sizeof (struct description_tlv_metricalgo)) == FAILURE)
                cleanup_all(-500844);


	if (!descMetricalgo)
		return TLV_TX_DATA_IGNORED;


        if (tx_iterator_cache_data_space_pref(it, 0, 0) < ((int) sizeof (struct description_tlv_metricalgo))) {

                dbgf_sys(DBGT_ERR, "unable to announce metric due to limiting --%s", ARG_UDPD_SIZE);
                return TLV_TX_DATA_FAILURE;
        }

        memcpy(((struct description_tlv_metricalgo *) tx_iterator_cache_msg_ptr(it)), &tlv_algo,
                sizeof (struct description_tlv_metricalgo));

        return sizeof (struct description_tlv_metricalgo);
}


STATIC_FUNC
void metricalgo_remove(struct orig_node *on)
{
	remove_ogm(on);

	if (on->mtcAlgo) {
		debugFree(on->mtcAlgo, -300285);
		on->mtcAlgo = NULL;
	}
}

STATIC_FUNC
void metricalgo_assign(struct orig_node *on, struct host_metricalgo *host_algo)
{

	metricalgo_remove(on);

	assertion(-500684, (!on->mtcAlgo));

	if (!host_algo)
		host_algo = &my_hostmetricalgo;

	on->mtcAlgo = debugMalloc(sizeof (struct host_metricalgo), -300286);
	memcpy(on->mtcAlgo, host_algo, sizeof (struct host_metricalgo));
}


STATIC_FUNC
void metrics_description_event_hook(int32_t cb_id, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

        assertion(-501306, (on));
        assertion(-501270, IMPLIES(cb_id == PLUGIN_CB_DESCRIPTION_CREATED, (on)));
        assertion(-501273, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501274, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));

	if (cb_id==PLUGIN_CB_DESCRIPTION_CREATED) {

		if (!on->mtcAlgo)
			metricalgo_assign(on, NULL);
/*
		struct NeighRef_node *ref = NULL;
		while ((ref = avl_next_item(&on->dc->kn->neighRefs_tree, ref ? &ref->nn : NULL)))
			process_ogm_metric(ref);
*/
	} else {

		metricalgo_remove(on);
	}
}

STATIC_FUNC
int process_description_tlv_metricalgo(struct rx_frame_iterator *it )
{
        TRACE_FUNCTION_CALL;
        assertion(-500683, (it->f_type == BMX_DSC_TLV_METRIC));

        uint8_t op = it->op;

        struct description_tlv_metricalgo *tlv_algo = (struct description_tlv_metricalgo *) (it->f_data);
        struct host_metricalgo host_algo;

        dbgf_all( DBGT_INFO, "%s ", tlv_op_str(op));

        if (op == TLV_OP_NEW || op == TLV_OP_TEST) {

                if (metricalgo_tlv_to_host(tlv_algo, &host_algo, it->f_msgs_len) == FAILURE)
                        return TLV_RX_DATA_FAILURE;
        }

        if (op == TLV_OP_DEL)
		metricalgo_remove(it->on);

        if (op == TLV_OP_NEW)
		metricalgo_assign(it->on, &host_algo);

        return it->f_msgs_len;
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

                test_algo.umetric_min = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_PATH_UMETRIC_MIN)) ?
                        my_path_umetric_min : (patch->diff != DEL ? strtol(patch->val, NULL, 10) : (int)DEF_PATH_UMETRIC_MIN);

                test_algo.fmetric_u16_min = umetric_to_fmetric(test_algo.umetric_min);


		test_algo.ogm_hop_penalty = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_OGM_HOP_PENALTY)) ?
			my_ogm_hop_penalty : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_OGM_HOP_PENALTY);

		test_algo.ogm_hops_max = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_OGM_HOPS_MAX)) ?
			my_ogm_hops_max : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_OGM_HOPS_MAX);

		test_algo.ogm_hop_history = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_OGM_HOP_HISTORY_SZ)) ?
			my_ogm_hop_hisotry_size : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_OGM_HOP_HISTORY_SZ);

		test_algo.ogm_metric_hystere_new_path = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_OGM_METRIC_HYST_NEW_PATH)) ?
			my_ogm_metric_hyst_new_path : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_OGM_METRIC_HYST_NEW_PATH);

		test_algo.ogm_metric_hystere_old_path = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_OGM_METRIC_HYST_OLD_PATH)) ?
			my_ogm_metric_hyst_old_path : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_OGM_METRIC_HYST_OLD_PATH);

		test_algo.ogm_sqn_best_hystere = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_OGM_SQN_BEST_HYST)) ?
			my_ogm_sqn_best_hyst : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_OGM_SQN_BEST_HYST);

		test_algo.ogm_sqn_late_hystere_100ms = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_OGM_SQN_LATE_HYST)) ?
			my_ogm_sqn_late_hyst_100ms : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_OGM_SQN_LATE_HYST);

		test_algo.lq_tx_point_r255 = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_PATH_LQ_TX_R255)) ?
			my_path_lq_tx_r255 : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_PATH_LQ_TX_R255);

		test_algo.lq_ty_point_r255 = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_PATH_LQ_TY_R255)) ?
			my_path_lq_ty_r255 : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_PATH_LQ_TY_R255);

		test_algo.lq_t1_point_r255 = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_PATH_LQ_T1_R255)) ?
			my_path_lq_t1_r255 : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_PATH_LQ_T1_R255);

		test_algo.ogm_link_rate_efficiency = (cmd == OPT_REGISTER || strcmp(opt->name, ARG_OGM_LINK_RATE_EFFICIENCY)) ?
			my_ogm_link_rate_efficiency : ((patch->diff != DEL) ? strtol(patch->val, NULL, 10) : DEF_OGM_LINK_RATE_EFFICIENCY);


		memcpy(test_algo.pip, my_path_interference_parameter, sizeof(my_path_interference_parameter));


                if (cmd == OPT_REGISTER || strcmp(opt->name, ARG_PATH_METRIC_ALGO)) {

			test_algo.algo_type = my_ogm_path_algo;
			test_algo.algo_rp_exp_numerator = my_path_rp_exp_numerator;
			test_algo.algo_rp_exp_divisor = my_path_rp_exp_divisor;
			test_algo.algo_tp_exp_numerator = my_path_tp_exp_numerator;
			test_algo.algo_tp_exp_divisor = my_path_tp_exp_divisor;
/*
			test_algo.ogm_hop_penalty = my_ogm_hop_penalty;
			test_algo.ogm_hops_max = my_ogm_hops_max;
			test_algo.ogm_hop_history = my_ogm_hop_hisotry_size;
			test_algo.ogm_metric_hystere_new_path = my_ogm_metric_hyst_new_path;
			test_algo.ogm_metric_hystere_old_path = my_ogm_metric_hyst_old_path;
			test_algo.ogm_sqn_best_hystere = my_ogm_sqn_best_hyst;
			test_algo.ogm_sqn_late_hystere_100ms = my_ogm_sqn_late_hyst_100ms;
			test_algo.lq_tx_point_r255 = my_path_lq_tx_r255;
			test_algo.lq_ty_point_r255 = my_path_lq_ty_r255;
			test_algo.lq_t1_point_r255 = my_path_lq_t1_r255;
			test_algo.ogm_link_rate_efficiency = my_ogm_link_rate_efficiency;
*/

                } else {

			test_algo.algo_type = DEF_METRIC_ALGO;
			test_algo.algo_rp_exp_numerator = DEF_PATH_RP_EXP_NUMERATOR;
			test_algo.algo_rp_exp_divisor = DEF_PATH_RP_EXP_DIVISOR;
			test_algo.algo_tp_exp_numerator = DEF_PATH_TP_EXP_NUMERATOR;
			test_algo.algo_tp_exp_divisor = DEF_PATH_TP_EXP_DIVISOR;
/*
			test_algo.ogm_hop_penalty = DEF_OGM_HOP_PENALTY;
			test_algo.ogm_hops_max = DEF_OGM_HOPS_MAX;
			test_algo.ogm_hop_history = DEF_OGM_HOP_HISTORY_SZ;
			test_algo.ogm_metric_hystere_new_path = DEF_OGM_METRIC_HYST_NEW_PATH;
			test_algo.ogm_metric_hystere_old_path = DEF_OGM_METRIC_HYST_OLD_PATH;
			test_algo.ogm_sqn_best_hystere = DEF_OGM_SQN_BEST_HYST;
			test_algo.ogm_sqn_late_hystere_100ms = DEF_OGM_SQN_LATE_HYST;
			test_algo.lq_tx_point_r255 = DEF_PATH_LQ_TX_R255;
			test_algo.lq_ty_point_r255 = DEF_PATH_LQ_TY_R255;
			test_algo.lq_t1_point_r255 = DEF_PATH_LQ_T1_R255;
			test_algo.ogm_link_rate_efficiency = DEF_OGM_LINK_RATE_EFFICIENCY;
*/

                        if (patch->diff != DEL) {

                                test_algo.algo_type = strtol(patch->val, NULL, 10);

                                struct opt_child *c = NULL;
                                while ((c = list_iterate(&patch->childs_instance_list, c))) {

                                        if (!c->val)
                                                continue;

                                        int32_t val = strtol(c->val, NULL, 10);

                                        if (!strcmp(c->opt->name, ARG_PATH_RP_EXP_NUMERATOR))
                                                test_algo.algo_rp_exp_numerator = val;

                                        if (!strcmp(c->opt->name, ARG_PATH_RP_EXP_DIVISOR))
                                                test_algo.algo_rp_exp_divisor = val;

                                        if (!strcmp(c->opt->name, ARG_PATH_TP_EXP_NUMERATOR))
                                                test_algo.algo_tp_exp_numerator = val;

                                        if (!strcmp(c->opt->name, ARG_PATH_TP_EXP_DIVISOR))
                                                test_algo.algo_tp_exp_divisor = val;
/*
                                        if (!strcmp(c->opt->name, ARG_OGM_HOP_PENALTY))
                                                test_algo.ogm_hop_penalty = val;

                                        if (!strcmp(c->opt->name, ARG_OGM_HOPS_MAX))
                                                test_algo.ogm_hops_max = val;

                                        if (!strcmp(c->opt->name, ARG_OGM_HOP_HISTORY_SZ))
						test_algo.ogm_hop_history = val;

                                        if (!strcmp(c->opt->name, ARG_OGM_METRIC_HYST_NEW_PATH))
                                                test_algo.ogm_metric_hystere_new_path = val;

                                        if (!strcmp(c->opt->name, ARG_OGM_METRIC_HYST_OLD_PATH))
                                                test_algo.ogm_metric_hystere_old_path = val;

                                        if (!strcmp(c->opt->name, ARG_OGM_SQN_BEST_HYST))
                                                test_algo.ogm_sqn_best_hystere = val;

                                        if (!strcmp(c->opt->name, ARG_OGM_SQN_LATE_HYST))
                                                test_algo.ogm_sqn_late_hystere_100ms = val;

                                        if (!strcmp(c->opt->name, ARG_PATH_LQ_TX_R255))
                                                test_algo.lq_tx_point_r255 = val;

                                        if (!strcmp(c->opt->name, ARG_PATH_LQ_TY_R255))
                                                test_algo.lq_ty_point_r255 = val;

                                        if (!strcmp(c->opt->name, ARG_PATH_LQ_T1_R255))
                                                test_algo.lq_t1_point_r255 = val;

                                        if (!strcmp(c->opt->name, ARG_OGM_LINK_RATE_EFFICIENCY))
                                                test_algo.ogm_link_rate_efficiency = val;
*/
                                }
                        }
                }

                if (validate_metricalgo(&test_algo, cn) == FAILURE)
                        return FAILURE;

                if (cmd == OPT_APPLY) {
                        my_path_umetric_min = test_algo.umetric_min;

                        my_ogm_path_algo = test_algo.algo_type;
                        my_path_rp_exp_numerator = test_algo.algo_rp_exp_numerator;
                        my_path_rp_exp_divisor = test_algo.algo_rp_exp_divisor;
                        my_path_tp_exp_numerator = test_algo.algo_tp_exp_numerator;
                        my_path_tp_exp_divisor = test_algo.algo_tp_exp_divisor;
/*
			my_ogm_hop_penalty = test_algo.ogm_hop_penalty;
			my_ogm_hops_max = test_algo.ogm_hops_max;
			my_ogm_hop_hisotry_size = test_algo.ogm_hop_history;
			my_ogm_metric_hyst_new_path = test_algo.ogm_metric_hystere_new_path;
			my_ogm_metric_hyst_old_path = test_algo.ogm_metric_hystere_old_path;
			my_ogm_sqn_best_hyst = test_algo.ogm_sqn_best_hystere;
			my_ogm_sqn_late_hyst_100ms = test_algo.ogm_sqn_late_hystere_100ms;
			my_path_lq_tx_r255 = test_algo.lq_tx_point_r255;
			my_path_lq_ty_r255 = test_algo.lq_ty_point_r255;
			my_path_lq_t1_r255 = test_algo.lq_t1_point_r255;
			my_ogm_link_rate_efficiency = test_algo.ogm_link_rate_efficiency;
*/
                        my_description_changed = YES;
                }
        }


	return SUCCESS;
}


STATIC_FUNC
struct opt_type metrics_options[]=
{
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

#ifndef LESS_OPTIONS
        {ODI, 0, ARG_PATH_METRIC_ALGO, CHR_PATH_METRIC_ALGO,  9,1, A_PS1N, A_ADM, A_DYI, A_CFA, A_ANY, &my_ogm_path_algo,MIN_METRIC_ALGO,    MAX_METRIC_ALGO,    DEF_METRIC_ALGO,0,    opt_path_metricalgo,
                ARG_VALUE_FORM, HELP_PATH_METRIC_ALGO}
        ,
        {ODI, ARG_PATH_METRIC_ALGO, ARG_PATH_RP_EXP_NUMERATOR, CHR_PATH_RP_EXP_NUMERATOR, 9,1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_rp_exp_numerator, MIN_PATH_XP_EXP_NUMERATOR, MAX_PATH_XP_EXP_NUMERATOR, DEF_PATH_RP_EXP_NUMERATOR,0, opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, ARG_PATH_METRIC_ALGO, ARG_PATH_RP_EXP_DIVISOR, CHR_PATH_RP_EXP_DIVISOR, 9,1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_rp_exp_divisor, MIN_PATH_XP_EXP_DIVISOR, MAX_PATH_XP_EXP_DIVISOR, DEF_PATH_RP_EXP_DIVISOR,0, opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, ARG_PATH_METRIC_ALGO, ARG_PATH_TP_EXP_NUMERATOR, CHR_PATH_TP_EXP_NUMERATOR, 9,1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_tp_exp_numerator, MIN_PATH_XP_EXP_NUMERATOR, MAX_PATH_XP_EXP_NUMERATOR, DEF_PATH_TP_EXP_NUMERATOR,0, opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, ARG_PATH_METRIC_ALGO, ARG_PATH_TP_EXP_DIVISOR, CHR_PATH_TP_EXP_DIVISOR, 9,1, A_CS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_tp_exp_divisor, MIN_PATH_XP_EXP_DIVISOR, MAX_PATH_XP_EXP_DIVISOR, DEF_PATH_TP_EXP_DIVISOR,0, opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
	{ODI, 0, ARG_OGM_METRIC_HYST_NEW_PATH,     0,   9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,    &my_ogm_metric_hyst_new_path,MIN_OGM_METRIC_HYST_NEW_PATH, MAX_OGM_METRIC_HYST_NEW_PATH,DEF_OGM_METRIC_HYST_NEW_PATH,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	"use metric hysteresis in % to delay route switching to alternative next-hop neighbors with better path metric"}
        ,
	{ODI, 0, ARG_OGM_METRIC_HYST_OLD_PATH,     0,   9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,    &my_ogm_metric_hyst_old_path,MIN_OGM_METRIC_HYST_OLD_PATH, MAX_OGM_METRIC_HYST_OLD_PATH,DEF_OGM_METRIC_HYST_OLD_PATH,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	"use metric hysteresis in % to delay ogm updates due to better path metric via old path"}
        ,
	{ODI, 0, ARG_OGM_SQN_BEST_HYST,0,9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,    &my_ogm_sqn_best_hyst,MIN_OGM_SQN_BEST_HYST,MAX_OGM_SQN_BEST_HYST,DEF_OGM_SQN_BEST_HYST,0, opt_path_metricalgo,
		ARG_VALUE_FORM,	"overcome metric hysteresis to force route switching after successive reception of x new OGM-SQNs with with better path metric"}
        ,
	{ODI, 0, ARG_OGM_SQN_LATE_HYST,0,9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,    &my_ogm_sqn_late_hyst_100ms,MIN_OGM_SQN_LATE_HYST,MAX_OGM_SQN_LATE_HYST,DEF_OGM_SQN_LATE_HYST,0, opt_path_metricalgo,
		ARG_VALUE_FORM,	"delay route switching in 100ms to next-hop neighbor due its fast OGM-SQN delivery"}
        ,
	{ODI, 0, ARG_OGM_HOPS_MAX,	   0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_ogm_hops_max, MIN_OGM_HOPS_MAX, MAX_OGM_HOPS_MAX, DEF_OGM_HOPS_MAX,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	"set maximum amount of hops my OGMs are allowed to be forwarded"}
        ,
        {ODI,0,ARG_OGM_HOP_HISTORY_SZ,     0,9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_ogm_hop_hisotry_size,  MIN_OGM_HOP_HISTORY_SZ, MAX_OGM_HOP_HISTORY_SZ, DEF_OGM_HOP_HISTORY_SZ,0,   opt_path_metricalgo,
			ARG_VALUE_FORM,	"set maximum history size of hop (link) metrics attached to my OGMs"},

	{ODI, 0, ARG_OGM_HOP_PENALTY,	   0,  9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&my_ogm_hop_penalty, MIN_OGM_HOP_PENALTY, MAX_OGM_HOP_PENALTY, DEF_OGM_HOP_PENALTY,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	"penalize non-first rcvd OGMs in 1/255 (each hop will substract metric*(VALUE/255) from current path-metric)"}
        ,
        {ODI, 0, ARG_NEW_RT_DISMISSAL,     0, 9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &new_rt_dismissal_div100, MIN_NEW_RT_DISMISSAL, MAX_NEW_RT_DISMISSAL, DEF_NEW_RT_DISMISSAL,0, 0,
			ARG_VALUE_FORM,	HLP_NEW_RT_DISMISSAL}
	,
	{ODI, 0, ARG_PATH_LQ_TX_R255,   0, 9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,    &my_path_lq_tx_r255, MIN_PATH_LQ_TX_R255, MAX_PATH_LQ_TX_R255,DEF_PATH_LQ_TX_R255,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	"specify X threshold point for transforming path lq values 255==100%"}
        ,
	{ODI, 0, ARG_PATH_LQ_TY_R255,   0, 9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,    &my_path_lq_ty_r255, MIN_PATH_LQ_TY_R255, MAX_PATH_LQ_TY_R255,DEF_PATH_LQ_TY_R255,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	"specify Y threshold point for transforming path lq values 255==100%"}
        ,
	{ODI, 0, ARG_PATH_LQ_T1_R255,   0, 9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,    &my_path_lq_t1_r255, MIN_PATH_LQ_T1_R255, MAX_PATH_LQ_T1_R255,DEF_PATH_LQ_T1_R255,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	"specify 100% threshold point for transforming path lq values 255==100%"}
        ,
	{ODI, 0, ARG_OGM_LINK_RATE_EFFICIENCY,0, 9,1,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&my_ogm_link_rate_efficiency,MIN_OGM_LINK_RATE_EFFICIENCY,MAX_OGM_LINK_RATE_EFFICIENCY,DEF_OGM_LINK_RATE_EFFICIENCY,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	HLP_OGM_LINK_RATE_EFFICIENCY}
        ,

        {ODI, 0, ARG_PATH_UMETRIC_MIN, 0,  9,1, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &my_path_umetric_min,MIN_PATH_UMETRIC_MIN,MAX_PATH_UMETRIC_MIN,DEF_PATH_UMETRIC_MIN,0,    opt_path_metricalgo,
                ARG_VALUE_FORM, " "}
        ,
        {ODI, 0, ARG_DESC_METRICALGO,0, 9,2, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &descMetricalgo, MIN_DESC_METRICALGO, MAX_DESC_METRICALGO, DEF_DESC_METRICALGO,0, opt_path_metricalgo,
			ARG_VALUE_FORM,	"enable/disable inclusion of metric algo in node description (other nodes will use their default algo)"}
        ,
#endif

};



STATIC_FUNC
void init_metrics_assertions( void ) {

#ifndef NO_ASSERTIONS
        dbgf_all(DBGT_INFO, "um_fm8_min=%ju um_max=%ju um_mask=%ju um_shift_max=%zu um_multiply_max=%ju um_max_sqrt_square=%ju um_max_sqrt=%ju u32_max=%u u64_max=%ju u64_max_half=%ju u64_max_half_sqrt_square=%ju u64_max_half_sqrt=%ju precision_max=%ju precision_half=%ju\n",
		UMETRIC_FM8_MIN, UMETRIC_MAX, UMETRIC_MASK, UMETRIC_SHIFT_MAX, UMETRIC_MULTIPLY_MAX, UMETRIC_MAX_SQRT_SQUARE, UMETRIC_MAX_SQRT, U32_MAX, U64_MAX, U64_MAX_HALF, U64_MAX_HALF_SQRT_SQUARE, U64_MAX_HALF_SQRT, (UMETRIC_MAX / 300000), ((U64_MAX_HALF) / 3000000));

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
	// validate precision: deviation less than 0.001%
        assertion(-501082, ((XMAX(UMETRIC_MAX_SQRT_SQUARE, UMETRIC_MAX) - XMIN(UMETRIC_MAX_SQRT_SQUARE, UMETRIC_MAX))     < (UMETRIC_MAX    / 100000)));
        assertion(-501083, ((XMAX(U64_MAX_HALF_SQRT_SQUARE, U64_MAX_HALF) - XMIN(U64_MAX_HALF_SQRT_SQUARE, U64_MAX_HALF)) < ((U64_MAX_HALF) / 100000)));

	UMETRIC_T test = 1000000000;
	while (test >=   10000000) {
		dbgf_all(DBGT_INFO, "um=%ju fm=%d %s",test, umetric_to_fmetric(test).val.u16, umetric_to_human(test));
		assertion(-500000, (umetric_to_fmetric(test).val.u16 > umetric_to_fmetric(umetric_substract_min(&test)).val.u16));
		test = umetric_substract_min(&test);
	}

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

        for (val = UMETRIC_MAX; val <= UMETRIC_MAX; val += XMAX(1, val >> steps)) {

                c++;

                UMETRIC_T usqrt = umetric_fast_sqrt(val);
                int32_t failure_sqrt = -((int32_t) ((val *10000) / (val ? val : 1))) + ((int32_t) (((usqrt*usqrt) *10000) / (val ? val : 1)));
                failure_sqrt = XMAX((-failure_sqrt), failure_sqrt);
                err_sqrt_min = XMIN(err_sqrt_min, failure_sqrt);
                err_sqrt_max = XMAX(err_sqrt_max, failure_sqrt);
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
}

STATIC_FUNC
int32_t init_metrics( void )
{
	assertion(-500996, (sizeof (FMETRIC_U16_T) == 2));
        assertion(-500997, (sizeof (FMETRIC_U8_T) == 1));

        UMETRIC_MAX_SQRT = umetric_fast_sqrt(UMETRIC_MAX);
        U64_MAX_HALF_SQRT = umetric_fast_sqrt(U64_MAX_HALF);

	memcpy(my_path_interference_parameter, DEF_OGM_PATH_INTERFERENCE_PARAMETER, sizeof(DEF_OGM_PATH_INTERFERENCE_PARAMETER));


	init_metrics_assertions();


        static const struct field_format metric_format[] = DESCRIPTION_MSG_METRICALGO_FORMAT;

        struct frame_handl metric_handl;
        memset( &metric_handl, 0, sizeof(metric_handl));
        metric_handl.fixed_msg_size = 0;
        metric_handl.min_msg_size = sizeof (struct mandatory_tlv_metricalgo);
        metric_handl.name = "DSC_METRIC";
        metric_handl.tx_frame_handler = create_description_tlv_metricalgo;
        metric_handl.rx_frame_handler = process_description_tlv_metricalgo;
        metric_handl.msg_format = metric_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_METRIC, &metric_handl);

        
        register_path_metricalgo(BIT_METRIC_ALGO_MP, path_metricalgo_MultiplyQuality);
        register_path_metricalgo(BIT_METRIC_ALGO_EP, path_metricalgo_ExpectedQuality);
        register_path_metricalgo(BIT_METRIC_ALGO_MB, path_metricalgo_MultiplyBandwidth);
        register_path_metricalgo(BIT_METRIC_ALGO_EB, path_metricalgo_ExpectedBandwidth);
        register_path_metricalgo(BIT_METRIC_ALGO_VB, path_metricalgo_VectorBandwidth);
        register_path_metricalgo(BIT_METRIC_ALGO_CP, path_metricalgo_Capacity);

        register_options_array(metrics_options, sizeof (metrics_options), CODE_CATEGORY_NAME);

	return SUCCESS;
}

STATIC_FUNC
void cleanup_metrics( void )
{
/*
        if (self->path_metricalgo) {
                debugFree(self->path_metricalgo, -300281);
                self->path_metricalgo = NULL;
        }
*/
}





struct plugin *metrics_get_plugin( void ) {

	static struct plugin metrics_plugin;
	memset( &metrics_plugin, 0, sizeof ( struct plugin ) );

	metrics_plugin.plugin_name = CODE_CATEGORY_NAME;
	metrics_plugin.plugin_size = sizeof ( struct plugin );
        metrics_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_CREATED] = (void (*) (int32_t, void*)) metrics_description_event_hook;
        metrics_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_DESTROY] = (void (*) (int32_t, void*)) metrics_description_event_hook;
        metrics_plugin.cb_init = init_metrics;
	metrics_plugin.cb_cleanup = cleanup_metrics;

        return &metrics_plugin;
}
