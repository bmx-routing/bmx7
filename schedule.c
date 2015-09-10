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
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>     // ifr_if, ifr_tun
#include <linux/rtnetlink.h>


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
#include "ip.h"
#include "plugin.h"
#include "schedule.h"
#include "allocate.h"
#include "key.h"




static LIST_SIMPEL( task_list, struct task_node, list, list );

static int32_t receive_max_sock = 0;
static fd_set receive_wait_set;

static uint16_t changed_readfds = 1;


static struct timeval start_time_tv;
static struct timeval curr_tv;


void upd_time(struct timeval *precise_tv)
{
        static const struct timeval MAX_TV = {(((MAX_SELECT_TIMEOUT_MS + MAX_SELECT_SAFETY_MS) / 1000)), (((MAX_SELECT_TIMEOUT_MS + MAX_SELECT_SAFETY_MS) % 1000)*1000)};

        struct timeval bmx_tv, diff_tv, acceptable_max_tv, acceptable_min_tv = curr_tv;

        timeradd( &MAX_TV, &curr_tv, &acceptable_max_tv );

	gettimeofday( &curr_tv, NULL );

	IDM_T larger;
	if ( (larger=timercmp( &curr_tv, &acceptable_max_tv, > )) || timercmp( &curr_tv, &acceptable_min_tv, < ) ) {

		if (larger)
			timersub( &curr_tv, &acceptable_max_tv, &diff_tv );
		else
			timersub( &acceptable_min_tv, &curr_tv, &diff_tv );

		timeradd( &start_time_tv, &diff_tv, &start_time_tv );

                dbg_sys(DBGT_WARN, "critical system time drift detected: %s approx %ld s, %ld us! Correcting reference!",
		     larger ? "++" : "--", diff_tv.tv_sec, diff_tv.tv_usec );

                if ( diff_tv.tv_sec > CRITICAL_PURGE_TIME_DRIFT )
                        keyNodes_cleanup(KCPromoted, myKey);
	}

	timersub( &curr_tv, &start_time_tv, &bmx_tv );

	if ( precise_tv ) {
		precise_tv->tv_sec = bmx_tv.tv_sec;
		precise_tv->tv_usec = bmx_tv.tv_usec;
	}

}

STATIC_FUNC
void upd_bmx_time(struct timeval *tv)
{
	static struct timeval tmp;

	while (1) {
		upd_time((tv = tv ? tv : &tmp));

		bmx_time = ( (tv->tv_sec * 1000) + (tv->tv_usec / 1000) );
		bmx_time_sec = tv->tv_sec;

		if (bmx_time)
			break;
		else //Never return zero bmx_time. To Simplifying timeout processing.
			usleep(100);
	}
}



void change_selects(void)
{
	changed_readfds++;	
}

static void check_selects(void)
{
        TRACE_FUNCTION_CALL;

        if (changed_readfds) {

                FD_ZERO(&receive_wait_set);
                receive_max_sock = 0;

                //	receive_max_sock = ifevent_sk;
                //	FD_SET(ifevent_sk, &receive_wait_set);
                //	if ( receive_max_sock < unix_sock )
                //		receive_max_sock = unix_sock;

                assertion(-501099, (unix_sock > 0));

                receive_max_sock = XMAX(receive_max_sock, unix_sock);
                FD_SET(unix_sock, &receive_wait_set);

                struct ctrl_node *cn = NULL;
                while ((cn = list_iterate(&ctrl_list, cn))) {

                        if (cn->fd > 0 && cn->fd != STDOUT_FILENO) {

                                receive_max_sock = XMAX(receive_max_sock, cn->fd);
                                FD_SET(cn->fd, &receive_wait_set);
                        }
                }

                struct avl_node *it = NULL;
                struct dev_node *dev;
                while ((dev = avl_iterate_item(&dev_ip_tree, &it))) {

                        if (dev->active && dev->linklayer != TYP_DEV_LL_LO) {

                                receive_max_sock = XMAX(receive_max_sock, dev->unicast_sock);
                                FD_SET(dev->unicast_sock, &receive_wait_set);

                                receive_max_sock = XMAX(receive_max_sock, dev->rx_mcast_sock);
                                FD_SET(dev->rx_mcast_sock, &receive_wait_set);

                                if (dev->rx_fullbrc_sock > 0) {

                                        receive_max_sock = XMAX(receive_max_sock, dev->rx_fullbrc_sock);
                                        FD_SET(dev->rx_fullbrc_sock, &receive_wait_set);
                                }
                        }
                }

                struct cb_fd_node *cdn = NULL;
                while ((cdn = list_iterate(&cb_fd_list, cdn))) {

                        receive_max_sock = XMAX(receive_max_sock, cdn->fd);
                        FD_SET(cdn->fd, &receive_wait_set);
                }

                dbgf_all(DBGT_INFO, "updated changed=%d", changed_readfds);
                changed_readfds = 0;
        }
}





void task_register(TIME_T timeout, void (* task) (void *), void *data, int32_t tag)
{

        TRACE_FUNCTION_CALL;

        assertion(-500475, (task_remove(task, data) == FAILURE));
        assertion(-500989, (timeout <= REGISTER_TASK_TIMEOUT_MAX ));

	struct list_node *list_pos, *prev_pos = (struct list_node *)&task_list;
	struct task_node *tmp_tn = NULL;

	
	//TODO: allocating and freeing tn and tn->data may be much faster when done by registerig function.. 
	struct task_node *tn = debugMallocReset( sizeof( struct task_node ), tag );
	
	tn->expire = bmx_time + timeout;
	tn->task = task;
	tn->data = data;
	
	
	list_for_each( list_pos, &task_list ) {

		tmp_tn = list_entry( list_pos, struct task_node, list );

		if ( U32_GT(tmp_tn->expire, tn->expire) ) {

                        list_add_after(&task_list, prev_pos, &tn->list);
			break;

		}

		prev_pos = &tmp_tn->list;

	}

	if ( ( tmp_tn == NULL ) || ( U32_LE(tmp_tn->expire, tn->expire) ))
                list_add_tail(&task_list, &tn->list);
	
}


IDM_T task_remove(void (* task) (void *), void *data)
{
        TRACE_FUNCTION_CALL;

	struct list_node *list_pos, *tmp_pos, *prev_pos = (struct list_node*)&task_list;
        IDM_T ret = FAILURE;
		
	list_for_each_safe( list_pos, tmp_pos, &task_list ) {
			
		struct task_node *tn = list_entry( list_pos, struct task_node, list );
			
		if ( tn->task == task && tn->data == data  ) {

                        list_del_next(&task_list, prev_pos);
			
			debugFree( tn, -300080 );
#ifndef EXTREME_PARANOIA
                        return SUCCESS;
#else
                        ASSERTION(-500474, (ret == FAILURE));
                        ret = SUCCESS;
#endif
			
		} else {
			
			prev_pos = list_pos;
		}
	}

        return ret;
}


TIME_T task_next( void )
{
        TRACE_FUNCTION_CALL;

        struct list_node *list_pos, *tmp_pos, *prev_pos;

task_next_again:
        prev_pos = (struct list_node*) &task_list;

	list_for_each_safe( list_pos, tmp_pos, &task_list ) {
			
		struct task_node *tn = list_entry( list_pos, struct task_node, list );
			
		if ( U32_LE( tn->expire, bmx_time )  ) {

                        void (* task) (void *fpara) = tn->task;
                        void *data = tn->data;

			list_del_next( &task_list, prev_pos );
			debugFree( tn, -300081 ); // remove before executing because otherwise we get memory leak if taks causes an assertion
			
			(*(task)) (data);

                        CHECK_INTEGRITY();

                        //dbgf_track(DBGT_INFO, "executed %p", task );

                        goto task_next_again;
                        return 0;
			
		} else {
			
			return tn->expire - bmx_time;
		}
	}
	
	return MAX_SELECT_TIMEOUT_MS;
}



void wait4Event(TIME_T timeout)
{
        TRACE_FUNCTION_CALL;
	static struct packet_buff pb;

        static uint32_t addr_len = sizeof (pb.i.addr);

	TIME_T return_time = bmx_time + timeout;
	struct timeval tv;
	struct list_node *list_pos;
	int selected;
	fd_set tmp_wait_set;
		
	keyNode_fixTimeouts();

loop4Event:
	
	while ( U32_GT(return_time, bmx_time) ) {


		check_selects();
		
		memcpy( &tmp_wait_set, &receive_wait_set, sizeof(fd_set) );
			
		tv.tv_sec  =   (return_time - bmx_time) / 1000;
		tv.tv_usec = ( (return_time - bmx_time) % 1000 ) * 1000;
			
		selected = select( receive_max_sock + 1, &tmp_wait_set, NULL, NULL, &tv );

		upd_bmx_time( &(pb.i.tv_stamp) );

                //dbgf_track(DBGT_INFO, "select=%d", selected);
		
		//omit debugging here since event could be a closed -d4 ctrl socket 
		//which should be removed before debugging
		//dbgf_all( DBGT_INFO, "timeout %d", timeout );
		
					
		if ( selected < 0 ) {
                        static TIME_T last_interrupted_syscall = 0;

                        if (((TIME_T) (bmx_time - last_interrupted_syscall) < 1000)) {
                                dbg_sys(DBGT_WARN, //happens when receiving SIGHUP
                                        "can't select! Waiting a moment! errno: %s", strerror(errno));
                        }

                        last_interrupted_syscall = bmx_time;

			wait_sec_msec( 0, 1 );
			upd_bmx_time( NULL );
			
			goto wait4Event_end;
		}
	
		if ( selected == 0 ) {
	
			//Often select returns just a few milliseconds before being scheduled
			if ( U32_LT( return_time, (bmx_time + 10) ) ) {
					
				//cheating time :-)
				bmx_time = return_time;
				
				goto wait4Event_end;
			}
					
			//if ( LESS_U32( return_time, bmx_time ) )
                        dbgf_track(DBGT_WARN, "select() returned %d without reason!! return_time %d, curr_time %d",
			     selected, return_time, bmx_time );
				
			goto loop4Event;
		}

		keyNodes_block_and_sync(0, YES);

		// check for received packets...
                struct avl_node *it = NULL;
                while ((pb.i.iif = avl_iterate_item(&dev_ip_tree, &it))) {

			if ( pb.i.iif->linklayer == TYP_DEV_LL_LO )
				continue;
				
			if ( FD_ISSET( pb.i.iif->rx_mcast_sock, &tmp_wait_set ) ) {
	
				pb.i.unicast = NO;
				
				errno=0;
				pb.i.length = recvfrom( pb.i.iif->rx_mcast_sock, pb.p.data,
				                             sizeof(pb.p.data) - 1, 0,
				                             (struct sockaddr *)&pb.i.addr, (socklen_t*)&addr_len );
				
				if ( pb.i.length < 0  &&  ( errno == EWOULDBLOCK || errno == EAGAIN ) ) {

                                        dbgf_sys(DBGT_WARN, "sock returned %d errno %d: %s",
					    pb.i.length, errno, strerror(errno) );
					
					continue;
				}

				ioctl(pb.i.iif->rx_mcast_sock, SIOCGSTAMP, &(pb.i.tv_stamp)) ;
				
				rx_packet( &pb );
				
				if ( --selected == 0 )
					goto loop4Event;

			}
			
			if ( FD_ISSET( pb.i.iif->rx_fullbrc_sock, &tmp_wait_set ) ) {
				
				pb.i.unicast = NO;
				
				errno=0;
				pb.i.length = recvfrom( pb.i.iif->rx_fullbrc_sock, pb.p.data,
				                             sizeof(pb.p.data) - 1, 0,
				                             (struct sockaddr *)&pb.i.addr, (socklen_t*)&addr_len );
				
				if ( pb.i.length < 0  &&  ( errno == EWOULDBLOCK || errno == EAGAIN ) ) {

                                        dbgf_sys(DBGT_WARN, "sock returned %d errno %d: %s",
					     pb.i.length, errno, strerror(errno) );
					
					continue;
				}
				
				ioctl(pb.i.iif->rx_fullbrc_sock, SIOCGSTAMP, &(pb.i.tv_stamp)) ;
				
				rx_packet( &pb );
				
				if ( --selected == 0 )
					goto loop4Event;
				
			}
			
			
			if ( FD_ISSET( pb.i.iif->unicast_sock, &tmp_wait_set ) ) {
				
				pb.i.unicast = YES;
					
				struct msghdr msghdr;
				struct iovec iovec = {.iov_base = pb.p.data, .iov_len = sizeof(pb.p.data) - 1};
				char buf[4096];
				struct cmsghdr *cp;
				struct timeval *tv_stamp = NULL;
	
				msghdr.msg_name = (struct sockaddr *)&pb.i.addr;
				msghdr.msg_namelen = addr_len;
				msghdr.msg_iov = &iovec;
				msghdr.msg_iovlen = 1;
				msghdr.msg_control = buf;
				msghdr.msg_controllen = sizeof( buf );
				msghdr.msg_flags = 0;
				
				errno=0;
				
				pb.i.length = recvmsg( pb.i.iif->unicast_sock, &msghdr, MSG_DONTWAIT  );
				
				if ( pb.i.length < 0  &&  ( errno == EWOULDBLOCK || errno == EAGAIN ) ) {
                                        dbgf_sys(DBGT_WARN, "sock returned %d errno %d: %s",
					    pb.i.length, errno, strerror(errno) );
					continue;
				}
						
#ifdef SO_TIMESTAMP
				for (cp = CMSG_FIRSTHDR(&msghdr); cp; cp = CMSG_NXTHDR(&msghdr, cp)) {
						
					if ( 	cp->cmsg_type == SO_TIMESTAMP && 
						cp->cmsg_level == SOL_SOCKET && 
						cp->cmsg_len >= CMSG_LEN(sizeof(struct timeval)) )  {
	
						tv_stamp = (struct timeval*)CMSG_DATA(cp);
						break;
					}
				}
#endif
				if ( tv_stamp == NULL )
					ioctl( pb.i.iif->unicast_sock, SIOCGSTAMP, &(pb.i.tv_stamp) );
				else
					timercpy( &(pb.i.tv_stamp), tv_stamp );
				
				rx_packet( &pb );
				
				if ( --selected == 0)
					goto loop4Event;
					//goto wait4Event_end;

			}
		
		}
		
loop4ActivePlugins:

		// check active plugins...
		list_for_each( list_pos, &cb_fd_list ) {
	
			struct cb_fd_node *cdn = list_entry( list_pos, struct cb_fd_node, list );
	
			if ( FD_ISSET( cdn->fd, &tmp_wait_set ) ) {
				
				FD_CLR( cdn->fd, &tmp_wait_set );
				
				(*(cdn->cb_fd_handler)) (cdn->fd); 
				
				// list might have changed, due to unregistered handlers, reiterate NOW
				//TODO: check if fd was really consumed !
				if ( --selected == 0 )
					goto loop4Event;
				
				goto loop4ActivePlugins;
			}

		}
		

		// check for new control clients...
		if ( FD_ISSET( unix_sock, &tmp_wait_set ) ) {
				
			accept_ctrl_node();
			
			if ( --selected == 0 )
				goto loop4Event;
			
		}
			
	
loop4ActiveClients:
		// check for all connected control clients...
		list_for_each( list_pos, &ctrl_list ) {
			
			struct ctrl_node *client = list_entry( list_pos, struct ctrl_node, list );
				
			if ( FD_ISSET( client->fd, &tmp_wait_set ) ) {
					
				FD_CLR( client->fd, &tmp_wait_set );
				
				//omit debugging here since event could be a closed -d4 ctrl socket 
				//which should be removed before debugging
				//dbgf_all( DBGT_INFO, "got msg from control client");
					
				handle_ctrl_node( client );
				
				--selected;
				
				// return straight because client might be removed and list might have changed.
				goto loop4ActiveClients;
			} 
		
		}

		

                if (selected) {
                        dbg_track(DBGT_WARN, "select() returned %d unhandled event(s)!! return_time %d, curr_time %d",
                                selected, return_time, bmx_time);
                }
		
		break;
	}
	
wait4Event_end:

	keyNodes_block_and_sync(0, YES);

	dbgf_all( DBGT_INFO, "end of function");
	
	return;
}

IDM_T doNowOrLater(TIME_T *nextScheduled, TIME_T interval, IDM_T now)
{

	if (((TIME_T) (*nextScheduled - (bmx_time + 1))) >= ((TIME_T) interval) || now) {

		*nextScheduled = interval +
			((((TIME_T) ((*nextScheduled + interval) - (bmx_time + 1))) >= ((TIME_T) interval)) ?
			bmx_time : *nextScheduled);

		return YES;
	} else {
		return NO;
	}
}

void init_schedule( void ) {
	gettimeofday( &start_time_tv, NULL );
        curr_tv = start_time_tv;

	upd_bmx_time( NULL );
}

void cleanup_schedule( void ) {
	

        struct task_node *tn;

        while ( (tn = list_del_head( &task_list )))
                debugFree(tn, -300082);
        
}
