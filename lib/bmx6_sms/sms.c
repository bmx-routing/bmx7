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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
//#include <json/json.h>
#include <dirent.h>
#include <sys/inotify.h>

#include "bmx.h"
#include "msg.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
//#include "ip.h"
#include "sms.h"
//#include "hna.h"


#define CODE_CATEGORY_NAME "sms"


static char *json_smsTx_dir = NULL;
static char *json_smsRx_dir = NULL;

static int extensions_fd = -1;
static int extensions_wd = -1;


static AVL_TREE(json_sms_tree, struct json_sms, name );






STATIC_FUNC
void check_for_changed_sms(void *unused)
{
        uint16_t found_sms = 0;
        uint16_t matching_sms = 0;

        struct opt_type *opt = get_option( 0, 0, ARG_SMS );
        struct opt_parent *p = NULL;
        struct json_sms * sms = NULL;
        struct avl_node *an = NULL;

        char name[MAX_JSON_SMS_NAME_LEN];
        char data[MAX_JSON_SMS_DATA_LEN + 1];

        dbgf_track(DBGT_INFO, "checking...");

        if (extensions_fd == -1) {
                task_remove(check_for_changed_sms, NULL);
                task_register(SMS_POLLING_INTERVAL, check_for_changed_sms, NULL, 300000);
        }


        while ((sms = avl_iterate_item(&json_sms_tree, &an))) {
                sms->stale = 1;
        }

        while ((p = list_iterate(&opt->d.parents_instance_list, p))) {

                int len = 0;

                memset(name, 0, sizeof (name));
                strcpy(name, p->p_val);

                int fd = -1;
                char path_name[MAX_PATH_SIZE + 20] = "";
                sprintf(path_name, "%s/%s", json_smsTx_dir, p->p_val);



                if ((fd = open(path_name, O_RDONLY, 0)) < 0) {

                        dbgf_all(DBGT_INFO, "could not open %s - %s", path_name, strerror(errno));
                        continue;

                } else if ((len = read(fd, data, sizeof (data))) < 0 || len > MAX_JSON_SMS_DATA_LEN) {

                        dbgf_sys(DBGT_ERR, "sms=%s data_len=%d too big or: %s", path_name, len, strerror(errno));
                        close(fd);
                        continue;

                } else if ((sms = avl_find_item(&json_sms_tree, name)) && sms->text_len == len && !memcmp(sms->text, data, len)) {

                        matching_sms++;
                        sms->stale = 0;

                } else {

                        if (sms) {
                                avl_remove(&json_sms_tree, sms->name, -300378);
                                debugFree(sms, -300369);
                        }

                        sms = debugMalloc(sizeof (struct json_sms) +len, -300370);
                        memset(sms, 0, sizeof (struct json_sms) +len);
                        strcpy(sms->name, name);
                        sms->text_len = len;
                        sms->stale = 0;
                        memcpy(sms->text, data, len);
                        avl_insert(&json_sms_tree, sms, -300371);

                        dbgf_track(DBGT_INFO, "new sms=%s size=%d! updating description..-", path_name, sms->text_len);
                }

                found_sms++;
        }


        if (found_sms != matching_sms || found_sms != json_sms_tree.items) {

                dbgf_all(DBGT_INFO, "sms found=%d matching=%d items=%d", found_sms, matching_sms, json_sms_tree.items);

                memset(name, 0, sizeof (name));
                while ((sms = avl_next_item(&json_sms_tree, name))) {
                        memcpy(name, sms->name, sizeof (sms->name));
                        if (sms->stale) {
                                dbgf_track(DBGT_INFO, "removed sms=%s/%s size=%d! updating description...",
                                        json_smsTx_dir, sms->name, sms->text_len);

                                avl_remove(&json_sms_tree, sms->name, -300373);
                                debugFree(sms, -300374);
                        }
                }

                my_description_changed = YES;
        }
}


STATIC_FUNC
void json_inotify_event_hook(int fd)
{
        TRACE_FUNCTION_CALL;

        dbgf_track(DBGT_INFO, "detected changes in directory: %s", json_smsTx_dir);

        assertion(-501258, (fd > -1 && fd == extensions_fd));

        int ilen = 1024;
        char *ibuff = debugMalloc(ilen, -300375);
        int rcvd;
        int processed = 0;

        while ((rcvd = read(fd, ibuff, ilen)) == 0 || rcvd == EINVAL) {

                ibuff = debugRealloc(ibuff, (ilen = ilen * 2), -300376);
                assertion(-501259, (ilen <= (1024 * 16)));
        }

        if (rcvd > 0) {

                while (processed < rcvd) {

                        struct inotify_event *ievent = (struct inotify_event *) &ibuff[processed];

                        processed += (sizeof (struct inotify_event) +ievent->len);

                        if (ievent->mask & (IN_DELETE_SELF)) {
                                dbgf_sys(DBGT_ERR, "directory %s has been removed \n", json_smsTx_dir);
                                cleanup_all(-501260);
                        }
                }

        } else {
                dbgf_sys(DBGT_ERR, "read()=%d: \n", rcvd, strerror(errno));
        }

        debugFree(ibuff, -300377);

        check_for_changed_sms(NULL);
}


STATIC_FUNC
int create_description_sms(struct tx_frame_iterator *it)
{

        struct avl_node *an = NULL;
        struct json_sms *sms;

        uint8_t *data = tx_iterator_cache_msg_ptr(it);
        uint16_t max_size = tx_iterator_cache_data_space(it);
        int pos = 0;

        if (!json_sms_tree.items)
                return TLV_TX_DATA_IGNORED;

        while ((sms = avl_iterate_item(&json_sms_tree, &an))) {

                if (pos + sizeof (struct description_msg_sms) + sms->text_len > max_size) {
                        dbgf_sys(DBGT_ERR, "Failed adding descriptionSms=%s/%s", json_smsTx_dir, sms->name);
                        continue;
                }

                struct description_msg_sms *msg = (struct description_msg_sms*) (data + pos);

                memset(msg, 0, sizeof (struct description_msg_sms));
                strcpy(msg->name, sms->name);
                msg->text_len = htons(sms->text_len);
                memcpy(msg->text, sms->text, sms->text_len);

                pos += (sizeof (struct description_msg_sms) + sms->text_len);

                dbgf_track(DBGT_INFO, "added descriptionSms=%s/%s text_len=%d total_len=%d",
                        json_smsTx_dir, sms->name, sms->text_len, pos);

        }


        return pos;
}

STATIC_FUNC
int process_description_sms(struct rx_frame_iterator *it)
{
        struct orig_node *on = it->on;
        uint8_t op = it->op;

        int pos = 0;
        int mlen;

        do {

                if (pos + (int)sizeof ( struct description_msg_sms) > it->frame_msgs_length)
                        return TLV_RX_DATA_FAILURE;

                struct description_msg_sms *sms = (struct description_msg_sms *) (it->frame_data + pos);
                mlen = sizeof ( struct description_msg_sms) +ntohs(sms->text_len);

                if (pos + mlen > it->frame_msgs_length)
                        return TLV_RX_DATA_FAILURE;

                if (validate_name_string(sms->name, sizeof (sms->name)) != SUCCESS)
                        return TLV_RX_DATA_FAILURE;

                char path_name[MAX_PATH_SIZE];
                sprintf(path_name, "%s/%s:%s", json_smsRx_dir, globalIdAsString(&on->global_id), sms->name);
                int fd;

                if (op == TLV_OP_DEL) {

                        if (remove(path_name) != 0) {
                                dbgf_sys(DBGT_ERR, "could not remove %s: %s \n", path_name, strerror(errno));
                        }

                } else if (op == TLV_OP_ADD) {


                        if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {

                                dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno));

                        } else {

                                int written = write(fd, sms->text, ntohs(sms->text_len));
                                if (written != ntohs(sms->text_len)) {
                                        dbgf_sys(DBGT_ERR, "write=%d of %d bytes to %s: %s",
                                                written, ntohs(sms->text_len), path_name, strerror(errno));
                                }
                                close(fd);
                        }
                }

        } while ((pos = pos + mlen) < it->frame_msgs_length);

        return pos;
}





STATIC_FUNC
int32_t opt_json_sms(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

        // this function is used to initialize all json directories

        static char *sms_dir = NULL;
        static char tmp_sms_dir[MAX_PATH_SIZE];
        static char tmp_sms_tx_dir[MAX_PATH_SIZE];
        static char tmp_sms_rx_dir[MAX_PATH_SIZE];

        if (initializing && !sms_dir && (cmd == OPT_CHECK || cmd == OPT_APPLY || cmd == OPT_SET_POST)) {

                assertion(-501255, (strlen(run_dir) > 3));

                sprintf(tmp_sms_dir, "%s/%s", run_dir, DEF_SMS_SUBDIR);

                if (check_dir(tmp_sms_dir, YES/*create*/, YES/*writable*/) == FAILURE)
			return FAILURE;


                sprintf(tmp_sms_rx_dir, "%s/%s", tmp_sms_dir, DEF_SMS_RX_SUBDIR);

                if (check_dir(tmp_sms_rx_dir, YES/*create*/, YES/*writable*/) == FAILURE)
                        return FAILURE;

                else if (cmd == OPT_SET_POST && rm_dir_content(tmp_sms_rx_dir) == FAILURE)
                        return FAILURE;



                sprintf(tmp_sms_tx_dir, "%s/%s", tmp_sms_dir, DEF_SMS_TX_SUBDIR);

                if (check_dir(tmp_sms_tx_dir, YES/*create*/, YES/*writable*/) == FAILURE) {

                        dbgf_sys(DBGT_ERR, "failed checking dir=%s: %s\n", tmp_sms_tx_dir, strerror(errno));
                        return FAILURE;

                } else if (1 || (extensions_fd = inotify_init()) < 0) {

                        dbg_sys(DBGT_WARN, "failed init inotify socket: %s! Using %d ms polling instead! You should enable inotify support in your kernel!",
                                strerror(errno), SMS_POLLING_INTERVAL);
                        extensions_fd = -1;

                } else if (fcntl(extensions_fd, F_SETFL, O_NONBLOCK) < 0) {

                        dbgf_sys(DBGT_ERR, "failed setting inotify non-blocking: %s", strerror(errno));
                        return FAILURE;

                } else if ((extensions_wd = inotify_add_watch(extensions_fd, tmp_sms_tx_dir,
                        IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO)) < 0) {

                        dbgf_sys(DBGT_ERR, "failed adding watch for dir=%s: %s \n", tmp_sms_tx_dir, strerror(errno));
                        return FAILURE;

                } else {

                        set_fd_hook(extensions_fd, json_inotify_event_hook, ADD);
                }

                sms_dir =  tmp_sms_dir;
                json_smsTx_dir = tmp_sms_tx_dir;
                json_smsRx_dir = tmp_sms_rx_dir;
        }



        if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

                if (!json_smsTx_dir)
                        return FAILURE;

                if (strlen(patch->p_val) >= MAX_JSON_SMS_NAME_LEN)
                        return FAILURE;

                if (validate_name_string(patch->p_val, strlen(patch->p_val) + 1) != SUCCESS)
                        return FAILURE;

        }

        static IDM_T sms_applied = NO;

        if (cmd == OPT_APPLY) {
                sms_applied = YES;
        }

        if (cmd == OPT_POST && sms_applied) {
                sms_applied = NO;

                check_for_changed_sms(NULL);
        }


        return SUCCESS;
}

static struct opt_type sms_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,ARG_SMS,	        0,  5,2,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_json_sms,
			ARG_PREFIX_FORM,"add arbitrary file-data to description"}
	
};


static void sms_cleanup( void )
{


        if (extensions_fd > -1) {

                if( extensions_wd > -1) {
                        inotify_rm_watch(extensions_fd, extensions_wd);
                        extensions_wd = -1;
                }

                set_fd_hook(extensions_fd, json_inotify_event_hook, DEL);

                close(extensions_fd);
                extensions_fd = -1;
        } else {
                task_remove(check_for_changed_sms, NULL);
        }

        while (json_sms_tree.items) {
                struct json_sms *sms = avl_first_item(&json_sms_tree);
                avl_remove(&json_sms_tree, sms->name, -300381);
                debugFree(sms, -300382);
        }

}



static int32_t sms_init( void ) {

        register_options_array(sms_options, sizeof ( sms_options), CODE_CATEGORY_NAME);

        static const struct field_format json_extension_format[] = DESCRIPTION_MSG_SMS_FORMAT;
        struct frame_handl tlv_handl;

        memset( &tlv_handl, 0, sizeof(tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_sms);
        tlv_handl.fixed_msg_size = 0;
        tlv_handl.is_relevant = 0;
        tlv_handl.name = "SMS_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_sms;
        tlv_handl.rx_frame_handler = process_description_sms;
        tlv_handl.msg_format = json_extension_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_JSON_SMS, &tlv_handl);

	return SUCCESS;
}


struct plugin* get_plugin( void ) {
	
	static struct plugin json_plugin;
	
	memset( &json_plugin, 0, sizeof ( struct plugin ) );
	

	json_plugin.plugin_name = CODE_CATEGORY_NAME;
	json_plugin.plugin_size = sizeof ( struct plugin );
        json_plugin.plugin_code_version = CODE_VERSION;
	json_plugin.cb_init = sms_init;
	json_plugin.cb_cleanup = sms_cleanup;

	return &json_plugin;
}


