#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <asm/types.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <endian.h>

#include <sys/ioctl.h>
//#include <net/if.h>

//#include <linux/if_tun.h> /* TUNSETPERSIST, ... */
//#include <linux/if.h>     /* ifr_if, ifr_tun */
#include <fcntl.h>        /* open(), O_RDWR */
#include <linux/ip.h>
#include <netinet/ip6.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "ip.h"
#include "plugin.h"
#include "prof.h"
#include "hna.h"
#include "tun.h"
#include "tools.h"
#include "iptools.h"
#include "schedule.h"
#include "allocate.h"

#include "wireguard.h"
#include "wg_tun.h"

#define CODE_CATEGORY_NAME "wg_tun"

wg_key my_wg_private_key;
wg_key my_wg_public_key;

#define DEF_AUTO_WG_TUN_PREFIX  "fd77::/16"
struct net_key my_wg_tun_addr;

wg_peer my_wg_peer = {
	.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS
};

wg_device my_wg_device = {
	.name = "wgtest0",
	.listen_port = 1234,
	.flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT,
	.first_peer = &my_wg_peer,
	.last_peer = &my_wg_peer
};

STATIC_FUNC
int create_dsc_tlv_wg_tun(struct tx_frame_iterator *it)
{
	/*
	 * From this iterator we are able to access the memory
	 * giving the address to adv and then write to it our public
	 */
	struct dsc_msg_wg_tun *adv = (struct dsc_msg_wg_tun *) tx_iterator_cache_msg_ptr(it);
	memcpy(adv->public_key, my_wg_public_key, sizeof(my_wg_public_key));

	/*
	 Calculate the wg_tun_addr and add it to the wg_description
	 */
	assertion(-500000, myKey != NULL);
	my_wg_tun_addr.ip = create_crypto_IPv6(&my_wg_tun_addr, &myKey->kHash);
	adv->wg_tun_addr = my_wg_tun_addr.ip;
	adv->wg_tun_addr_prefix_len = my_wg_tun_addr.mask;
	return sizeof(struct dsc_msg_wg_tun);
}

STATIC_FUNC
int process_dsc_tlv_wg_tun(struct rx_frame_iterator *it)
{

	if (it->dcOp->kn == myKey)
		return it->f_msgs_len;

	for (int16_t frm_msg = 0; frm_msg < it->f_msgs_fixed; frm_msg++) {

		/*
		 * Map the advertizement with the data of the messages of the frame given by the iterator
		 */
		struct dsc_msg_wg_tun *adv = &(((struct dsc_msg_wg_tun *) (it->f_data))[frm_msg]);

		if (it->op == TLV_OP_DEL) {

			if (wg_del_device(my_wg_device.name) < 0) {
				dbgf_sys(DBGT_ERR,"Unable to delete device");
			}

		} else if (it->op == TLV_OP_TEST) {
			if (adv->wg_tun_addr_prefix_len != my_wg_tun_addr.mask)
				return TLV_RX_DATA_FAILURE;
			if (!is_ip_net_equal(&my_wg_tun_addr.ip, &adv->wg_tun_addr, my_wg_tun_addr.mask, my_wg_tun_addr.af) )
				return TLV_RX_DATA_FAILURE;
			if (!is_ip_valid(&adv->wg_tun_addr, AF_INET6))
				return TLV_RX_DATA_FAILURE;
			if(is_ip_net_equal(&adv->wg_tun_addr, &IP6_LINKLOCAL_UC_PREF, IP6_LINKLOCAL_UC_PLEN, AF_INET6))
				return TLV_RX_DATA_FAILURE;
			if (verify_crypto_ip6_suffix(&adv->wg_tun_addr, my_wg_tun_addr.mask, &it->dcOp->kn->kHash) != SUCCESS)
				return TLV_RX_DATA_FAILURE;

		} else if (it->op == TLV_OP_NEW) {

			memcpy(my_wg_peer.public_key, adv->public_key, sizeof(my_wg_peer.public_key));
			memcpy(my_wg_device.private_key, my_wg_private_key, sizeof(my_wg_private_key));

			if (wg_add_device(my_wg_device.name) < 0) {
				dbgf_sys(DBGT_ERR, "Unable to add device");
				assertion(-500000, 0);
			}

			if (wg_set_device(&my_wg_device) < 0) {
				dbgf_sys(DBGT_ERR, "Unable to set device");
				assertion(-500000, 0);
			}
			assertion(-500000, 1);
		}
	}
	/* STUB */

	return it->f_msgs_len;
}



STATIC_FUNC
void wg_tun_cleanup(void)
{
	memset(my_wg_private_key, 0, sizeof(my_wg_private_key));
}

STATIC_FUNC
int32_t wg_tun_init(void)
{
	/* Initialize tunnel */
	static const struct field_format wg_tun_adv_format[] = DESCRIPTION_MSG_WG_TUN_ADV_FORMAT;


	/* Message handler declared in msg.h */
	struct frame_handl tlv_handl;
	memset(&tlv_handl, 0, sizeof(tlv_handl));

	/* Register a handler for  DSC_WG_TUN */
	tlv_handl.name = "DSC_WG_TUN";
	tlv_handl.min_msg_size= sizeof(struct dsc_msg_wg_tun);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;

	tlv_handl.tx_frame_handler = create_dsc_tlv_wg_tun;
	tlv_handl.rx_msg_handler = process_dsc_tlv_wg_tun;
	tlv_handl.msg_format = wg_tun_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_WG_TUN, &tlv_handl);

	wg_generate_private_key(my_wg_private_key);
	wg_generate_public_key(my_wg_public_key, my_wg_private_key);
	
	my_wg_tun_addr = ZERO_NET6_KEY;
	str2netw(DEF_AUTO_WG_TUN_PREFIX, &my_wg_tun_addr.ip, NULL, &my_wg_tun_addr.mask, &my_wg_tun_addr.af, NO);
	assertion(-500000, my_wg_tun_addr.mask=16);

	return SUCCESS;
}

/* Register Plugin and initialize */
struct plugin* get_plugin(void)
{
	static struct plugin wg_tun_plugin;

	memset(&wg_tun_plugin, 0, sizeof(struct plugin));

	/* Assign Attributes */
	wg_tun_plugin.plugin_name = CODE_CATEGORY_NAME;
	wg_tun_plugin.plugin_size = sizeof(struct plugin);

	/* Init */
	wg_tun_plugin.cb_init = wg_tun_init;

	/* Cleanup */
	wg_tun_plugin.cb_cleanup = wg_tun_cleanup;

	return &wg_tun_plugin;
}
