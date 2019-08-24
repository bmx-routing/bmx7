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

// Hardcoded autoconfigured IPv6 address prefix equivalent to fd70 -- 2 Bytes
#define DEF_AUTO_WG_TUN_PREFIX  "fd77::/16"
struct net_key my_wg_tun_addr;

wg_device my_wg_device = {
	.name = "wgBmx7",
	.listen_port = 1234,
	.flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT
		| WGDEVICE_HAS_PUBLIC_KEY | WGDEVICE_REPLACE_PEERS,
	.first_peer = NULL,
	.last_peer = NULL
};

/* Create wg node's advertised values */
STATIC_FUNC
int create_dsc_tlv_wg_tun(struct tx_frame_iterator *it)
{
	/*
	 * From this iterator we are able to access the memory
	 * giving the address to adv and then write to it our public
	 */
	struct dsc_msg_wg_tun *adv = (struct dsc_msg_wg_tun *) tx_iterator_cache_msg_ptr(it);

	memcpy(adv->public_key, my_wg_device.public_key, sizeof(wg_key));

	/*
	 Calculate the wg_tun_addr and add it to the wg_description
	 */
	assertion(-500000, myKey != NULL);

	// Create IPv6 address based on the static address and 14 bytes of key-hash
	my_wg_tun_addr.ip = create_crypto_IPv6(&my_wg_tun_addr, &myKey->kHash);

	// Assign values to the advertisement given memory space
	adv->wg_tun_addr = my_wg_tun_addr.ip;
	adv->wg_tun_addr_prefix_len = my_wg_tun_addr.mask;

	adv->udp_port = my_wg_device.listen_port;

	return sizeof(struct dsc_msg_wg_tun);
}

bool peer_exists (wg_device *device, wg_key public_key)
{
	wg_peer *peer;
	uint8_t flag = 0;
	wg_for_each_peer(device, peer) {
		if(peer->public_key == public_key)
			flag = 1;
	}
	return flag;
}

/*
 * Process other wg_tun nodes (fd77:* /16) received advertisements
 */
STATIC_FUNC
int process_dsc_tlv_wg_tun(struct rx_frame_iterator *it)
{

	// Exclude this nodes's advertised properties handling
	if (it->dcOp->kn == myKey)
		return it->f_msgs_len;

	// For every frame's messages invoke operation codes (DEL|ADD|TEST)
	for (int16_t frm_msg = 0; frm_msg < it->f_msgs_fixed; frm_msg++) {

		/*
		 * Map the advertisement with the data of the messages of the frame given by the iterator
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

			// Check if peer already exists
			if(!peer_exists(&my_wg_device, adv->public_key))
			{
				// Create peer's allowed_ip struct
				wg_allowedip new_peer_ip ={
					.family = AF_INET6,
					.ip6 = adv->wg_tun_addr,
					.cidr = adv->wg_tun_addr_prefix_len,
					.next_allowedip = NULL
				};

				// Create peer based on adv
				wg_peer new_peer = {
					.flags = WGPEER_REPLACE_ALLOWEDIPS | WGPEER_HAS_PUBLIC_KEY,
					//.endpoint = adv->wg_tun_addr,
					.first_allowedip = &new_peer_ip,
					.last_allowedip = &new_peer_ip,
					.next_peer = my_wg_device.first_peer
				};
				memcpy(new_peer.public_key, adv->public_key, sizeof(new_peer.public_key));

				// Inform of new peer
				wg_key_b64_string key;
				wg_key_to_base64(key, new_peer.public_key);
				dbgf_sys(DBGT_INFO, "Added peer with identifier: %s", key);

				// Add peer as first peer
				my_wg_device.first_peer = &new_peer;
			}

			assertion(-500000, 1);
		}
	}

	/* ?? */
	return it->f_msgs_len;
}

struct wg_tun_status {
	wg_key private_key;
	wg_key public_key;
	IP6_T unique_bmx7_wg_addr;
	uint8_t mask;
	uint16_t udp_port;
};

static const struct field_format wg_tun_status_format[] = {
	FIELD_FORMAT_INIT(FIELD_TYPE_STRING_BINARY, wg_tun_status, private_key,			1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_STRING_BINARY, wg_tun_status, public_key,			1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_IPX6,			wg_tun_status, unique_bmx7_wg_addr, 1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,			wg_tun_status, mask,				1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_INIT(FIELD_TYPE_UINT,			wg_tun_status, udp_port,			1, FIELD_RELEVANCE_HIGH),
	FIELD_FORMAT_END
};

static int32_t wg_tun_status_creator(struct status_handl *handl, void *data)
{
	int32_t status_size = sizeof(struct wg_tun_status);
//	struct wg_tun_status *status = (struct wg_tun_status *) (handl->data = debugRealloc(handl->data, status_size, -300000));
//	memset(status, 0, status_size);
	return 0;
}

STATIC_FUNC
void wg_tun_cleanup(void)
{
	//memset(my_wg_private_key, 0, sizeof(my_wg_private_key));
	//wg_free_device(&my_wg_device);
	wg_del_device(my_wg_device.name);
}

void init_wg_device(wg_device *wg_device)
{
	// First make sure device doesn't already exist
	wg_tun_cleanup();

	wg_generate_private_key(wg_device->private_key);
	wg_generate_public_key(wg_device->public_key, wg_device->private_key);

	/* Initialize device with name */
	//printf("%s", my_wg_device.name);
	//wg_list_device_names();


	if (wg_add_device(wg_device->name) < 0) {
		//dbgf_sys(DBGT_ERR, "Unable to add device");
		perror("Unable to add dev");
		//assertion(-500000, 0);
	}

	// Log creation of device
	wg_key_b64_string key;
	wg_key_to_base64(key, wg_device->private_key);
	dbgf_sys(DBGT_INFO, "Successfully created wg device:%s \twith private key: %s", wg_device->name, key);

	// Set device with properties
	if (wg_set_device(wg_device) < 0) {
		//dbgf_sys(DBGT_ERR, "Unable to set device");
		perror("Unable to set dev");
		//assertion(-500000, 0);
	}

	//printf("HELLO\n");
}

/* Plugin initialization and parsing of handling fucntions and properties */
STATIC_FUNC
int32_t wg_tun_init(void)
{
	/* Initialize tunnel */
	static const struct field_format wg_tun_adv_format[] = DESCRIPTION_MSG_WG_TUN_ADV_FORMAT;


	/* Message handler declared in msg.h */
	struct frame_handl tlv_handl;
	memset(&tlv_handl, 0, sizeof(tlv_handl));

	/* Register a handler for  DSC_WG_TUN taking care of the frame properties */
	tlv_handl.name = "DSC_WG_TUN";
	tlv_handl.min_msg_size= sizeof(struct dsc_msg_wg_tun);
	tlv_handl.fixed_msg_size = 1;
	tlv_handl.dextCompression = (int32_t*) & dflt_fzip;
	tlv_handl.dextReferencing = (int32_t*) & fref_dflt;

	tlv_handl.tx_frame_handler = create_dsc_tlv_wg_tun;
	tlv_handl.rx_msg_handler = process_dsc_tlv_wg_tun;
	tlv_handl.msg_format = wg_tun_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_WG_TUN, &tlv_handl);

	/* Generate public and private key based on global structs */
	init_wg_device(&my_wg_device);

	/*  */
	my_wg_tun_addr = ZERO_NET6_KEY;
	str2netw(DEF_AUTO_WG_TUN_PREFIX, &my_wg_tun_addr.ip, NULL, &my_wg_tun_addr.mask, &my_wg_tun_addr.af, NO);
	assertion(-500000, my_wg_tun_addr.mask=16);

	register_status_handl(sizeof(struct wg_tun_status), 1, wg_tun_status_format, ARG_TUNS, wg_tun_status_creator);

	return SUCCESS;
}

/* Register Plugin */
struct plugin* get_plugin(void)
{
	static struct plugin wg_tun_plugin;
	memset(&wg_tun_plugin, 0, sizeof(struct plugin));

	/* Assign Properties */
	wg_tun_plugin.plugin_name = CODE_CATEGORY_NAME;
	wg_tun_plugin.plugin_size = sizeof(struct plugin);

	/* Init */
	wg_tun_plugin.cb_init = wg_tun_init;

	/* Cleanup */
	wg_tun_plugin.cb_cleanup = wg_tun_cleanup;

	return &wg_tun_plugin;
}
