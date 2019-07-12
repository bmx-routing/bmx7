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


STATIC_FUNC
int create_dsc_tlv_wg_tun(struct tx_frame_iterator *it)
{
	/* STUB */
	return 0;
}

STATIC_FUNC
int process_dsc_tlv_wg_tun(struct rx_frame_iterator *it)
{
	/* STUB */
	return 0;
}


int gwg_tundev_init(void)
{

	return 0;
}

///* TODO: Place them around
int wg_CnC(void)
{
	wg_peer new_peer = {
		.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS
	};

	wg_device new_device = {
		.name = "wgtest0",
		.listen_port = 1234,
		.flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT,
		.first_peer = &new_peer,
		.last_peer = &new_peer
	};

	// TODO PLACE THEM AROUND
	wg_key temp_private_key;
	wg_generate_private_key(temp_private_key);
	wg_generate_public_key(new_peer.public_key, temp_private_key);
	wg_generate_private_key(new_device.private_key);


	if (wg_add_device(new_device.name) < 0) {
		perror("Unable to add device");
		exit(1);
	}

	if (wg_set_device(&new_device) < 0) {
		perror("Unable to set device");
		exit(1);
	}

	//list_devices();

	if (wg_del_device(new_device.name) < 0) {
		perror("Unable to delete device");
		exit(1);
	}

	return 0;
}
//*/


STATIC_FUNC
void wg_tun_cleanup(void)
{
	/* Harry TODO */
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
	tlv_handl.tx_frame_handler = create_dsc_tlv_wg_tun;
	tlv_handl.rx_msg_handler = process_dsc_tlv_wg_tun;
	tlv_handl.msg_format = wg_tun_adv_format;
	register_frame_handler(description_tlv_db, BMX_DSC_TLV_WG_TUN, &tlv_handl);

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
