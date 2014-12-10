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

/*
 * Alternative cryptographic libraries are:
 * libtomcrypt and gcrypt
 */

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if.h>

//#define DEF_PERSISTENT_PATH "/etc/bmx6"
#define DEF_TRUST_DIR_POLLING_INTERVAL 5000

#define DEF_TRUSTED_NODES_DIR "/etc/bmx6/trustedNodes"
#define ARG_TRUSTED_NODES_DIR "trustedNodesDir"

#define DEF_SUPPORTED_NODES_DIR "/etc/bmx6/supportedNodes"
#define ARG_SUPPORTED_NODES_DIR "supportedNodesDir"

#define ARG_KEY_PATH "keyPath"
#define DEF_KEY_PATH "/etc/bmx6/rsa.der"

#define ARG_DESC_SIGN "descSignLen"
#define MIN_DESC_SIGN 512
#define MAX_DESC_SIGN 4096
#define DEF_DESC_SIGN 3072
#define HLP_DESC_SIGN "sign own descriptions with given RSA key length"


#define ARG_DESC_VERIFY "descVerificationLen"
#define MIN_DESC_VERIFY 512
#define MAX_DESC_VERIFY 4096
#define DEF_DESC_VERIFY 4096
#define HLP_DESC_VERIFY "verify description signatures up-to given RSA key length"

#define ARG_PACKET_SIGN "packetSignLen"
#define MIN_PACKET_SIGN 0
#define MAX_PACKET_SIGN 2048
#define DEF_PACKET_SIGN 896
#define HLP_PACKET_SIGN "sign outgoing packets with given RSA key length"
extern int32_t packetSigning;


// http://my.opera.com/securitygroup/blog/2009/09/29/512-bit-rsa-key-breaking-developments
// assuming 70 days to crack RSA512 keys (2009!) with a single dual-core machine,
// means can be cracked in
// ~6000 secs with ~1000 machines, or
// ~600 secs with ~10000 machines, or 
// ~60 secs with ~100000 machines
// However, this would be for RSA512 but RSA896 is used by default!!:
#define MIN_PACKET_SIGN_LT (60)    // one minute, needs ~100000 machines to crack RSA512 before end of life
#define DEF_PACKET_SIGN_LT (6000)   // 100 minutes, needs ~1000 machines to crack RSA512 before end of life
#define MAX_PACKET_SIGN_LT (REGISTER_TASK_TIMEOUT_MAX/1000)
#define ARG_PACKET_SIGN_LT "packetSignLifetime"



#define ARG_PACKET_VERIFY "packetVerification"
#define MIN_PACKET_VERIFY 0
#define MAX_PACKET_VERIFY 4096
#define DEF_PACKET_VERIFY 1024
#define HLP_PACKET_VERIFY "verify incoming packet signature up-to given RSA key length"


extern CRYPTKEY_T *my_PubKey;
extern CRYPTKEY_T *my_PktKey;


#define DESCRIPTION_MSG_PUBKEY_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(struct dsc_msg_pubkey),     1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "key" }, \
FIELD_FORMAT_END }

struct dsc_msg_pubkey {
        uint8_t type;
        uint8_t key[];
} __attribute__((packed));


#define DESCRIPTION_MSG_SIGNATURE_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint8_t),                   1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "signature" }, \
FIELD_FORMAT_END }

struct dsc_msg_signature {
        uint8_t type;
        uint8_t signature[];
} __attribute__((packed));

#define FRAME_MSG_SIGNATURE_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 8*sizeof(CRYPTSHA1_T),               1, FIELD_RELEVANCE_HIGH,  "dhash"},  \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint8_t),                   1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "signature" }, \
FIELD_FORMAT_END }

struct frame_msg_signature {
    CRYPTSHA1_T dhash;
    uint8_t type;
    uint8_t signature[];
} __attribute__((packed));

#define DESCRIPTION_MSG_SHA_FORMAT { \
{FIELD_TYPE_UINT,          -1, 32,                        0, FIELD_RELEVANCE_HIGH,  "dataLen"}, \
{FIELD_TYPE_STRING_BINARY, -1, 8*sizeof(SHA1_T),          1, FIELD_RELEVANCE_HIGH,  "dataSha"}, \
FIELD_FORMAT_END }

struct dsc_msg_sha {
        uint32_t dataLen;
        CRYPTSHA1_T dataSha;
} __attribute__((packed));



#define DESCRIPTION_MSG_TRUST_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 8*sizeof(CRYPTSHA1_T),               1, FIELD_RELEVANCE_HIGH,  "globalId"},  \
{FIELD_TYPE_UINT,          -1, 8*sizeof(uint16_t),                   1, FIELD_RELEVANCE_HIGH,  "reserved"}, \
FIELD_FORMAT_END }

struct dsc_msg_trust {
    CRYPTSHA1_T globalId;
    uint16_t reserved;
} __attribute__((packed));

void free_internalNeighId(OGM_DEST_T ini);
OGM_DEST_T allocate_internalNeighId(struct neigh_node *nn);

uint32_t *init_neighTrust(struct orig_node *on);
IDM_T verify_neighTrust(struct orig_node *on, struct neigh_node *neigh);

IDM_T supported_pubkey( CRYPTSHA1_T *pkhash );
IDM_T setted_pubkey(struct dhash_node *dhn, uint8_t type, GLOBAL_ID_T *globalId);

int process_signature(int32_t sig_msg_length, struct dsc_msg_signature *sig_msg, uint8_t *desc_frame, int32_t desc_frame_len, struct dsc_msg_pubkey *pkey_msg);

void init_sec( void );
void cleanup_sec( void );
