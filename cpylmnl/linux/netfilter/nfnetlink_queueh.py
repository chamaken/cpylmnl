# -*- coding: utf-8 -*-

import ctypes

import cpylmnl.linux.netlinkh as netlink
from cpylmnl.nlstruct import NLStructure

# enum nfqnl_msg_types
class NfqnlMsgTypes(object):
    NFQNL_MSG_PACKET		= 0 # packet from kernel to userspace
    NFQNL_MSG_VERDICT		= 1 # verdict from userspace to kernel
    NFQNL_MSG_CONFIG		= 2 # connect to a particular queue 
    NFQNL_MSG_VERDICT_BATCH	= 3 # batchv from userspace to kernel
    NFQNL_MSG_MAX		= 4
NFQNL_MSG_PACKET	= NfqnlMsgTypes.NFQNL_MSG_PACKET
NFQNL_MSG_VERDICT	= NfqnlMsgTypes.NFQNL_MSG_VERDICT
NFQNL_MSG_CONFIG	= NfqnlMsgTypes.NFQNL_MSG_CONFIG
NFQNL_MSG_VERDICT_BATCH	= NfqnlMsgTypes.NFQNL_MSG_VERDICT_BATCH
NFQNL_MSG_MAX		= NfqnlMsgTypes.NFQNL_MSG_MAX

class NfqnlMsgPacketHdr(NLStructure):
    """struct nfqnl_msg_packet_hdr
    """
    _fields_ = [("packet_id",	ctypes.c_uint32), # unique ID of packet in queue
                ("hw_protocol", ctypes.c_uint16), # hw protocol (network order)
                ("hook",        ctypes.c_uint8)]  # netfilter hook

class NfqnlMsgPacketHw(NLStructure):
    """struct nfqnl_msg_packet_hw
    """
    _fields_ = [("hw_addrlen",  ctypes.c_uint16),
                ("_pad",        ctypes.c_uint16),
                ("hw_addr",     (ctypes.c_ubyte * 8))]

class NfqnlMsgPacketTimestamp(NLStructure):
    """struct nfqnl_msg_packet_timestamp
    """
    _fields_ = [("sec",         ctypes.c_uint64),
                ("usec",	ctypes.c_uint64)]

class NfqnlVlanAttr(object):
    """enum nfqnl_vlan_attr
    """
    NFQA_VLAN_UNSPEC	= 0
    NFQA_VLAN_PROTO	= 1 # __be16 skb vlan_proto
    NFQA_VLAN_TCI	= 2 # __be16 skb htons(vlan_tci)
    __NFQA_VLAN_MAX	= 3
    NFQA_VLAN_MAX	= __NFQA_VLAN_MAX - 1
NFQA_VLAN_UNSPEC	= NfqnlVlanAttr.NFQA_VLAN_UNSPEC
NFQA_VLAN_PROTO		= NfqnlVlanAttr.NFQA_VLAN_PROTO
NFQA_VLAN_TCI		= NfqnlVlanAttr.NFQA_VLAN_TCI
NFQA_VLAN_MAX		= NfqnlVlanAttr.NFQA_VLAN_MAX


# enum nfqnl_attr_type
class NfqnlAttrType(object):
    NFQA_UNSPEC			= 0  # 
    NFQA_PACKET_HDR		= 1  # 
    NFQA_VERDICT_HDR		= 2  # 
    NFQA_MARK			= 3  # nfqnl_msg_verdict_hrd
    NFQA_TIMESTAMP		= 4  # __u32 nfmark
    NFQA_IFINDEX_INDEV		= 5  # nfqnl_msg_packet_timestamp
    NFQA_IFINDEX_OUTDEV		= 6  # __u32 ifindex
    NFQA_IFINDEX_PHYSINDEV	= 7  # __u32 ifindex
    NFQA_IFINDEX_PHYSOUTDEV	= 8  # __u32 ifindex
    NFQA_HWADDR			= 9  # __u32 ifindex
    NFQA_PAYLOAD		= 10 # nfqnl_msg_packet_hw
    NFQA_CT			= 11 # opaque data payload
    NFQA_CT_INFO		= 12 # nf_conntrack_netlink.h
    NFQA_CAP_LEN		= 13 # enum ip_conntrack_info
    NFQA_SKB_INFO		= 14 # __u32 length of captured packet
    NFQA_EXP			= 15 # __u32 skb meta information
    NFQA_UID			= 16 # __u32 sk uid
    NFQA_GID			= 17 # __u32 sk gid
    NFQA_SECCTX			= 18 # security context string
    NFQA_VLAN			= 19 # nested attribute: packet vlan info
    NFQA_L2HDR			= 20 # full L2 header
    __NFQA_MAX			= 21 # nf_conntrack_netlink.h
    NFQA_MAX			= (__NFQA_MAX - 1)
NFQA_UNSPEC		= NfqnlAttrType.NFQA_UNSPEC
NFQA_PACKET_HDR		= NfqnlAttrType.NFQA_PACKET_HDR
NFQA_VERDICT_HDR	= NfqnlAttrType.NFQA_VERDICT_HDR
NFQA_MARK		= NfqnlAttrType.NFQA_MARK
NFQA_TIMESTAMP		= NfqnlAttrType.NFQA_TIMESTAMP
NFQA_IFINDEX_INDEV	= NfqnlAttrType.NFQA_IFINDEX_INDEV
NFQA_IFINDEX_OUTDEV	= NfqnlAttrType.NFQA_IFINDEX_OUTDEV
NFQA_IFINDEX_PHYSINDEV	= NfqnlAttrType.NFQA_IFINDEX_PHYSINDEV
NFQA_IFINDEX_PHYSOUTDEV	= NfqnlAttrType.NFQA_IFINDEX_PHYSOUTDEV
NFQA_HWADDR		= NfqnlAttrType.NFQA_HWADDR
NFQA_PAYLOAD		= NfqnlAttrType.NFQA_PAYLOAD
NFQA_CT			= NfqnlAttrType.NFQA_CT
NFQA_CT_INFO		= NfqnlAttrType.NFQA_CT_INFO
NFQA_CAP_LEN		= NfqnlAttrType.NFQA_CAP_LEN
NFQA_SKB_INFO		= NfqnlAttrType.NFQA_SKB_INFO
NFQA_EXP		= NfqnlAttrType.NFQA_EXP
NFQA_UID		= NfqnlAttrType.NFQA_UID
NFQA_GID		= NfqnlAttrType.NFQA_GID
NFQA_SECCTX		= NfqnlAttrType.NFQA_SECCTX
NFQA_VLAN		= NfqnlAttrType.NFQA_VLAN
NFQA_L2HDR		= NfqnlAttrType.NFQA_L2HDR
NFQA_MAX		= NfqnlAttrType.NFQA_MAX

class NfqnlMsgVerdictHdr(NLStructure):
    """struct nfqnl_msg_verdict_hdr
    """
    _fields_ = [("verdict",     ctypes.c_uint32),
                ("id",          ctypes.c_uint32)]

# enum nfqnl_msg_config_cmds
class NfqnlMsgConfigCmds(object):
    NFQNL_CFG_CMD_NONE		= 0
    NFQNL_CFG_CMD_BIND		= 1
    NFQNL_CFG_CMD_UNBIND	= 2
    NFQNL_CFG_CMD_PF_BIND	= 3
    NFQNL_CFG_CMD_PF_UNBIND	= 4
NFQNL_CFG_CMD_NONE	= NfqnlMsgConfigCmds.NFQNL_CFG_CMD_NONE
NFQNL_CFG_CMD_BIND	= NfqnlMsgConfigCmds.NFQNL_CFG_CMD_BIND
NFQNL_CFG_CMD_UNBIND	= NfqnlMsgConfigCmds.NFQNL_CFG_CMD_UNBIND
NFQNL_CFG_CMD_PF_BIND	= NfqnlMsgConfigCmds.NFQNL_CFG_CMD_PF_BIND
NFQNL_CFG_CMD_PF_UNBIND	= NfqnlMsgConfigCmds.NFQNL_CFG_CMD_PF_UNBIND

class NfqnlMsgConfigCmd(NLStructure):
    """struct nfqnl_msg_config_cmd
    """
    _fields_ = [("command",     ctypes.c_uint8),  # nfqnl_msg_config_cmds
                ("_pad",        ctypes.c_uint8),
                ("pf",          ctypes.c_uint16)] # AF_xxx for PF_[UN]BIND

# enum nfqnl_config_mode
class NfqnlConfigMode(object):
    NFQNL_COPY_NONE	= 0
    NFQNL_COPY_META	= 1
    NFQNL_COPY_PACKET	= 2
NFQNL_COPY_NONE		= NfqnlConfigMode.NFQNL_COPY_NONE
NFQNL_COPY_META		= NfqnlConfigMode.NFQNL_COPY_META
NFQNL_COPY_PACKET	= NfqnlConfigMode.NFQNL_COPY_PACKET

class NfqnlMsgConfigParams(NLStructure):
    """struct nfqnl_msg_config_params
    """
    _fields_ = [("copy_range",  ctypes.c_uint32),
                ("copy_mode",   ctypes.c_uint8)]  # enum nfqnl_config_mode

# enum nfqnl_attr_config
class NfqnlAttrConfig(object):
    NFQA_CFG_UNSPEC		= 0
    NFQA_CFG_CMD		= 1 # nfqnl_msg_config_cmd
    NFQA_CFG_PARAMS		= 2 # nfqnl_msg_config_params
    NFQA_CFG_QUEUE_MAXLEN	= 3 # __u32
    NFQA_CFG_MASK		= 4 # identify which flags to change
    NFQA_CFG_FLAGS		= 5 # value of these flags (__u32)
    __NFQA_CFG_MAX		= 6 # 
    NFQA_CFG_MAX		= (__NFQA_CFG_MAX-1)
NFQA_CFG_UNSPEC		= NfqnlAttrConfig.NFQA_CFG_UNSPEC
NFQA_CFG_CMD		= NfqnlAttrConfig.NFQA_CFG_CMD
NFQA_CFG_PARAMS		= NfqnlAttrConfig.NFQA_CFG_PARAMS
NFQA_CFG_QUEUE_MAXLEN	= NfqnlAttrConfig.NFQA_CFG_QUEUE_MAXLEN
NFQA_CFG_MASK		= NfqnlAttrConfig.NFQA_CFG_MASK
NFQA_CFG_FLAGS		= NfqnlAttrConfig.NFQA_CFG_FLAGS
NFQA_CFG_MAX		= NfqnlAttrConfig.NFQA_CFG_MAX

# Flags for NFQA_CFG_FLAGS
NFQA_CFG_F_FAIL_OPEN	= (1 << 0)
NFQA_CFG_F_CONNTRACK	= (1 << 1)
NFQA_CFG_F_GSO		= (1 << 2)
NFQA_CFG_F_UID_GID	= (1 << 3)
NFQA_CFG_F_SECCTX	= (1 << 4)
NFQA_CFG_F_MAX		= (1 << 5)

# flags for NFQA_SKB_INFO
# packet appears to have wrong checksums, but they are ok
NFQA_SKB_CSUMNOTREADY		= (1 << 0)
# packet is GSO (i.e., exceeds device mtu)
NFQA_SKB_GSO			= (1 << 1)
# csum not validated (incoming device doesn't support hw checksum, etc.)
NFQA_SKB_CSUM_NOTVERIFIED	= (1 << 2)
