# -*- coding: utf-8 -*-

import ctypes

import cpylmnl.linux.netlinkh as netlink
from cpylmnl.nlstruct import NLStructure
try:
    from enum import Enum
except ImportError:
    Enum = object


# enum nfqnl_msg_types
class NfqnlMsgTypes(Enum):
    NFQNL_MSG_PACKET		= 0 # packet from kernel to userspace
    NFQNL_MSG_VERDICT		= 1 # verdict from userspace to kernel
    NFQNL_MSG_CONFIG		= 2 # connect to a particular queue 
    NFQNL_MSG_VERDICT_BATCH	= 3 # batchv from userspace to kernel
    NFQNL_MSG_MAX		= 4
NFQNL_MSG_PACKET	= 0
NFQNL_MSG_VERDICT	= 1
NFQNL_MSG_CONFIG	= 2
NFQNL_MSG_VERDICT_BATCH	= 3
NFQNL_MSG_MAX		= 4

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

# enum nfqnl_attr_type
class NfqnlAttrType(Enum):
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
    __NFQA_MAX			= 16 # nf_conntrack_netlink.h
    NFQA_MAX			= (__NFQA_MAX - 1)
NFQA_UNSPEC		= 0
NFQA_PACKET_HDR		= 1
NFQA_VERDICT_HDR	= 2
NFQA_MARK		= 3
NFQA_TIMESTAMP		= 4
NFQA_IFINDEX_INDEV	= 5
NFQA_IFINDEX_OUTDEV	= 6
NFQA_IFINDEX_PHYSINDEV	= 7
NFQA_IFINDEX_PHYSOUTDEV	= 8
NFQA_HWADDR		= 9
NFQA_PAYLOAD		= 10
NFQA_CT			= 11
NFQA_CT_INFO		= 12
NFQA_CAP_LEN		= 13
NFQA_SKB_INFO		= 14
NFQA_EXP		= 15
__NFQA_MAX		= 16
NFQA_MAX		= (__NFQA_MAX - 1)

class NfqnlMsgVerdictHdr(NLStructure):
    """struct nfqnl_msg_verdict_hdr
    """
    _fields_ = [("verdict",     ctypes.c_uint32),
                ("id",          ctypes.c_uint32)]

# enum nfqnl_msg_config_cmds
class NfqnlMsgConfigCmds(Enum):
    NFQNL_CFG_CMD_NONE		= 0
    NFQNL_CFG_CMD_BIND		= 1
    NFQNL_CFG_CMD_UNBIND	= 2
    NFQNL_CFG_CMD_PF_BIND	= 3
    NFQNL_CFG_CMD_PF_UNBIND	= 4
NFQNL_CFG_CMD_NONE	= 0
NFQNL_CFG_CMD_BIND	= 1
NFQNL_CFG_CMD_UNBIND	= 2
NFQNL_CFG_CMD_PF_BIND	= 3
NFQNL_CFG_CMD_PF_UNBIND	= 4

class NfqnlMsgConfigCmd(NLStructure):
    """struct nfqnl_msg_config_cmd
    """
    _fields_ = [("command",     ctypes.c_uint8),  # nfqnl_msg_config_cmds
                ("_pad",        ctypes.c_uint8),
                ("pf",          ctypes.c_uint16)] # AF_xxx for PF_[UN]BIND

# enum nfqnl_config_mode
class NfqnlConfigMode(Enum):
    NFQNL_COPY_NONE	= 0
    NFQNL_COPY_META	= 1
    NFQNL_COPY_PACKET	= 2
NFQNL_COPY_NONE		= 0
NFQNL_COPY_META		= 1
NFQNL_COPY_PACKET	= 2

class NfqnlMsgConfigParams(NLStructure):
    """struct nfqnl_msg_config_params
    """
    _fields_ = [("copy_range",  ctypes.c_uint32),
                ("copy_mode",   ctypes.c_uint8)]  # enum nfqnl_config_mode

# enum nfqnl_attr_config
class NfqnlAttrConfig(Enum):
    NFQA_CFG_UNSPEC		= 0
    NFQA_CFG_CMD		= 1 # nfqnl_msg_config_cmd
    NFQA_CFG_PARAMS		= 2 # nfqnl_msg_config_params
    NFQA_CFG_QUEUE_MAXLEN	= 3 # __u32
    NFQA_CFG_MASK		= 4 # identify which flags to change
    NFQA_CFG_FLAGS		= 5 # value of these flags (__u32)
    __NFQA_CFG_MAX		= 6 # 
    NFQA_CFG_MAX		= (__NFQA_CFG_MAX-1)
NFQA_CFG_UNSPEC		= 0
NFQA_CFG_CMD		= 1
NFQA_CFG_PARAMS		= 2
NFQA_CFG_QUEUE_MAXLEN	= 3
NFQA_CFG_MASK		= 4
NFQA_CFG_FLAGS		= 5
__NFQA_CFG_MAX		= 6
NFQA_CFG_MAX		= (__NFQA_CFG_MAX-1)

# Flags for NFQA_CFG_FLAGS
NFQA_CFG_F_FAIL_OPEN	= (1 << 0)
NFQA_CFG_F_CONNTRACK	= (1 << 1)
NFQA_CFG_F_GSO		= (1 << 2)
NFQA_CFG_F_MAX		= (1 << 3)

# flags for NFQA_SKB_INFO
# packet appears to have wrong checksums, but they are ok
NFQA_SKB_CSUMNOTREADY		= (1 << 0)
# packet is GSO (i.e., exceeds device mtu)
NFQA_SKB_GSO			= (1 << 1)
# csum not validated (incoming device doesn't support hw checksum, etc.)
NFQA_SKB_CSUM_NOTVERIFIED	= (1 << 2)
