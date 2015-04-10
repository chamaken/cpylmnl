# -*- coding: utf-8 -*-

import ctypes

import cpylmnl.linux.netlinkh as netlink
from cpylmnl.nlstruct import NLStructure
try:
    from enum import Enum
except ImportError:
    Enum = object


# enum nfulnl_msg_types
class NfulnlMsgTypes(Enum):
    NFULNL_MSG_PACKET	= 0 # packet from kernel to userspace
    NFULNL_MSG_CONFIG	= 1 # connect to a particular queue
    NFULNL_MSG_MAX	= 2
NFULNL_MSG_PACKET	= NfulnlMsgTypes.NFULNL_MSG_PACKET
NFULNL_MSG_CONFIG	= NfulnlMsgTypes.NFULNL_MSG_CONFIG
NFULNL_MSG_MAX		= NfulnlMsgTypes.NFULNL_MSG_MAX

class NfulnlMsgPacketHdr(NLStructure):
    """struct nfulnl_msg_packet_hdr
    """
    _fields_ = [("hw_protocol",	ctypes.c_uint16), # __be16 hw_protocol /* hw protocol (network order) */
                ("hook",	ctypes.c_uint8),  # __u8   hook        /* netfilter hook */
                ("_pad",	ctypes.c_uint8)]  # __u8   _pad

class NfulnlMsgPacketHw(NLStructure):
    """struct nfulnl_msg_packet_hw
    """
    _fields_ = [("hw_addrlen",	ctypes.c_uint16),    # __be16 hw_addrlen;
                ("_pad",	ctypes.c_uint16),    # __u16  _pad;
                ("hw_addr",	ctypes.c_uint8 * 8)] # __u8   hw_addr[8];

class NfulnlMsgPacketTimestamp(NLStructure):
    """struct nfulnl_msg_packet_timestamp
    """
    _fields_ = [("sec",		ctypes.c_uint64), # __aligned_be64 sec;
                ("usec",	ctypes.c_uint64)] # __aligned_be64 usec;

# enum nfulnl_attr_type
class NfulnlAttrType(Enum):
    NFULA_UNSPEC		= 0  # 
    NFULA_PACKET_HDR		= 1  # 
    NFULA_MARK			= 2  # __u32 nfmark
    NFULA_TIMESTAMP		= 3  # nfulnl_msg_packet_timestamp
    NFULA_IFINDEX_INDEV		= 4  # __u32 ifindex
    NFULA_IFINDEX_OUTDEV	= 5  # __u32 ifindex
    NFULA_IFINDEX_PHYSINDEV	= 6  # __u32 ifindex
    NFULA_IFINDEX_PHYSOUTDEV	= 7  # __u32 ifindex
    NFULA_HWADDR		= 8  # nfulnl_msg_packet_hw
    NFULA_PAYLOAD		= 9  # opaque data payload
    NFULA_PREFIX		= 10 # string prefix
    NFULA_UID			= 11 # user id of socket
    NFULA_SEQ			= 12 # instance-local sequence number
    NFULA_SEQ_GLOBAL		= 13 # global sequence number
    NFULA_GID			= 14 # group id of socket
    NFULA_HWTYPE		= 15 # hardware type
    NFULA_HWHEADER		= 16 # hardware header
    NFULA_HWLEN			= 17 # hardware header length
    __NFULA_MAX			= 18
    NFULA_MAX			= (__NFULA_MAX - 1)
NFULA_UNSPEC			= NfulnlAttrType.NFULA_UNSPEC
NFULA_PACKET_HDR		= NfulnlAttrType.NFULA_PACKET_HDR
NFULA_MARK			= NfulnlAttrType.NFULA_MARK
NFULA_TIMESTAMP			= NfulnlAttrType.NFULA_TIMESTAMP
NFULA_IFINDEX_INDEV		= NfulnlAttrType.NFULA_IFINDEX_INDEV
NFULA_IFINDEX_OUTDEV		= NfulnlAttrType.NFULA_IFINDEX_OUTDEV
NFULA_IFINDEX_PHYSINDEV		= NfulnlAttrType.NFULA_IFINDEX_PHYSINDEV
NFULA_IFINDEX_PHYSOUTDEV	= NfulnlAttrType.NFULA_IFINDEX_PHYSOUTDEV
NFULA_HWADDR			= NfulnlAttrType.NFULA_HWADDR
NFULA_PAYLOAD			= NfulnlAttrType.NFULA_PAYLOAD
NFULA_PREFIX			= NfulnlAttrType.NFULA_PREFIX
NFULA_UID			= NfulnlAttrType.NFULA_UID
NFULA_SEQ			= NfulnlAttrType.NFULA_SEQ
NFULA_SEQ_GLOBAL		= NfulnlAttrType.NFULA_SEQ_GLOBAL
NFULA_GID			= NfulnlAttrType.NFULA_GID
NFULA_HWTYPE			= NfulnlAttrType.NFULA_HWTYPE
NFULA_HWHEADER			= NfulnlAttrType.NFULA_HWHEADER
NFULA_HWLEN			= NfulnlAttrType.NFULA_HWLEN
NFULA_MAX			= NfulnlAttrType.NFULA_MAX

# enum nfulnl_msg_config_cmds
class NfulnlMsgConfigCmds(Enum):
    NFULNL_CFG_CMD_NONE		= 0
    NFULNL_CFG_CMD_BIND		= 1
    NFULNL_CFG_CMD_UNBIND	= 2
    NFULNL_CFG_CMD_PF_BIND	= 3
    NFULNL_CFG_CMD_PF_UNBIND	= 4
NFULNL_CFG_CMD_NONE		= NfulnlMsgConfigCmds.NFULNL_CFG_CMD_NONE
NFULNL_CFG_CMD_BIND		= NfulnlMsgConfigCmds.NFULNL_CFG_CMD_BIND
NFULNL_CFG_CMD_UNBIND		= NfulnlMsgConfigCmds.NFULNL_CFG_CMD_UNBIND
NFULNL_CFG_CMD_PF_BIND		= NfulnlMsgConfigCmds.NFULNL_CFG_CMD_PF_BIND
NFULNL_CFG_CMD_PF_UNBIND	= NfulnlMsgConfigCmds.NFULNL_CFG_CMD_PF_UNBIND

class NfulnlMsgConfigCmd(NLStructure):
    """struct nfulnl_msg_config_cmd
    """
    _fields_ = [("command",	ctypes.c_uint8)] # __u8 command; /* nfulnl_msg_config_cmds */

class NfulnlMsgConfigMode(NLStructure):
    """struct nfulnl_msg_config_mode
    """

    _fields_ = [("copy_range",	ctypes.c_uint32), # __be32 copy_range;
                ("copy_mode",	ctypes.c_uint8),  # __u8   copy_mode;
                ("_pad",	ctypes.c_uint8)]  # __u8   _pad;

# enum nfulnl_attr_config
class NfulnlAttrConfig(Enum):
    NFULA_CFG_UNSPEC	= 0 # 
    NFULA_CFG_CMD	= 1 # 
    NFULA_CFG_MODE	= 2 # nfulnl_msg_config_cmd
    NFULA_CFG_NLBUFSIZ	= 3 # nfulnl_msg_config_mode
    NFULA_CFG_TIMEOUT	= 4 # __u32 buffer size
    NFULA_CFG_QTHRESH	= 5 # __u32 in 1/100 s
    NFULA_CFG_FLAGS	= 6 # __u32
    __NFULA_CFG_MAX	= 7 # __u16
    NFULA_CFG_MAX	= (__NFULA_CFG_MAX -1)
NFULA_CFG_UNSPEC	= NfulnlAttrConfig.NFULA_CFG_UNSPEC
NFULA_CFG_CMD		= NfulnlAttrConfig.NFULA_CFG_CMD
NFULA_CFG_MODE		= NfulnlAttrConfig.NFULA_CFG_MODE
NFULA_CFG_NLBUFSIZ	= NfulnlAttrConfig.NFULA_CFG_NLBUFSIZ
NFULA_CFG_TIMEOUT	= NfulnlAttrConfig.NFULA_CFG_TIMEOUT
NFULA_CFG_QTHRESH	= NfulnlAttrConfig.NFULA_CFG_QTHRESH
NFULA_CFG_FLAGS		= NfulnlAttrConfig.NFULA_CFG_FLAGS
NFULA_CFG_MAX		= NfulnlAttrConfig.NFULA_CFG_MAX

NFULNL_COPY_NONE	= 0x00
NFULNL_COPY_META	= 0x01
NFULNL_COPY_PACKET	= 0x02
# 0xff is reserved, don't use it for new copy modes.

NFULNL_CFG_F_SEQ	= 0x0001
NFULNL_CFG_F_SEQ_GLOBAL	= 0x0002
