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
NFULNL_MSG_PACKET	= 0
NFULNL_MSG_CONFIG	= 1
NFULNL_MSG_MAX		= 2

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
NFULA_UNSPEC			= 0
NFULA_PACKET_HDR		= 1
NFULA_MARK			= 2
NFULA_TIMESTAMP			= 3
NFULA_IFINDEX_INDEV		= 4
NFULA_IFINDEX_OUTDEV		= 5
NFULA_IFINDEX_PHYSINDEV		= 6
NFULA_IFINDEX_PHYSOUTDEV	= 7
NFULA_HWADDR			= 8
NFULA_PAYLOAD			= 9
NFULA_PREFIX			= 10
NFULA_UID			= 11
NFULA_SEQ			= 12
NFULA_SEQ_GLOBAL		= 13
NFULA_GID			= 14
NFULA_HWTYPE			= 15
NFULA_HWHEADER			= 16
NFULA_HWLEN			= 17
__NFULA_MAX			= 18
NFULA_MAX			= (__NFULA_MAX - 1)

# enum nfulnl_msg_config_cmds
class NfulnlMsgConfigCmds(Enum):
    NFULNL_CFG_CMD_NONE		= 0
    NFULNL_CFG_CMD_BIND		= 1
    NFULNL_CFG_CMD_UNBIND	= 2
    NFULNL_CFG_CMD_PF_BIND	= 3
    NFULNL_CFG_CMD_PF_UNBIND	= 4
NFULNL_CFG_CMD_NONE		= 0
NFULNL_CFG_CMD_BIND		= 1
NFULNL_CFG_CMD_UNBIND		= 2
NFULNL_CFG_CMD_PF_BIND		= 3
NFULNL_CFG_CMD_PF_UNBIND	= 4

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
NFULA_CFG_UNSPEC	= 0
NFULA_CFG_CMD		= 1
NFULA_CFG_MODE		= 2
NFULA_CFG_NLBUFSIZ	= 3
NFULA_CFG_TIMEOUT	= 4
NFULA_CFG_QTHRESH	= 5
NFULA_CFG_FLAGS		= 6
__NFULA_CFG_MAX		= 7
NFULA_CFG_MAX		= (__NFULA_CFG_MAX -1)

NFULNL_COPY_NONE	= 0x00
NFULNL_COPY_META	= 0x01
NFULNL_COPY_PACKET	= 0x02
# 0xff is reserved, don't use it for new copy modes.

NFULNL_CFG_F_SEQ	= 0x0001
NFULNL_CFG_F_SEQ_GLOBAL	= 0x0002
