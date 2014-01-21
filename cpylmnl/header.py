# -*- coding: utf-8 -*-

import resource
import ctypes
from .linux import netlinkh as netlink
try:
    from enum import Enum
except ImportError:
    Enum = object


# Netlink socket API
MNL_SOCKET_AUTOPID = 0
#define MNL_SOCKET_BUFFER_SIZE (getpagesize() < 8192L ? getpagesize() : 8192L)
MNL_SOCKET_BUFFER_SIZE		= resource.getpagesize() < 8192 and resource.getpagesize() or 8192


# Netlink message API
MNL_ALIGNTO			= 4
#define MNL_ALIGN(len)		(((len)+MNL_ALIGNTO-1) & ~(MNL_ALIGNTO-1))
def MNL_ALIGN(len):		return (((len)+MNL_ALIGNTO-1) & ~(MNL_ALIGNTO-1))
#define MNL_NLMSG_HDRLEN	MNL_ALIGN(sizeof(struct nlmsghdr))
MNL_NLMSG_HDRLEN		= MNL_ALIGN(ctypes.sizeof(netlink.Nlmsghdr))


# Netlink attributes API
#define MNL_ATTR_HDRLEN	MNL_ALIGN(sizeof(struct nlattr))
MNL_ATTR_HDRLEN		= MNL_ALIGN(ctypes.sizeof(netlink.Nlattr))

class MnlAttrDataType(Enum):
    MNL_TYPE_UNSPEC = 0
    MNL_TYPE_U8 = 1
    MNL_TYPE_U16 = 2
    MNL_TYPE_U32 = 3
    MNL_TYPE_U64 = 4
    MNL_TYPE_STRING = 5
    MNL_TYPE_FLAG = 6
    MNL_TYPE_MSECS = 7
    MNL_TYPE_NESTED = 8
    MNL_TYPE_NESTED_COMPAT = 9
    MNL_TYPE_NUL_STRING = 10
    MNL_TYPE_BINARY = 11
    MNL_TYPE_MAX = 12

MNL_TYPE_UNSPEC = 0
MNL_TYPE_U8 = 1
MNL_TYPE_U16 = 2
MNL_TYPE_U32 = 3
MNL_TYPE_U64 = 4
MNL_TYPE_STRING = 5
MNL_TYPE_FLAG = 6
MNL_TYPE_MSECS = 7
MNL_TYPE_NESTED = 8
MNL_TYPE_NESTED_COMPAT = 9
MNL_TYPE_NUL_STRING = 10
MNL_TYPE_BINARY = 11
MNL_TYPE_MAX = 12


# callback API
MNL_CB_ERROR		= -1
MNL_CB_STOP		= 0
MNL_CB_OK		= 1


# other declarations
SOL_NETLINK		= 270
def MNL_ARRAY_SIZE(a):	return (ctypes.sizeof(a)/ctypes.sizeof((a)[0]))


### a little bit differ from C macro - requires len
def MNL_FRAME_PAYLOAD(hdr, size):
    return ctypes.cast(ctypes.addressof(hdr) + netlink.NL_MMAP_HDRLEN,
                       ctypes.POINTER(ctypes.c_ubyte * size)).contents

MNL_RING_RX = 0
MNL_RING_TX = 1
