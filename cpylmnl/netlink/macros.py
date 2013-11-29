# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import sizeof
from .structs import *

# H2PY_ERR: h/linux/netlink.h - define: NLMSG_ALIGNTO = 4U
NLMSG_ALIGNTO = 0x4

def NLMSG_ALIGN(len): return ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )

# H2PY_ERR: h/linux/netlink.h - define: NLMSG_HDRLEN = ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
NLMSG_HDRLEN = NLMSG_ALIGN(sizeof(Nlmsghdr))

def NLMSG_LENGTH(len):	return ((len) + NLMSG_HDRLEN)
def NLMSG_SPACE(len):	return NLMSG_ALIGN(NLMSG_LENGTH(len))

# H2PY_ERR: h/linux/netlink.h - macro: def NLMSG_DATA(nlh): return ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
def NLMSG_DATA(nlh):	return nlh.ubuf[NLMSG_LENGTH(0):]

# H2PY_ERR: h/linux/netlink.h - define: NL_MMAP_MSG_ALIGNMENT = NLMSG_ALIGNTO
NL_MMAP_MSG_ALIGNMENT = NLMSG_ALIGNTO

# H2PY_ERR: h/linux/netlink.h - define: NL_MMAP_HDRLEN = NL_MMAP_MSG_ALIGN(sizeof(struct nl_mmap_hdr))
# 'kernel.h' contains some often-used function prototypes etc
def __ALIGN_KERNEL(x, a): return __ALIGN_KERNEL_MASK(x, (a) - 1)
def __ALIGN_KERNEL_MASK(x, mask): return  ((x) + (mask)) & ~(mask)
def NL_MMAP_MSG_ALIGN(sz): return __ALIGN_KERNEL(sz, NL_MMAP_MSG_ALIGNMENT)

NLA_ALIGNTO = 4
def NLA_ALIGN(len): return (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))

# H2PY_ERR: h/linux/netlink.h - define: NLA_HDRLEN = ((int) NLA_ALIGN(sizeof(struct nlattr)))
NLA_HDRLEN = NLA_ALIGN(sizeof(Nlattr))
