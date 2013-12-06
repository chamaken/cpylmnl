from __future__ import absolute_import

from ctypes import *
from cpylmnl import netlink


class Nfattr(netlink.UStructure):
    """struct nfattr

    Generic structure for encapsulation optional netfilter information.
    It is reminiscent of sockaddr, but with sa_family replaced
    with attribute type.
    ! This should someday be put somewhere generic as now rtnetlink and
    ! nfnetlink use the same attributes methods. - J. Schulist.
    """
    _fields_ = [("len",		c_uint16), # __u16 nfa_len
                ("type",	c_uint16)] # we use 15 bits for the type, and the highest
                                           # bit to indicate whether the payload is nested

#
# used in examples/nf-log.c
#
NFA_ALIGNTO	= 4

def NFA_ALIGN(size):
    return ((size) + NFA_ALIGNTO - 1) & ~(NFA_ALIGNTO - 1)

def NFA_LENGTH(size):
    return NFA_ALIGN(Nfattr.sizeof() + size)

def NFA_PAYLOAD(nfa):
    return nfa.len - NFA_LENGTH(0)
