# -*- coding: utf-8 -*-

from ctypes import *
import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnetlink
from cpylmnl.nlstruct import NLStructure

class Ifaddrmsg(NLStructure):
    _fields_ = [("family",	c_uint8),  # __u8 ifa_family
                ("prefixlen",	c_uint8),  # __u8 ifa_prefixlen /* The prefix length            */
                ("flags",	c_uint8),  # __u8 ifa_flags     /* Flags                        */
                ("scope",	c_uint8),  # __u8 ifa_scope     /* Address scope                */
                ("index",	c_uint32)] # __u32 ifa_index    /* Link index                   */

# Important comment:
# IFA_ADDRESS is prefix address, rather than local interface address.
# It makes no difference for normally configured broadcast interfaces,
# but for point-to-point IFA_ADDRESS is DESTINATION address,
# local address is supplied in IFA_LOCAL attribute.
# enum
IFA_UNSPEC	= 0
IFA_ADDRESS	= 1
IFA_LOCAL	= 2
IFA_LABEL	= 3
IFA_BROADCAST	= 4
IFA_ANYCAST	= 5
IFA_CACHEINFO	= 6
IFA_MULTICAST	= 7
__IFA_MAX	= 8
IFA_MAX		= (__IFA_MAX - 1)

# ifa_flags
IFA_F_SECONDARY		= 0x01
IFA_F_TEMPORARY		= IFA_F_SECONDARY
IFA_F_NODAD		= 0x02
IFA_F_OPTIMISTIC	= 0x04
IFA_F_DADFAILED		= 0x08
IFA_F_HOMEADDRESS	= 0x10
IFA_F_DEPRECATED	= 0x20
IFA_F_TENTATIVE		= 0x40
IFA_F_PERMANENT		= 0x80

class IfaCacheinfo(Structure):
    """struct ifa_cacheinfo
    """
    _fields_ = [("prefered",	c_uint32), # __u32 ifa_prefered
                ("valid",	c_uint32), # __u32 ifa_valid
                ("cstamp",	c_uint32), # __u32 cstamp /* created timestamp, hundredths of seconds */
                ("tstamp",	c_uint32)] # __u32 tstamp /* updated timestamp, hundredths of seconds */


# backwards compatibility for userspace
#define IFA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
def IFA_RTA(r):	    	return rtnetlink.Rtattr.pointer(addressof(r) + netlink.NLMSG_ALIGN(sizeof(Ifaddrmsg)))
#define IFA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
def IFA_PAYLOAD(n):	return netlink.NLMSG_PAYLOAD(n, sizeof(Ifaddrmsg))
