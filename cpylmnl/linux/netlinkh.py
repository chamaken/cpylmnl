# -*- coding: utf-8 -*-

import ctypes

from cpylmnl.nlstruct import NLStructure
try:
    from enum import Enum
except ImportError:
    Enum = object


NETLINK_ROUTE		= 0	# Routing/device hook				
NETLINK_UNUSED		= 1	# Unused number				
NETLINK_USERSOCK	= 2	# Reserved for user mode socket protocols 	
NETLINK_FIREWALL	= 3	# Unused number, formerly ip_queue		
NETLINK_SOCK_DIAG	= 4	# socket monitoring				
NETLINK_NFLOG		= 5	# netfilter/iptables ULOG 
NETLINK_XFRM		= 6	# ipsec 
NETLINK_SELINUX		= 7	# SELinux event notifications 
NETLINK_ISCSI		= 8	# Open-iSCSI 
NETLINK_AUDIT		= 9	# auditing 
NETLINK_FIB_LOOKUP	= 10	
NETLINK_CONNECTOR	= 11
NETLINK_NETFILTER	= 12	# netfilter subsystem 
NETLINK_IP6_FW		= 13
NETLINK_DNRTMSG		= 14	# DECnet routing messages 
NETLINK_KOBJECT_UEVENT	= 15	# Kernel messages to userspace 
NETLINK_GENERIC		= 16
# leave room for NETLINK_DM (DM Events) 
NETLINK_SCSITRANSPORT	= 18	# SCSI Transports 
NETLINK_ECRYPTFS	= 19
NETLINK_RDMA		= 20
NETLINK_CRYPTO		= 21	# Crypto layer 

NETLINK_INET_DIAG	= NETLINK_SOCK_DIAG

MAX_LINKS = 32		

'''
class SockaddrNl(ctypes.Structure):
    """struct sockaddr_nl
    """
    _fields_ = [("family", 	c_ushort), # __kernel_sa_family_t	nl_family;	/* AF_NETLINK	*/
                ("pad",		c_short),  # unsigned short		nl_pad;		/* zero		*/
                ("pid",		ctypes.c_uint32), # __u32			nl_pid;		/* port ID	*/
                ("groups", 	ctypes.c_uint32)] # __u32			nl_groups;	/* multicast groups mask */
'''

class Nlmsghdr(NLStructure):
    """struct nlmsghdr
    """
    _fields_ = [("len",		ctypes.c_uint32), # __u32 nlmsg_len	/* Length of message including header */
                ("type",	ctypes.c_uint16), # __u16 nlmsg_type	/* Message content */
                ("flags",	ctypes.c_uint16), # __u16 nlmsg_flags	/* Additional flags */
                ("seq",		ctypes.c_uint32), # __u32 nlmsg_seq	/* Sequence number */
                ("pid",		ctypes.c_uint32)] # __u32 nlmsg_pid	/* Sending process port ID */

# Flags values 
NLM_F_REQUEST		= 1	# It is request message. 	
NLM_F_MULTI		= 2	# Multipart message, terminated by NLMSG_DONE 
NLM_F_ACK		= 4	# Reply with ack, with zero or error code 
NLM_F_ECHO		= 8	# Echo this request 		
NLM_F_DUMP_INTR		= 16	# Dump was inconsistent due to sequence change 

# Modifiers to GET request 
NLM_F_ROOT		= 0x100	# specify tree	root	
NLM_F_MATCH		= 0x200	# return all matching	
NLM_F_ATOMIC		= 0x400	# atomic GET		
NLM_F_DUMP		= (NLM_F_ROOT|NLM_F_MATCH)

# Modifiers to NEW request 
NLM_F_REPLACE		= 0x100	# Override existing		
NLM_F_EXCL		= 0x200	# Do not touch, if it exists	
NLM_F_CREATE		= 0x400	# Create, if it does not exist	
NLM_F_APPEND		= 0x800	# Add to end of list		

#   4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
#   4.4BSD CHANGE	NLM_F_REPLACE
#
#   True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
#   Append		NLM_F_CREATE
#   Check		NLM_F_EXCL
NLMSG_ALIGNTO = 0x4
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
def NLMSG_ALIGN(len): return ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define: NLMSG_HDRLEN = ((int) NLMSG_ALIGN(ctypes.sizeof(struct nlmsghdr)))
NLMSG_HDRLEN = NLMSG_ALIGN(ctypes.sizeof(Nlmsghdr))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
def NLMSG_LENGTH(len):	return ((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
def NLMSG_SPACE(len):	return NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
def NLMSG_DATA(nlh):	return cast(addressof(nlh), POINTER((c_ubyte * nlh.len))).contents
# XXX: not implemented yet
#define NLMSG_OK(nlh,len) ((len) >= (int)ctypes.sizeof(struct nlmsghdr) && \
#			   (nlh)->nlmsg_len >= ctypes.sizeof(struct nlmsghdr) && \
#			   (nlh)->nlmsg_len <= (len))
def NLMSG_OK(nlh, len): return (len >= ctypes.sizeof(Nlmsghdr) and
                                nlh.len >= ctypes.sizeof(Nlmsghdr) and
                                nlh.len <= len)
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
def NLMSG_PAYLOAD(nlh, len): return nlh.len - NLMSG_SPACE(len)

NLMSG_NOOP		= 0x1	# Nothing.		
NLMSG_ERROR		= 0x2	# Error		
NLMSG_DONE		= 0x3	# End of a dump	
NLMSG_OVERRUN		= 0x4	# Data lost		

NLMSG_MIN_TYPE		= 0x10	# < 0x10: reserved control messages 

class Nlmsgerr(NLStructure):
    """struct nlmsgerr
    """
    _fields_ = [("error",	ctypes.c_int),  # int error
                ("msg",		Nlmsghdr)] 	# struct nlmsghdr msg

NETLINK_ADD_MEMBERSHIP	= 1
NETLINK_DROP_MEMBERSHIP	= 2
NETLINK_PKTINFO		= 3
NETLINK_BROADCAST_ERROR	= 4
NETLINK_NO_ENOBUFS	= 5
NETLINK_RX_RING		= 6
NETLINK_TX_RING		= 7

class NlPktinfo(ctypes.Structure): # not NLStructure?
    """struct nl_pktinfo
    """
    _fields_ = [("group",	ctypes.c_uint32)] # __u32 group

class NlMmapReq(ctypes.Structure):
    """struct nl_mmap_req
    """
    _fields_ = [("block_size", 	ctypes.c_uint), # unsigned int	nm_block_size
                ("block_nr",	ctypes.c_uint), # unsigned int	nm_block_nr
                ("frame_size",	ctypes.c_uint), # unsigned int	nm_frame_size
                ("frame_nr",	ctypes.c_uint)] # unsigned int	nm_frame_nr

class NlMmapHdr(ctypes.Structure):
    """struct nl_mmap_hdr
    """
    _fields_ = [("status",	ctypes.c_uint),  # unsigned int	nm_status
                ("len",		ctypes.c_uint),  # unsigned int	nm_len
                ("group",	ctypes.c_uint32), # __u32		nm_group;
                # credentials
                ("pid",		ctypes.c_uint32), # __u32		nm_pid;
                ("uid",		ctypes.c_uint32), # __u32		nm_uid;
                ("gid", 	ctypes.c_uint32)] # __u32		nm_gid;

class NlMmapStatus(Enum):
    NL_MMAP_STATUS_UNUSED	= 0
    NL_MMAP_STATUS_RESERVED	= 1
    NL_MMAP_STATUS_VALID	= 2
    NL_MMAP_STATUS_COPY		= 3
    NL_MMAP_STATUS_SKIP		= 4
NL_MMAP_STATUS_UNUSED	= 0
NL_MMAP_STATUS_RESERVED	= 1
NL_MMAP_STATUS_VALID	= 2
NL_MMAP_STATUS_COPY	= 3
NL_MMAP_STATUS_SKIP	= 4

NL_MMAP_MSG_ALIGNMENT	= NLMSG_ALIGNTO
# 'kernel.h' contains some often-used function prototypes etc
def __ALIGN_KERNEL(x, a):		return __ALIGN_KERNEL_MASK(x, (a) - 1)
def __ALIGN_KERNEL_MASK(x, mask):	return  ((x) + (mask)) & ~(mask)
#define NL_MMAP_MSG_ALIGN(sz)		__ALIGN_KERNEL(sz, NL_MMAP_MSG_ALIGNMENT)
def NL_MMAP_MSG_ALIGN(sz):		return __ALIGN_KERNEL(sz, NL_MMAP_MSG_ALIGNMENT)
#define NL_MMAP_HDRLEN			NL_MMAP_MSG_ALIGN(ctypes.sizeof(struct nl_mmap_hdr))
NL_MMAP_HDRLEN				= NL_MMAP_MSG_ALIGN(ctypes.sizeof(NlMmapHdr))

NET_MAJOR = 36		# Major 36 is reserved for networking 						

# enum
NETLINK_UNCONNECTED	= 0
NETLINK_CONNECTED	= 1

#  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
# +---------------------+- - -+- - - - - - - - - -+- - -+
# |        Header       | Pad |     Payload       | Pad |
# |   (struct nlattr)   | ing |                   | ing |
# +---------------------+- - -+- - - - - - - - - -+- - -+
#  <-------------- nlattr->nla_len -------------->
class Nlattr(NLStructure):
    """struct nlattr
    """
    _fields_ = [("len",		ctypes.c_uint16), # __u16 nla_len
                ("type",	ctypes.c_uint16)] # __u16 nla_type

# nla_type (16 bits)
# +---+---+-------------------------------+
# | N | O | Attribute Type                |
# +---+---+-------------------------------+
# N := Carries nested attributes
# O := Payload stored in network byte order
# 
# Note: The N and O flag are mutually exclusive.
NLA_F_NESTED		= (1 << 15)
NLA_F_NET_BYTEORDER	= (1 << 14)
NLA_TYPE_MASK		= ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

NLA_ALIGNTO = 4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
def NLA_ALIGN(len):		return (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN		((int) NLA_ALIGN(ctypes.sizeof(struct nlattr)))
NLA_HDRLEN			= NLA_ALIGN(ctypes.sizeof(Nlattr))
