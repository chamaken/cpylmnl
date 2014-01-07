# -*- coding: utf-8 -*-

from ctypes import *

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnetlink
try:
    from enum import Enum
except ImportError:
    Enum = object


# This struct should be in sync with struct rtnl_link_stats64
class RtnlLinkStats(Structure):
    """struct rtnl_link_stats
    """
    _fields_ = [("rx_packets",		c_uint32), # __u32 rx_packets	 /* total packets received	 */
                ("tx_packets",		c_uint32), # __u32 tx_packets	 /* total packets transmitted	 */
                ("rx_bytes",		c_uint32), # __u32 rx_bytes	 /* total bytes received	 */
                ("tx_bytes",		c_uint32), # __u32 tx_bytes	 /* total bytes transmitted	 */
                ("rx_errors",		c_uint32), # __u32 rx_errors	 /* bad packets received	 */
                ("tx_errors",		c_uint32), # __u32 tx_errors	 /* packet transmit problems	 */
                ("rx_dropped",		c_uint32), # __u32 rx_dropped	 /* no space in linux buffers	 */
                ("tx_dropped",		c_uint32), # __u32 tx_dropped	 /* no space available in linux	 */
                ("multicast",		c_uint32), # __u32 multicast	 /* multicast packets received	 */
                ("collisions",		c_uint32), # __u32 collisions

                ## detailed rx_errors:
                ("rx_length_errors",	c_uint32), # __u32 rx_length_errors
                ("rx_over_errors",	c_uint32), # __u32 rx_over_errors   /* receiver ring buff overflow  */
                ("rx_crc_errors",	c_uint32), # __u32 rx_crc_errors    /* recved pkt with crc error    */
                ("rx_frame_errors",	c_uint32), # __u32 rx_frame_errors  /* recv'd frame alignment error */
                ("rx_fifo_errors",	c_uint32), # __u32 rx_fifo_errors   /* recv'r fifo overrun	    */
                ("rx_missed_errors",	c_uint32), # __u32 rx_missed_errors /* receiver missed packet	    */

                ## detailed tx_errors
                ("tx_aborted_errors",	c_uint32), # __u32 tx_aborted_errors
                ("tx_carrier_errors",	c_uint32), # __u32 tx_carrier_errors
                ("tx_fifo_errors",	c_uint32), # __u32 tx_fifo_errors
                ("tx_heartbear_errors",	c_uint32), # __u32 tx_heartbeat_errors
                ("tx_window_errors",	c_uint32), # __u32 tx_window_errors

                ## for cslip etc
                ("rx_compressed",	c_uint32), # __u32 rx_compressed
                ("tx_compressed",	c_uint32)] # __u32 tx_compressed

# The main device statistics structure
class RtnlLinkStats64(Structure):
    """struct rtnl_link_stats64
    """
    _fields_ = [("rx_packets",		c_uint64), # __u64 rx_packets	 /* total packets received	 */
                ("tx_packets",		c_uint64), # __u64 tx_packets	 /* total packets transmitted	 */
                ("rx_bytes",		c_uint64), # __u64 rx_bytes	 /* total bytes received	 */
                ("tx_bytes",		c_uint64), # __u64 tx_bytes	 /* total bytes transmitted	 */
                ("rx_errors",		c_uint64), # __u64 rx_errors	 /* bad packets received	 */
                ("tx_errors",		c_uint64), # __u64 tx_errors	 /* packet transmit problems	 */
                ("rx_dropped",		c_uint64), # __u64 rx_dropped	 /* no space in linux buffers	 */
                ("tx_dropped",		c_uint64), # __u64 tx_dropped	 /* no space available in linux	 */
                ("multicast",		c_uint64), # __u64 multicast	 /* multicast packets received	 */
                ("collisions",		c_uint64), # __u64 collisions

                ## detailed rx_errors:
                ("rx_length_errors",	c_uint64), # __u64 rx_length_errors
                ("rx_over_errors",	c_uint64), # __u64 rx_over_errors   /* receiver ring buff overflow  */
                ("rx_crc_errors",	c_uint64), # __u64 rx_crc_errors    /* recved pkt with crc error    */
                ("rx_frame_errors",	c_uint64), # __u64 rx_frame_errors  /* recv'd frame alignment error */
                ("rx_fifo_errors",	c_uint64), # __u64 rx_fifo_errors   /* recv'r fifo overrun	    */
                ("rx_missed_errors",	c_uint64), # __u64 rx_missed_errors /* receiver missed packet	    */

                ## detailed tx_errors
                ("tx_aborted_errors",	c_uint64), # __u64 tx_aborted_errors
                ("tx_carrier_errors",	c_uint64), # __u64 tx_carrier_errors
                ("tx_fifo_errors",	c_uint64), # __u64 tx_fifo_errors
                ("tx_heartbear_errors",	c_uint64), # __u64 tx_heartbeat_errors
                ("tx_window_errors",	c_uint64), # __u64 tx_window_errors

                ## for cslip etc
                ("rx_compressed",	c_uint64), # __u64 rx_compressed
                ("tx_compressed",	c_uint64)] # __u64 tx_compressed

# The struct should be in sync with struct ifmap
class RtnlLinkIfmap(Structure):
    """struct rtnl_link_ifmap
    """
    _fields_ = [("mem_start",	c_uint64), # __u64	mem_start
                ("mem_end",	c_uint64), # __u64	mem_end
                ("base_addr",	c_uint64), # __u64	base_addr
                ("irq",		c_uint16), # __u16	irq
                ("dma",		c_uint8),  # __u8	dma
                ("port",	c_uint8)]  # __u8	port


# IFLA_AF_SPEC
#   Contains nested attributes for address family specific attributes.
#   Each address family may create a attribute with the address family
#   number as type and create its own attribute structure in it.
#
#   Example:
#   [IFLA_AF_SPEC] = {
#       [AF_INET] = {
#           [IFLA_INET_CONF] = ...,
#       },
#       [AF_INET6] = {
#           [IFLA_INET6_FLAGS] = ...,
#           [IFLA_INET6_CONF] = ...,
#       }
#   }
#
# enum
IFLA_UNSPEC		= 0
IFLA_ADDRESS		= 1
IFLA_BROADCAST		= 2
IFLA_IFNAME		= 3
IFLA_MTU		= 4
IFLA_LINK		= 5
IFLA_QDISC		= 6
IFLA_STATS		= 7
IFLA_COST		= 8
IFLA_PRIORITY		= 9
IFLA_MASTER		= 10
IFLA_WIRELESS		= 11
IFLA_PROTINFO		= 12
IFLA_TXQLEN		= 13
IFLA_MAP		= 14
IFLA_WEIGHT		= 15
IFLA_OPERSTATE		= 16
IFLA_LINKMODE		= 17
IFLA_LINKINFO		= 18
IFLA_NET_NS_PID		= 19
IFLA_IFALIAS 		= 20
IFLA_NUM_VF		= 21
IFLA_VFINFO_LIST	= 22
IFLA_STATS64		= 23
IFLA_VF_PORTS		= 24
IFLA_PORT_SELF		= 25
IFLA_AF_SPEC		= 26
IFLA_GROUP		= 27
IFLA_NET_NS_FD		= 28
IFLA_EXT_MASK		= 29
IFLA_PROMISCUITY	= 30
IFLA_NUM_TX_QUEUES	= 31
IFLA_NUM_RX_QUEUES	= 32
IFLA_CARRIER		= 33
IFLA_PHYS_PORT_ID	= 34
__IFLA_MAX = 35
IFLA_MAX = (__IFLA_MAX - 1)


# backwards compatibility for userspace
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
def IFLA_RTA(r):	return rtnetlink.Rtattr.pointer(addressof(r) + netlink.NLMSG_ALIGN(sizeof(rtnetlink.Ifinfomsg)))
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
def IFLA_PAYLOAD(n):	return netlink.NLMSG_PAYLOAD(n, sizeof(rtnetlink.Ifinfomsg))


# enum
IFLA_INET_UNSPEC	= 0
IFLA_INET_CONF		= 1
__IFLA_INET_MAX		= 2
IFLA_INET_MAX		= (__IFLA_INET_MAX - 1)


# ifi_flags.
#
# IFF_* flags.
#
# The only change is:
# IFF_LOOPBACK, IFF_BROADCAST and IFF_POINTOPOINT are
# more not changeable by user. They describe link media
# characteristics and set by device driver.
#
# Comments:
# - Combination IFF_BROADCAST|IFF_POINTOPOINT is invalid
# - If neither of these three flags are set;
#   the interface is NBMA.
#
# - IFF_MULTICAST does not mean anything special:
# multicasts can be used on all not-NBMA links.
# IFF_MULTICAST means that this media uses special encapsulation
# for multicast frames. Apparently, all IFF_POINTOPOINT and
# IFF_BROADCAST devices are able to use multicasts too.

# IFLA_LINK.
# For usual devices it is equal ifi_index.
# If it is a "virtual interface" (f.e. tunnel), ifi_link
# can point to real physical interface (f.e. for bandwidth calculations),
# or maybe 0, what means, that real media is unknown (usual
# for IPIP tunnels, when route to endpoint is allowed to change)

# Subtype attributes for IFLA_PROTINFO */
# enum
IFLA_INET6_UNSPEC	= 0
IFLA_INET6_FLAGS	= 1 # link flags
IFLA_INET6_CONF		= 2 # sysctl parameters
IFLA_INET6_STATS	= 3 # statistics
IFLA_INET6_MCAST	= 4 # MC things. What of them?
IFLA_INET6_CACHEINFO	= 5 # time values and max reasm size      
IFLA_INET6_ICMP6STATS	= 6 # statistics (icmpv6)
IFLA_INET6_TOKEN	= 7 # device token
__IFLA_INET6_MAX	= 8
IFLA_INET6_MAX		= (__IFLA_INET6_MAX - 1)

# enum
BRIDGE_MODE_UNSPEC	= 0
BRIDGE_MODE_HAIRPIN	= 1

# enum
IFLA_BRPORT_UNSPEC		= 0  
IFLA_BRPORT_STATE		= 1  # Spanning tree state   
IFLA_BRPORT_PRIORITY		= 2  # "             priority
IFLA_BRPORT_COST		= 3  # "             cost    
IFLA_BRPORT_MODE		= 4  # mode (hairpin)        
IFLA_BRPORT_GUARD		= 5  # bpdu guard            
IFLA_BRPORT_PROTECT		= 6  # root port protection  
IFLA_BRPORT_FAST_LEAVE		= 7  # multicast fast leave  
IFLA_BRPORT_LEARNING		= 8  # mac learning          
IFLA_BRPORT_UNICAST_FLOOD	= 9  # flood unicast traffic 
__IFLA_BRPORT_MAX		= 10
IFLA_BRPORT_MAX			= (__IFLA_BRPORT_MAX - 1)

class IflaCacheinfo(Structure):
    """struct ifla_cacheinfo
    """
    _fields_ = [("max_reasm_len",	c_uint32), # __u32 max_reasm_len;
                ("tstamp",		c_uint32), # __u32 tstamp;         /* ipv6InterfaceTable updated timestamp */
                ("reachable_time",	c_uint32), # __u32 reachable_time;
                ("retrans_time",	c_uint32)] # __u32 retrans_time;

# enum
IFLA_INFO_UNSPEC	= 0
IFLA_INFO_KIND		= 1
IFLA_INFO_DATA		= 2
IFLA_INFO_XSTATS	= 3
__IFLA_INFO_MAX		= 4
IFLA_INFO_MAX		= (__IFLA_INFO_MAX - 1)


# VLAN section
# enum
IFLA_VLAN_UNSPEC	= 0
IFLA_VLAN_ID		= 1
IFLA_VLAN_FLAGS		= 2
IFLA_VLAN_EGRESS_QOS	= 3
IFLA_VLAN_INGRESS_QOS	= 4
IFLA_VLAN_PROTOCOL	= 5
__IFLA_VLAN_MAX		= 6
IFLA_VLAN_MAX		= (__IFLA_VLAN_MAX - 1)

class IflaVlanFlags(Structure):
    """struct ifla_vlan_flags
    """
    _fields_ = [("flags",	c_uint32), # __u32 flags
                ("mask",	c_uint32)] # __u32 mask

# enum
IFLA_VLAN_QOS_UNSPEC	= 0
IFLA_VLAN_QOS_MAPPING	= 1
__IFLA_VLAN_QOS_MAX	= 2
IFLA_VLAN_QOS_MAX	= (__IFLA_VLAN_QOS_MAX - 1)

class IflaVlanQosMapping(Structure):
    """struct ifla_vlan_qos_mapping
    """
    _fields_ = [("from",	c_uint32), # __u32 from
                ("to",		c_uint32)] # __u32 to


# MACVLAN section
IFLA_MACVLAN_UNSPEC	= 0
IFLA_MACVLAN_MODE	= 1
IFLA_MACVLAN_FLAGS	= 2
__IFLA_MACVLAN_MAX	= 3
IFLA_MACVLAN_MAX	= (__IFLA_MACVLAN_MAX - 1)

class MacvlanMode(Enum):
    MACVLAN_MODE_PRIVATE	= 1
    MACVLAN_MODE_VEPA		= 2
    MACVLAN_MODE_BRIDGE		= 4
    MACVLAN_MODE_PASSTHRU	= 8
MACVLAN_MODE_PRIVATE	= 1
MACVLAN_MODE_VEPA	= 2
MACVLAN_MODE_BRIDGE	= 4
MACVLAN_MODE_PASSTHRU	= 8

MACVLAN_FLAG_NOPROMISC = 1


# VXLAN section
# enum
IFLA_VXLAN_UNSPEC	= 0
IFLA_VXLAN_ID		= 1
IFLA_VXLAN_GROUP	= 2  # group or remote address
IFLA_VXLAN_LINK		= 3
IFLA_VXLAN_LOCAL	= 4
IFLA_VXLAN_TTL		= 5
IFLA_VXLAN_TOS		= 6
IFLA_VXLAN_LEARNING	= 7
IFLA_VXLAN_AGEING	= 8
IFLA_VXLAN_LIMIT	= 9
IFLA_VXLAN_PORT_RANGE	= 10 # source port
IFLA_VXLAN_PROXY	= 11
IFLA_VXLAN_RSC		= 12
IFLA_VXLAN_L2MISS	= 13
IFLA_VXLAN_L3MISS	= 14
IFLA_VXLAN_PORT		= 15 # destination port
IFLA_VXLAN_GROUP6	= 16
IFLA_VXLAN_LOCAL6	= 17
__IFLA_VXLAN_MAX	= 18
IFLA_VXLAN_MAX		= (__IFLA_VXLAN_MAX - 1)

class IflaVxlanPortRange(Structure):
    """struct ifla_vxlan_port_range
    """
    _fields_ = [("low",		c_uint16), # __be16 low
                ("high", 	c_uint16)] # __be16 high


# Bonding section
# enum
IFLA_BOND_UNSPEC	= 0
IFLA_BOND_MODE		= 1
IFLA_BOND_ACTIVE_SLAVE	= 2
__IFLA_BOND_MAX		= 3
IFLA_BOND_MAX		= (__IFLA_BOND_MAX - 1)


# SR-IOV virtual function management section
# enum
IFLA_VF_INFO_UNSPEC	= 0
IFLA_VF_INFO		= 1
__IFLA_VF_INFO_MAX	= 2
IFLA_VF_INFO_MAX	= (__IFLA_VF_INFO_MAX - 1)

# enum
IFLA_VF_UNSPEC		= 0
IFLA_VF_MAC		= 1  # Hardware queue specific attributes
IFLA_VF_VLAN		= 2
IFLA_VF_TX_RATE		= 3  # TX Bandwidth Allocation
IFLA_VF_SPOOFCHK	= 4  # Spoof Checking on/off switch
IFLA_VF_LINK_STATE	= 5  # link state enable/disable/auto switch
__IFLA_VF_MAX		= 6
IFLA_VF_MAX		= (__IFLA_VF_MAX - 1)

class IflaVfMac(Structure):
    """struct ifla_vf_mac
    """
    _fields_ = [("vf",	c_uint32),     # __u32 vf
                ("mac",	c_uint8 * 32)] # __u8 mac[32] /* MAX_ADDR_LEN */

class IflaVfVlan(Structure):
    """struct ifla_vf_vlan
    """
    _fields_ = [("vf",		c_uint32), # __u32 vf
                ("vlan",	c_uint32), # __u32 vlan; /* 0 - 4095, 0 disables VLAN filter */
                ("qos", 	c_uint32)] # __u32 qos

class IflaVfTxRate(Structure):
    """struct ifla_vf_tx_rate
    """
    _fields_ = [("vf", 		c_uint32), # __u32 vf
                ("rate", 	c_uint32)] # __u32 rate; /* Max TX bandwidth in Mbps, 0 disables throttling */

class IflaVfSpoofchk(Structure):
    """struct ifla_vf_spoofchk
    """
    _fields_ = [("vf", 		c_uint32), # __u32 vf
                ("setting", 	c_uint32)] # __u32 setting

# enum
IFLA_VF_LINK_STATE_AUTO		= 0  # link state of the uplink
IFLA_VF_LINK_STATE_ENABLE	= 1  # link always up
IFLA_VF_LINK_STATE_DISABLE	= 2  # link always down
__IFLA_VF_LINK_STATE_MAX	= 3

class IflaVfLinkState(Structure):
    """struct ifla_vf_link_state
    """
    _fields_ = [("vf",		c_uint32), # __u32 vf
                ("link_state",	c_uint32)] # __u32 link_state


# VF ports management section
#
#	Nested layout of set/get msg is:
#
#		[IFLA_NUM_VF]
#		[IFLA_VF_PORTS]
#			[IFLA_VF_PORT]
#				[IFLA_PORT_*], ...
#			[IFLA_VF_PORT]
#				[IFLA_PORT_*], ...
#			...
#		[IFLA_PORT_SELF]
#			[IFLA_PORT_*], ...

# enum
IFLA_VF_PORT_UNSPEC	= 0
IFLA_VF_PORT		= 1  # nest
__IFLA_VF_PORT_MAX	= 2
IFLA_VF_PORT_MAX	= (__IFLA_VF_PORT_MAX - 1)

# enum
IFLA_PORT_UNSPEC	= 0
IFLA_PORT_VF		= 1  # __u32
IFLA_PORT_PROFILE	= 2  # string
IFLA_PORT_VSI_TYPE	= 3  # 802.1Qbg (pre-)standard VDP
IFLA_PORT_INSTANCE_UUID	= 4  # binary UUID
IFLA_PORT_HOST_UUID	= 5  # binary UUID
IFLA_PORT_REQUEST	= 6  # __u8
IFLA_PORT_RESPONSE	= 7  # __u16, output only
__IFLA_PORT_MAX		= 8
IFLA_PORT_MAX		= (__IFLA_PORT_MAX - 1)

PORT_PROFILE_MAX	= 40
PORT_UUID_MAX		= 16
PORT_SELF_VF		= -1

# enum
PORT_REQUEST_PREASSOCIATE	= 0
PORT_REQUEST_PREASSOCIATE_RR	= 1
PORT_REQUEST_ASSOCIATE		= 2
PORT_REQUEST_DISASSOCIATE	= 3

# enum
PORT_VDP_RESPONSE_SUCCESS			= 0
PORT_VDP_RESPONSE_INVALID_FORMAT		= 1
PORT_VDP_RESPONSE_INSUFFICIENT_RESOURCES	= 2
PORT_VDP_RESPONSE_UNUSED_VTID			= 3
PORT_VDP_RESPONSE_VTID_VIOLATION		= 4
PORT_VDP_RESPONSE_VTID_VERSION_VIOALTION	= 5
PORT_VDP_RESPONSE_OUT_OF_SYNC			= 6
# 0x08-0xFF reserved for future VDP use
PORT_PROFILE_RESPONSE_SUCCESS			= 0x100
PORT_PROFILE_RESPONSE_INPROGRESS		= 257
PORT_PROFILE_RESPONSE_INVALID			= 258
PORT_PROFILE_RESPONSE_BADSTATE			= 259
PORT_PROFILE_RESPONSE_INSUFFICIENT_RESOURCES	= 260
PORT_PROFILE_RESPONSE_ERROR			= 261

class IflaPortVsi(Structure):
    """struct ifla_port_vsi
    """
    _fields_ = [("mgr_id", 		c_uint8),	# __u8 vsi_mgr_id
                ("type_id",		(c_uint8 * 3)), # __u8 vsi_type_id[3]
                ("type_version",	c_uint8),	# __u8 vsi_type_version
                ("pad",			(c_uint8 * 3))] # __u8 pad[3]


# IPoIB section
# enum
IFLA_IPOIB_UNSPEC	= 0
IFLA_IPOIB_PKEY		= 1
IFLA_IPOIB_MODE		= 2
IFLA_IPOIB_UMCAST	= 3
__IFLA_IPOIB_MAX	= 4
IFLA_IPOIB_MAX = (__IFLA_IPOIB_MAX - 1)

# enum
IPOIB_MODE_DATAGRAM	= 0
IPOIB_MODE_CONNECTED	= 1


# HSR section
# enum
IFLA_HSR_UNSPEC			= 0
IFLA_HSR_SLAVE1			= 1
IFLA_HSR_SLAVE2			= 2
IFLA_HSR_MULTICAST_SPEC		= 3
IFLA_HSR_SUPERVISION_ADDR	= 4
IFLA_HSR_SEQ_NR			= 5
__IFLA_HSR_MAX			= 6
IFLA_HSR_MAX			= (__IFLA_HSR_MAX - 1)