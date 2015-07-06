# -*- coding: utf-8 -*-

import ctypes

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnetlink


# This struct should be in sync with struct rtnl_link_stats64
class RtnlLinkStats(ctypes.Structure):
    """struct rtnl_link_stats
    """
    _fields_ = [("rx_packets",		ctypes.c_uint32), # __u32 rx_packets	 /* total packets received	 */
                ("tx_packets",		ctypes.c_uint32), # __u32 tx_packets	 /* total packets transmitted	 */
                ("rx_bytes",		ctypes.c_uint32), # __u32 rx_bytes	 /* total bytes received	 */
                ("tx_bytes",		ctypes.c_uint32), # __u32 tx_bytes	 /* total bytes transmitted	 */
                ("rx_errors",		ctypes.c_uint32), # __u32 rx_errors	 /* bad packets received	 */
                ("tx_errors",		ctypes.c_uint32), # __u32 tx_errors	 /* packet transmit problems	 */
                ("rx_dropped",		ctypes.c_uint32), # __u32 rx_dropped	 /* no space in linux buffers	 */
                ("tx_dropped",		ctypes.c_uint32), # __u32 tx_dropped	 /* no space available in linux	 */
                ("multicast",		ctypes.c_uint32), # __u32 multicast	 /* multicast packets received	 */
                ("collisions",		ctypes.c_uint32), # __u32 collisions

                ## detailed rx_errors:
                ("rx_length_errors",	ctypes.c_uint32), # __u32 rx_length_errors
                ("rx_over_errors",	ctypes.c_uint32), # __u32 rx_over_errors   /* receiver ring buff overflow  */
                ("rx_crc_errors",	ctypes.c_uint32), # __u32 rx_crc_errors    /* recved pkt with crc error    */
                ("rx_frame_errors",	ctypes.c_uint32), # __u32 rx_frame_errors  /* recv'd frame alignment error */
                ("rx_fifo_errors",	ctypes.c_uint32), # __u32 rx_fifo_errors   /* recv'r fifo overrun	    */
                ("rx_missed_errors",	ctypes.c_uint32), # __u32 rx_missed_errors /* receiver missed packet	    */

                ## detailed tx_errors
                ("tx_aborted_errors",	ctypes.c_uint32), # __u32 tx_aborted_errors
                ("tx_carrier_errors",	ctypes.c_uint32), # __u32 tx_carrier_errors
                ("tx_fifo_errors",	ctypes.c_uint32), # __u32 tx_fifo_errors
                ("tx_heartbear_errors",	ctypes.c_uint32), # __u32 tx_heartbeat_errors
                ("tx_window_errors",	ctypes.c_uint32), # __u32 tx_window_errors

                ## for cslip etc
                ("rx_compressed",	ctypes.c_uint32), # __u32 rx_compressed
                ("tx_compressed",	ctypes.c_uint32)] # __u32 tx_compressed

# The main device statistics structure
class RtnlLinkStats64(ctypes.Structure):
    """struct rtnl_link_stats64
    """
    _fields_ = [("rx_packets",		ctypes.c_uint64), # __u64 rx_packets	 /* total packets received	 */
                ("tx_packets",		ctypes.c_uint64), # __u64 tx_packets	 /* total packets transmitted	 */
                ("rx_bytes",		ctypes.c_uint64), # __u64 rx_bytes	 /* total bytes received	 */
                ("tx_bytes",		ctypes.c_uint64), # __u64 tx_bytes	 /* total bytes transmitted	 */
                ("rx_errors",		ctypes.c_uint64), # __u64 rx_errors	 /* bad packets received	 */
                ("tx_errors",		ctypes.c_uint64), # __u64 tx_errors	 /* packet transmit problems	 */
                ("rx_dropped",		ctypes.c_uint64), # __u64 rx_dropped	 /* no space in linux buffers	 */
                ("tx_dropped",		ctypes.c_uint64), # __u64 tx_dropped	 /* no space available in linux	 */
                ("multicast",		ctypes.c_uint64), # __u64 multicast	 /* multicast packets received	 */
                ("collisions",		ctypes.c_uint64), # __u64 collisions

                ## detailed rx_errors:
                ("rx_length_errors",	ctypes.c_uint64), # __u64 rx_length_errors
                ("rx_over_errors",	ctypes.c_uint64), # __u64 rx_over_errors   /* receiver ring buff overflow  */
                ("rx_crc_errors",	ctypes.c_uint64), # __u64 rx_crc_errors    /* recved pkt with crc error    */
                ("rx_frame_errors",	ctypes.c_uint64), # __u64 rx_frame_errors  /* recv'd frame alignment error */
                ("rx_fifo_errors",	ctypes.c_uint64), # __u64 rx_fifo_errors   /* recv'r fifo overrun	    */
                ("rx_missed_errors",	ctypes.c_uint64), # __u64 rx_missed_errors /* receiver missed packet	    */

                ## detailed tx_errors
                ("tx_aborted_errors",	ctypes.c_uint64), # __u64 tx_aborted_errors
                ("tx_carrier_errors",	ctypes.c_uint64), # __u64 tx_carrier_errors
                ("tx_fifo_errors",	ctypes.c_uint64), # __u64 tx_fifo_errors
                ("tx_heartbear_errors",	ctypes.c_uint64), # __u64 tx_heartbeat_errors
                ("tx_window_errors",	ctypes.c_uint64), # __u64 tx_window_errors

                ## for cslip etc
                ("rx_compressed",	ctypes.c_uint64), # __u64 rx_compressed
                ("tx_compressed",	ctypes.c_uint64)] # __u64 tx_compressed

# The struct should be in sync with struct ifmap
class RtnlLinkIfmap(ctypes.Structure):
    """struct rtnl_link_ifmap
    """
    _fields_ = [("mem_start",	ctypes.c_uint64), # __u64	mem_start
                ("mem_end",	ctypes.c_uint64), # __u64	mem_end
                ("base_addr",	ctypes.c_uint64), # __u64	base_addr
                ("irq",		ctypes.c_uint16), # __u16	irq
                ("dma",		ctypes.c_uint8),  # __u8	dma
                ("port",	ctypes.c_uint8)]  # __u8	port


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
IFLA_CARRIER_CHANGES	= 35
IFLA_PHYS_SWITCH_ID	= 36
IFLA_LINK_NETNSID	= 37
IFLA_PHYS_PORT_NAME	= 38
__IFLA_MAX		= 39
IFLA_MAX = (__IFLA_MAX - 1)


# backwards compatibility for userspace
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(ctypes.sizeof(struct ifinfomsg))))
def IFLA_RTA(r):	return rtnetlink.Rtattr.from_pointer(addressof(r) + netlink.NLMSG_ALIGN(ctypes.sizeof(rtnetlink.Ifinfomsg)))
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,ctypes.sizeof(struct ifinfomsg))
def IFLA_PAYLOAD(n):	return netlink.NLMSG_PAYLOAD(n, ctypes.sizeof(rtnetlink.Ifinfomsg))


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
IFLA_INET6_UNSPEC		= 0
IFLA_INET6_FLAGS		= 1 # link flags
IFLA_INET6_CONF			= 2 # sysctl parameters
IFLA_INET6_STATS		= 3 # statistics
IFLA_INET6_MCAST		= 4 # MC things. What of them?
IFLA_INET6_CACHEINFO		= 5 # time values and max reasm size      
IFLA_INET6_ICMP6STATS		= 6 # statistics (icmpv6)
IFLA_INET6_TOKEN		= 7 # device token
IFLA_INET6_ADDR_GEN_MODE	= 8 # implicit address generator mode
__IFLA_INET6_MAX		= 9
IFLA_INET6_MAX			= (__IFLA_INET6_MAX - 1)

class In6AddrGenMode(object):
    IN6_ADDR_GEN_MODE_EUI64		= 0
    IN6_ADDR_GEN_MODE_NONE		= 1
    IN6_ADDR_GEN_MODE_STABLE_PRIVACY	= 2
IN6_ADDR_GEN_MODE_EUI64	= In6AddrGenMode.IN6_ADDR_GEN_MODE_EUI64
IN6_ADDR_GEN_MODE_NONE	= In6AddrGenMode.IN6_ADDR_GEN_MODE_NONE
IN6_ADDR_GEN_MODE_STABLE_PRIVACY = In6AddrGenMode.IN6_ADDR_GEN_MODE_STABLE_PRIVACY

# Bridge section
# enum
IFLA_BR_UNSPEC		= 0
IFLA_BR_FORWARD_DELAY	= 1
IFLA_BR_HELLO_TIME	= 2
IFLA_BR_MAX_AGE		= 3
IFLA_BR_AGEING_TIME	= 4
IFLA_BR_STP_STATE	= 5
IFLA_BR_PRIORITY	= 6
__IFLA_BR_MAX		= 7
IFLA_BR_MAX		= (__IFLA_BR_MAX - 1)

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
IFLA_BRPORT_PROXYARP		= 10 # proxy ARP
IFLA_BRPORT_LEARNING_SYNC	= 11 # mac learning sync from device
IFLA_BRPORT_PROXYARP_WIFI	= 12 # proxy ARP for Wi-Fi
__IFLA_BRPORT_MAX		= 13
IFLA_BRPORT_MAX			= (__IFLA_BRPORT_MAX - 1)

class IflaCacheinfo(ctypes.Structure):
    """struct ifla_cacheinfo
    """
    _fields_ = [("max_reasm_len",	ctypes.c_uint32), # __u32 max_reasm_len;
                ("tstamp",		ctypes.c_uint32), # __u32 tstamp;         /* ipv6InterfaceTable updated timestamp */
                ("reachable_time",	ctypes.c_uint32), # __u32 reachable_time;
                ("retrans_time",	ctypes.c_uint32)] # __u32 retrans_time;

# enum
IFLA_INFO_UNSPEC	= 0
IFLA_INFO_KIND		= 1
IFLA_INFO_DATA		= 2
IFLA_INFO_XSTATS	= 3
IFLA_INFO_SLAVE_KIND	= 4
IFLA_INFO_SLAVE_DATA	= 5
__IFLA_INFO_MAX		= 6
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

class IflaVlanFlags(ctypes.Structure):
    """struct ifla_vlan_flags
    """
    _fields_ = [("flags",	ctypes.c_uint32), # __u32 flags
                ("mask",	ctypes.c_uint32)] # __u32 mask

# enum
IFLA_VLAN_QOS_UNSPEC	= 0
IFLA_VLAN_QOS_MAPPING	= 1
__IFLA_VLAN_QOS_MAX	= 2
IFLA_VLAN_QOS_MAX	= (__IFLA_VLAN_QOS_MAX - 1)

class IflaVlanQosMapping(ctypes.Structure):
    """struct ifla_vlan_qos_mapping
    """
    _fields_ = [("from",	ctypes.c_uint32), # __u32 from
                ("to",		ctypes.c_uint32)] # __u32 to


# MACVLAN section
IFLA_MACVLAN_UNSPEC		= 0
IFLA_MACVLAN_MODE		= 1
IFLA_MACVLAN_FLAGS		= 2
IFLA_MACVLAN_MACADDR_MODE	= 3
IFLA_MACVLAN_MACADDR		= 4
IFLA_MACVLAN_MACADDR_DATA	= 5
IFLA_MACVLAN_MACADDR_COUNT	= 6
__IFLA_MACVLAN_MAX		= 7
IFLA_MACVLAN_MAX		= (__IFLA_MACVLAN_MAX - 1)

class MacvlanMode(object):
    MACVLAN_MODE_PRIVATE	= 1
    MACVLAN_MODE_VEPA		= 2
    MACVLAN_MODE_BRIDGE		= 4
    MACVLAN_MODE_PASSTHRU	= 8
    MACVLAN_MODE_SOURCE		= 16
MACVLAN_MODE_PRIVATE	= MacvlanMode.MACVLAN_MODE_PRIVATE
MACVLAN_MODE_VEPA	= MacvlanMode.MACVLAN_MODE_VEPA
MACVLAN_MODE_BRIDGE	= MacvlanMode.MACVLAN_MODE_BRIDGE
MACVLAN_MODE_PASSTHRU	= MacvlanMode.MACVLAN_MODE_PASSTHRU
MACVLAN_MODE_SOURCE	= MacvlanMode.MACVLAN_MODE_SOURCE

class MacvlanMacaddrMode(object):
    MACVLAN_MACADDR_ADD		= 0
    MACVLAN_MACADDR_DEL		= 1
    MACVLAN_MACADDR_FLUSH	= 2
    MACVLAN_MACADDR_SET		= 3
MACVLAN_MACADDR_ADD	= MacvlanMacaddrMode.MACVLAN_MACADDR_ADD
MACVLAN_MACADDR_DEL	= MacvlanMacaddrMode.MACVLAN_MACADDR_DEL
MACVLAN_MACADDR_FLUSH	= MacvlanMacaddrMode.MACVLAN_MACADDR_FLUSH
MACVLAN_MACADDR_SET	= MacvlanMacaddrMode.MACVLAN_MACADDR_SET

MACVLAN_FLAG_NOPROMISC = 1


# IPVLAN section
# enum
IFLA_IPVLAN_UNSPEC	= 0
IFLA_IPVLAN_MODE	= 1
__IFLA_IPVLAN_MAX	= 2
IFLA_IPVLAN_MAX		= (__IFLA_IPVLAN_MAX - 1)

class IpvlanMode(object):
    IPVLAN_MODE_L2	= 0
    IPVLAN_MODE_L3	= 1
    IPVLAN_MODE_MAX	= 2
IPVLAN_MODE_L2	= IpvlanMode.IPVLAN_MODE_L2
IPVLAN_MODE_L3	= IpvlanMode.IPVLAN_MODE_L3
IPVLAN_MODE_MAX	= IpvlanMode.IPVLAN_MODE_MAX
    

# VXLAN section
# enum
IFLA_VXLAN_UNSPEC		= 0
IFLA_VXLAN_ID			= 1
IFLA_VXLAN_GROUP		= 2  # group or remote address
IFLA_VXLAN_LINK			= 3
IFLA_VXLAN_LOCAL		= 4
IFLA_VXLAN_TTL			= 5
IFLA_VXLAN_TOS			= 6
IFLA_VXLAN_LEARNING		= 7
IFLA_VXLAN_AGEING		= 8
IFLA_VXLAN_LIMIT		= 9
IFLA_VXLAN_PORT_RANGE		= 10 # source port
IFLA_VXLAN_PROXY		= 11
IFLA_VXLAN_RSC			= 12
IFLA_VXLAN_L2MISS		= 13
IFLA_VXLAN_L3MISS		= 14
IFLA_VXLAN_PORT			= 15 # destination port
IFLA_VXLAN_GROUP6		= 16
IFLA_VXLAN_LOCAL6		= 17
IFLA_VXLAN_UDP_CSUM		= 18
IFLA_VXLAN_UDP_ZERO_CSUM6_TX	= 19
IFLA_VXLAN_UDP_ZERO_CSUM6_RX	= 20
IFLA_VXLAN_REMCSUM_TX		= 21
IFLA_VXLAN_REMCSUM_RX		= 22
IFLA_VXLAN_GBP			= 23
IFLA_VXLAN_REMCSUM_NOPARTIAL	= 24
__IFLA_VXLAN_MAX		= 25
IFLA_VXLAN_MAX			= (__IFLA_VXLAN_MAX - 1)

class IflaVxlanPortRange(ctypes.Structure):
    """struct ifla_vxlan_port_range
    """
    _fields_ = [("low",		ctypes.c_uint16), # __be16 low
                ("high", 	ctypes.c_uint16)] # __be16 high

# GENEVE section
IFLA_GENEVE_UNSPEC	= 0
IFLA_GENEVE_ID		= 1
IFLA_GENEVE_REMOTE	= 2
IFLA_GENEVE_TTL		= 3
IFLA_GENEVE_TOS		= 4
__IFLA_GENEVE_MAX	= 5
IFLA_GENEVE_MAX		= (__IFLA_GENEVE_MAX - 1)

# Bonding section
# enum
IFLA_BOND_UNSPEC		= 0
IFLA_BOND_MODE			= 1
IFLA_BOND_ACTIVE_SLAVE		= 2
IFLA_BOND_MIIMON		= 3
IFLA_BOND_UPDELAY		= 4
IFLA_BOND_DOWNDELAY		= 5
IFLA_BOND_USE_CARRIER		= 6
IFLA_BOND_ARP_INTERVAL		= 7
IFLA_BOND_ARP_IP_TARGET		= 8
IFLA_BOND_ARP_VALIDATE		= 9
IFLA_BOND_ARP_ALL_TARGETS	= 10
IFLA_BOND_PRIMARY		= 11
IFLA_BOND_PRIMARY_RESELECT	= 12
IFLA_BOND_FAIL_OVER_MAC		= 13
IFLA_BOND_XMIT_HASH_POLICY	= 14
IFLA_BOND_RESEND_IGMP		= 15
IFLA_BOND_NUM_PEER_NOTIF	= 16
IFLA_BOND_ALL_SLAVES_ACTIVE	= 17
IFLA_BOND_MIN_LINKS		= 18
IFLA_BOND_LP_INTERVAL		= 19
IFLA_BOND_PACKETS_PER_SLAVE	= 20
IFLA_BOND_AD_LACP_RATE		= 21
IFLA_BOND_AD_SELECT		= 22
IFLA_BOND_AD_INFO		= 23
IFLA_BOND_AD_ACTOR_SYS_PRIO	= 24
IFLA_BOND_AD_USER_PORT_KEY	= 25
IFLA_BOND_AD_ACTOR_SYSTEM	= 26
__IFLA_BOND_MAX			= 27
IFLA_BOND_MAX		= (__IFLA_BOND_MAX - 1)

# enum
IFLA_BOND_AD_INFO_UNSPEC	= 0
IFLA_BOND_AD_INFO_AGGREGATOR	= 1
IFLA_BOND_AD_INFO_NUM_PORTS	= 2
IFLA_BOND_AD_INFO_ACTOR_KEY	= 3
IFLA_BOND_AD_INFO_PARTNER_KEY	= 4
IFLA_BOND_AD_INFO_PARTNER_MAC	= 5
__IFLA_BOND_AD_INFO_MAX		= 6
IFLA_BOND_AD_INFO_MAX		= (__IFLA_BOND_AD_INFO_MAX - 1)

# enum
IFLA_BOND_SLAVE_UNSPEC			= 0
IFLA_BOND_SLAVE_STATE			= 1
IFLA_BOND_SLAVE_MII_STATUS		= 2
IFLA_BOND_SLAVE_LINK_FAILURE_COUNT	= 3
IFLA_BOND_SLAVE_PERM_HWADDR		= 4
IFLA_BOND_SLAVE_QUEUE_ID		= 5
IFLA_BOND_SLAVE_AD_AGGREGATOR_ID	= 6
IFLA_BOND_SLAVE_AD_ACTOR_OPER_PORT_STATE	= 7
IFLA_BOND_SLAVE_AD_PARTNER_OPER_PORT_STATE	= 8
__IFLA_BOND_SLAVE_MAX			= 9
IFLA_BOND_SLAVE_MAX			= (__IFLA_BOND_SLAVE_MAX - 1)

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
IFLA_VF_TX_RATE		= 3  # Max TX Bandwidth Allocation
IFLA_VF_SPOOFCHK	= 4  # Spoof Checking on/off switch
IFLA_VF_LINK_STATE	= 5  # link state enable/disable/auto switch
IFLA_VF_RATE		= 6  # Min and Max TX Bandwidth Allocation
IFLA_VF_RSS_QUERY_EN	= 7  # RSS Redirection Table and Hash Key query
                             # on/off switch
IFLA_VF_STATS		= 8  # network device statistics
__IFLA_VF_MAX		= 9
IFLA_VF_MAX		= (__IFLA_VF_MAX - 1)

class IflaVfMac(ctypes.Structure):
    """struct ifla_vf_mac
    """
    _fields_ = [("vf",	ctypes.c_uint32),     # __u32 vf
                ("mac",	ctypes.c_uint8 * 32)] # __u8 mac[32] /* MAX_ADDR_LEN */

class IflaVfVlan(ctypes.Structure):
    """struct ifla_vf_vlan
    """
    _fields_ = [("vf",		ctypes.c_uint32), # __u32 vf
                ("vlan",	ctypes.c_uint32), # __u32 vlan; /* 0 - 4095, 0 disables VLAN filter */
                ("qos", 	ctypes.c_uint32)] # __u32 qos

class IflaVfTxRate(ctypes.Structure):
    """struct ifla_vf_tx_rate
    """
    _fields_ = [("vf", 		ctypes.c_uint32), # __u32 vf
                ("rate", 	ctypes.c_uint32)] # __u32 rate; /* Max TX bandwidth in Mbps, 0 disables throttling */

class IflaVfRate(ctypes.Structure):
    """struct ifla_vf_rate
    """
    _fields_ = [("vf",		ctypes.c_uint32), # __u32 vf;
                ("min_tx_rate", ctypes.c_uint32), # __u32 min_tx_rate; /* Min Bandwidth in Mbps */
                ("max_tx_rate", ctypes.c_uint32)] # __u32 max_tx_rate; /* Max Bandwidth in Mbps */

class IflaVfSpoofchk(ctypes.Structure):
    """struct ifla_vf_spoofchk
    """
    _fields_ = [("vf", 		ctypes.c_uint32), # __u32 vf
                ("setting", 	ctypes.c_uint32)] # __u32 setting

# enum
IFLA_VF_LINK_STATE_AUTO		= 0  # link state of the uplink
IFLA_VF_LINK_STATE_ENABLE	= 1  # link always up
IFLA_VF_LINK_STATE_DISABLE	= 2  # link always down
__IFLA_VF_LINK_STATE_MAX	= 3

class IflaVfLinkState(ctypes.Structure):
    """struct ifla_vf_link_state
    """
    _fields_ = [("vf",		ctypes.c_uint32), # __u32 vf
                ("link_state",	ctypes.c_uint32)] # __u32 link_state


class IflaVfRssQueryEn(ctypes.Structure):
    """sruct ifla_vf_rss_query_en
    """
    _fields_ = [("vf",		ctypes.c_uint32), # __u32 vf
                ("setting",	ctypes.c_uint32)] # __u32 setting

IFLA_VF_STATS_RX_PACKETS	= 0
IFLA_VF_STATS_TX_PACKETS	= 1
IFLA_VF_STATS_RX_BYTES		= 2
IFLA_VF_STATS_TX_BYTES		= 3
IFLA_VF_STATS_BROADCAST		= 4
IFLA_VF_STATS_MULTICAST		= 5
__IFLA_VF_STATS_MAX		= 6
IFLA_VF_STATS_MAX		= (__IFLA_VF_STATS_MAX - 1)

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

class IflaPortVsi(ctypes.Structure):
    """struct ifla_port_vsi
    """
    _fields_ = [("vsi_mgr_id", 		ctypes.c_uint8),	# __u8 vsi_mgr_id
                ("vsi_type_id",		(ctypes.c_uint8 * 3)),	# __u8 vsi_type_id[3]
                ("vsi_type_version",	ctypes.c_uint8),	# __u8 vsi_type_version
                ("pad",			(ctypes.c_uint8 * 3))]	# __u8 pad[3]


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
