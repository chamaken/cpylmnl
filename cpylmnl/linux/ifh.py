# -*- coding: utf-8 -*-

# IFF_ only
IFF_UP		= 0x1		# interface is up
IFF_BROADCAST	= 0x2		# broadcast address valid
IFF_DEBUG	= 0x4		# turn on debugging
IFF_LOOPBACK	= 0x8		# is a loopback net
IFF_POINTOPOINT	= 0x10		# interface is has p-p link
IFF_NOTRAILERS	= 0x20		# avoid use of trailers
IFF_RUNNING	= 0x40		# interface RFC2863 OPER_UP
IFF_NOARP	= 0x80		# no ARP protocol
IFF_PROMISC	= 0x100		# receive all packets
IFF_ALLMULTI	= 0x200		# receive all multicast packets

IFF_MASTER	= 0x400		# master of a load balancer
IFF_SLAVE	= 0x800		# slave of a load balancer

IFF_MULTICAST	= 0x1000	# Supports multicast

IFF_PORTSEL	= 0x2000	# can set media type
IFF_AUTOMEDIA	= 0x4000	# auto media select active
IFF_DYNAMIC	= 0x8000	# dialup device with changing addresses

IFF_LOWER_UP	= 0x10000	# driver signals L1 up
IFF_DORMANT	= 0x20000	# driver signals dormant

IFF_ECHO	= 0x40000	# echo sent packets

IFF_VOLATILE	= (IFF_LOOPBACK|IFF_POINTOPOINT|IFF_BROADCAST|IFF_ECHO|\
		   IFF_MASTER|IFF_SLAVE|IFF_RUNNING|IFF_LOWER_UP|IFF_DORMANT)

# Private (from user) interface flags (netdevice->priv_flags).
IFF_802_1Q_VLAN 	= 0x1	# 802.1Q VLAN device.
IFF_EBRIDGE		= 0x2	# Ethernet bridging device.
IFF_SLAVE_INACTIVE	= 0x4	# bonding slave not the curr. active
IFF_MASTER_8023AD	= 0x8	# bonding master, 802.3ad.
IFF_MASTER_ALB		= 0x10	# bonding master, balance-alb.
IFF_BONDING		= 0x20	# bonding master or slave
IFF_SLAVE_NEEDARP	= 0x40	# need ARPs for validation
IFF_ISATAP		= 0x80	# ISATAP interface (RFC4214)
IFF_MASTER_ARPMON	= 0x100	# bonding master, ARP mon in use
IFF_WAN_HDLC		= 0x200	# WAN HDLC device
IFF_XMIT_DST_RELEASE 	= 0x400	# dev_hard_start_xmit() is allowed to
				# release skb->dst

IFF_DONT_BRIDGE		= 0x800		# disallow bridging this ether dev
IFF_DISABLE_NETPOLL	= 0x1000	# disable netpoll at run-time
IFF_MACVLAN_PORT	= 0x2000	# device used as macvlan port
IFF_BRIDGE_PORT		= 0x4000	# device used as bridge port
IFF_OVS_DATAPATH	= 0x8000	# device used as Open vSwitch
					# datapath port
IFF_TX_SKB_SHARING	= 0x10000	# The interface supports sharing
				 	# skbs on transmit
IFF_UNICAST_FLT		= 0x20000	# Supports unicast filtering
IFF_TEAM_PORT		= 0x40000	# device used as team port
IFF_SUPP_NOFCS		= 0x80000	# device supports sending custom FCS
IFF_LIVE_ADDR_CHANGE 	= 0x100000	# device supports hardware address
				 	# change when it's running
IFF_MACVLAN 		= 0x200000	# Macvlan device
