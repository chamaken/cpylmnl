# -*- coding: utf-8 -*-

# IFF_ only

class NetDeviceFlags(object):
    """struct net_device flags

    IFF_UP: interface is up. Can be toggled through sysfs.
    IFF_BROADCAST: broadcast address valid. Volatile.
    IFF_DEBUG: turn on debugging. Can be toggled through sysfs.
    IFF_LOOPBACK: is a loopback net. Volatile.
    IFF_POINTOPOINT: interface is has p-p link. Volatile.
    IFF_NOTRAILERS: avoid use of trailers. Can be toggled through sysfs.
                    Volatile.
    IFF_RUNNING: interface RFC2863 OPER_UP. Volatile.
    IFF_NOARP: no ARP protocol. Can be toggled through sysfs. Volatile.
    IFF_PROMISC: receive all packets. Can be toggled through sysfs.
    IFF_ALLMULTI: receive all multicast packets. Can be toggled through
                  sysfs.
    IFF_MASTER: master of a load balancer. Volatile.
    IFF_SLAVE: slave of a load balancer. Volatile.
    IFF_MULTICAST: Supports multicast. Can be toggled through sysfs.
    IFF_PORTSEL: can set media type. Can be toggled through sysfs.
    IFF_AUTOMEDIA: auto media select active. Can be toggled through sysfs.
    IFF_DYNAMIC: dialup device with changing addresses. Can be toggled
                 through sysfs.
    IFF_LOWER_UP: driver signals L1 up. Volatile.
    IFF_DORMANT: driver signals dormant. Volatile.
    IFF_ECHO: echo sent packets. Volatile.
    """
    IFF_UP			= 1<<0  # sysfs
    IFF_BROADCAST		= 1<<1  # volatile
    IFF_DEBUG			= 1<<2  # sysfs
    IFF_LOOPBACK		= 1<<3  # volatile
    IFF_POINTOPOINT		= 1<<4  # volatile
    IFF_NOTRAILERS		= 1<<5  # sysfs
    IFF_RUNNING			= 1<<6  # volatile
    IFF_NOARP			= 1<<7  # sysfs
    IFF_PROMISC			= 1<<8  # sysfs
    IFF_ALLMULTI		= 1<<9  # sysfs
    IFF_MASTER			= 1<<10 # volatile
    IFF_SLAVE			= 1<<11 # volatile
    IFF_MULTICAST		= 1<<12 # sysfs
    IFF_PORTSEL			= 1<<13 # sysfs
    IFF_AUTOMEDIA		= 1<<14 # sysfs
    IFF_DYNAMIC			= 1<<15 # sysfs
    IFF_LOWER_UP		= 1<<16 # volatile
    IFF_DORMANT			= 1<<17 # volatile
    IFF_ECHO			= 1<<18 # volatile
    
IFF_UP		=		NetDeviceFlags.IFF_UP
IFF_BROADCAST	=		NetDeviceFlags.IFF_BROADCAST
IFF_DEBUG	=		NetDeviceFlags.IFF_DEBUG
IFF_LOOPBACK	=		NetDeviceFlags.IFF_LOOPBACK
IFF_POINTOPOINT	=		NetDeviceFlags.IFF_POINTOPOINT
IFF_NOTRAILERS	=		NetDeviceFlags.IFF_NOTRAILERS
IFF_RUNNING	=		NetDeviceFlags.IFF_RUNNING
IFF_NOARP	=		NetDeviceFlags.IFF_NOARP
IFF_PROMISC	=		NetDeviceFlags.IFF_PROMISC
IFF_ALLMULTI	=		NetDeviceFlags.IFF_ALLMULTI
IFF_MASTER	=		NetDeviceFlags.IFF_MASTER
IFF_SLAVE	=		NetDeviceFlags.IFF_SLAVE
IFF_MULTICAST	=		NetDeviceFlags.IFF_MULTICAST
IFF_PORTSEL	=		NetDeviceFlags.IFF_PORTSEL
IFF_AUTOMEDIA	=		NetDeviceFlags.IFF_AUTOMEDIA
IFF_DYNAMIC	=		NetDeviceFlags.IFF_DYNAMIC
IFF_LOWER_UP	=		NetDeviceFlags.IFF_LOWER_UP
IFF_DORMANT	=		NetDeviceFlags.IFF_DORMANT
IFF_ECHO	=		NetDeviceFlags.IFF_ECHO
 
IFF_VOLATILE	=		(NetDeviceFlags.IFF_LOOPBACK|NetDeviceFlags.IFF_POINTOPOINT|\
    				 NetDeviceFlags.IFF_BROADCAST|NetDeviceFlags.IFF_ECHO|\
                                 NetDeviceFlags.IFF_MASTER|NetDeviceFlags.IFF_SLAVE|\
                                 NetDeviceFlags.IFF_RUNNING|NetDeviceFlags.IFF_LOWER_UP|\
                                 NetDeviceFlags.IFF_DORMANT)
