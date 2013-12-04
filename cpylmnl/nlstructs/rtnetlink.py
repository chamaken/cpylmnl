# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import *
from cpylmnl import netlink


class Rtattr(netlink.UStructure):
    """struct rtattr

    Generic structure for encapsulation of optional route information.

    It is reminiscent of sockaddr, but with sa_family replaced
    with attribute type.
    """
    _fields_ = [("len", 	c_ushort),  # unsigned short	rta_len
                ("type", 	c_ushort)]  # unsigned short	rta_type


class Rtmsg(netlink.UStructure):
    """struct rtmsg

    Definitions used in routing table administration.
    """
    _fields_ = [("family", 	c_ubyte), # unsigned char rtm_family                                   
                ("dst_len", 	c_ubyte), # unsigned char rtm_dst_len                                  
                ("src_len", 	c_ubyte), # unsigned char rtm_src_len                                  
                ("tos", 	c_ubyte), # unsigned char rtm_tos                                      
                ("table", 	c_ubyte), # unsigned char rtm_table - Routing table id                 
                ("protocol", 	c_ubyte), # unsigned char rtm_protocol - Routing protocol; see below   
                ("scope", 	c_ubyte), # unsigned char rtm_scope - See below                        
                ("type", 	c_ubyte), # unsigned char rtm_type - See below                         
                ("flags", 	c_uint)]  # unsigned	  rtm_flags


class Rtgenmsg(netlink.UStructure):
    """struct rtgenmsg

    General form of address family dependent message.
    """
    _fields_ = [("family",	c_ubyte)] # unsigned char		rtgen_family


class Ifinfomsg(netlink.UStructure):
    """struct ifinfomsg

    Link layer specific messages.
    struct ifinfomsg
    passes link level specific information, not dependent
    on network protocol.
    """

    _fields_ = [("family",	c_ubyte),  # unsigned char  ifi_family
                ("_pad",	c_ubyte),  # unsigned char   __ifi_pad
                ("type",	c_ushort), # unsigned short ifi_type   /* ARPHRD_* */
                ("index",	c_int),    # int            ifi_index  /* Link index	*/
                ("flags",	c_uint),   # unsigned	    ifi_flags  /* IFF_* flags	*/
                ("change",	c_uint)]   # unsigned	    ifi_change /* IFF_* change mask */
