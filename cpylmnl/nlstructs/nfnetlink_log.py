# -*- coding: utf-8 -*-

from __future__ import absolute_import

from cpylmnl import netlink

class NfulnlMsgPacketHdr(netlink.UStructure):
    """struct nfulnl_msg_packet_hdr

    General form of address family dependent message.
    """
    _fields_ = [("hw_protocol",	c_uint16), # __be16 hw_protocol /* hw protocol (network order) */
                ("hook",	c_uint8),  # __u8   hook        /* netfilter hook */
                ("_pad",	c_uint8)]  # __u8   _pad


class NfulnlMsgPacketHw(netlink.UStructure):
    """struct nfulnl_msg_packet_hw
    """
    _fields_ = [("hw_addrlen",	c_uint16),    # __be16 hw_addrlen;
                ("_pad",	c_uint16),    # __u16  _pad;
                ("hw_addr",	c_uint8 * 8)] # __u8   hw_addr[8];


class NfulnlMsgPacketTimestamp(netlink.UStructure):
    """struct nfulnl_msg_packet_timestamp
    """
    _fields_ = [("sec",		c_uint64), # __aligned_be64 sec;
                ("usec",	c_uint64)] # __aligned_be64 usec;


class NfulnlMsgConfigCmd(netlink.UStructure):
    """struct nfulnl_msg_config_cmd
    """
    _fields_ = [("command",	c_uint8)] # __u8 command; /* nfulnl_msg_config_cmds */


class NfulnlMsgConfigMode(netlink.UStructure):
    """struct nfulnl_msg_config_mode
    """

    _fields_ = [("copy_range",	c_uint32), # __be32 copy_range;
                ("copy_mode",	c_uint8),  # __u8   copy_mode;
                ("_pad",	c_uint8)]  # __u8   _pad;
