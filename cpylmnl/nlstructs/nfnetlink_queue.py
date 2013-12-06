# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import *
from cpylmnl import netlink


class NfqnlMsgPacketHdr(netlink.UStructure):
    _fields_ = [("packet_id",	c_uint32), # unique ID of packet in queue
                ("hw_protocol", c_uint16), # hw protocol (network order)
                ("hook",        c_uint8)]  # netfilter hook


class NfqnlMsgPacketHw(netlink.UStructure):
    _fields_ = [("hw_addrlen",  c_uint16),
                ("_pad",        c_uint16),
                ("hw_addr",     (c_ubyte * 8))]


class NfqnlMsgPacketTimestamp(netlink.UStructure):
    _fields_ = [("sec",         c_uint64),
                ("usec",	c_uint64)]


class NfqnlMsgVerdictHdr(netlink.UStructure):
    _fields_ = [("verdict",     c_uint32),
                ("id",          c_uint32)]


class NfqnlMsgConfigCmd(netlink.UStructure):
    _fields_ = [("command",     c_uint8),  # nfqnl_msg_config_cmds
                ("_pad",        c_uint8),
                ("pf",          c_uint16)] # AF_xxx for PF_[UN]BIND


class NfqnlMsgConfigParams(netlink.UStructure):
    _fields_ = [("copy_range",  c_uint32),
                ("copy_mode",   c_uint8)]  # enum nfqnl_config_mode
