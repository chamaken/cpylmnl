# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import *
from cpylmnl import netlink


class Genlmsghdr(netlink.UStructure):
    _fields_ = [("cmd",		c_uint8),   # __u8	cmd
                ("version",	c_uint8),   # __u8	version
                ("reserved",	c_uint16)]  # __u16	reserved
