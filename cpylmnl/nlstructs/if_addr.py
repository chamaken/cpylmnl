# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import *
from cpylmnl import netlink


class Ifaddrmsg(netlink.UStructure):
    _fields_ = [("family",	c_uint8), # __u8 ifa_family
                ("prefixlen",	c_uint8), # __u8 ifa_prefixlen /* The prefix length            */
                ("flags",	c_uint8), # __u8 ifa_flags     /* Flags                        */
                ("scope",	c_uint8), # __u8 ifa_scope     /* Address scope                */
                ("index",	c_uint8)] # __u32 ifa_index    /* Link index                   */


class Ifacacheinfo(Structure):
    _fields_ = [("prefered",	c_uint32), # __u32 ifa_prefered
                ("valid",	c_uint32), # __u32 ifa_valid
                ("cstamp",	c_uint32), # __u32 cstamp /* created timestamp, hundredths of seconds */
                ("tstamp",	c_uint32)] # __u32 tstamp /* updated timestamp, hundredths of seconds */
