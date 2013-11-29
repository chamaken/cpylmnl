# -*- coding: utf-8 -*-

from __future__ import absolute_import

from cpylmnl import netlink

class Nfgenmsg(netlink.UStructure):
    """struct nfgenmsg

    General form of address family dependent message.
    """
    _fields_ = [("family",	c_uint8),  # __u8   nfgen_family /* AF_xxx */
                ("version",	c_uint8),  # __u8   version      /* nfnetlink version */
                ("res_id",	c_uint16)] # __be16 res_id       /* resource id */
