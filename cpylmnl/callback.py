# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import sys, os, errno

from . import netlink
from .cproto import *
from ctypes import *

def cb_run2(buf, seq, portid, cb_data, data, cb_ctls=None):
    if cb_ctls is not None:
        cb_ctls_len = netlink.NLMSG_MIN_TYPE
        c_cb_ctls = (MNL_CB_T * cb_ctls_len)()
        for i in range(cb_ctls_len):
            c_cb_ctls[i] = cb_ctls.get(i, MNL_CB_T())
    else:
        cb_ctls_len = 0
        c_cb_ctls = None

    c_buf = (c_ubyte * len(buf)).from_buffer(buf)
    if cb_data is None: cb_data = MNL_CB_T()

    set_errno(0)
    ret = c_cb_run2(c_buf, len(c_buf), seq, portid, cb_data, data, c_cb_ctls, cb_ctls_len)
    if ret < 0: c_raise_if_errno()
    return ret


def cb_run(buf, seq, portid, cb_data, data):
    c_buf = (c_ubyte * len(buf)).from_buffer(buf)
    if cb_data is None: cb_data = MNL_CB_T()
    set_errno(0)
    ret = c_cb_run(c_buf, len(c_buf), seq, portid, cb_data, data)
    if ret < 0: c_raise_if_errno()
    return ret


def _cb_factory(argcls, cftype):
    def _decorator(cbfunc):
        def _inner(p1, p2):
            attr = cast(p1, POINTER(argcls)).contents
            # data = p2 is None and None or cast(p2, py_object).value
            if p2 is None: data = None
            else: data = cast(p2, py_object).value
            ret = cbfunc(attr, data)
            return ret
        return cftype(_inner)
    return _decorator

mnl_cb_t	= _cb_factory(netlink.Nlmsghdr, MNL_CB_T)
mnl_attr_cb_t	= _cb_factory(netlink.Nlattr, MNL_ATTR_CB_T)

from .py_class import Attribute, Header
attribute_cb	= _cb_factory(Attribute, MNL_ATTR_CB_T)
header_cb	= _cb_factory(Header, MNL_CB_T)
