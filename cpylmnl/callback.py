# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import sys, os, errno, ctypes

from .linux import netlinkh as netlink
from . import cproto


def cb_run2(buf, seq, portid, cb_data, data, cb_ctls=None):
    if cb_ctls is not None:
        cb_ctls_len = netlink.NLMSG_MIN_TYPE
        c_cb_ctls = (cproto.MNL_CB_T * cb_ctls_len)()
        for i in range(cb_ctls_len):
            c_cb_ctls[i] = cb_ctls.get(i, cproto.MNL_CB_T())
    else:
        cb_ctls_len = 0
        c_cb_ctls = None

    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
    if cb_data is None: cb_data = cproto.MNL_CB_T()

    ret = cproto.c_cb_run2(c_buf, len(c_buf), seq, portid, cb_data, data, c_cb_ctls, cb_ctls_len)
    if ret < 0: raise cproto.os_error()
    return ret


def cb_run(buf, seq, portid, cb_data, data):
    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
    if cb_data is None: cb_data = cproto.MNL_CB_T()

    ret = cproto.c_cb_run(c_buf, len(c_buf), seq, portid, cb_data, data)
    if ret < 0: raise cproto.os_error()
    return ret


def _cb_factory(argcls, cftype):
    def _decorator(cbfunc):
        def _inner(ptr, data):
            o = ctypes.cast(ptr, ctypes.POINTER(argcls)).contents
            ret = cbfunc(o, data)
            return ret
        return cftype(_inner)
    return _decorator

mnl_cb_t	= _cb_factory(netlink.Nlmsghdr, cproto.MNL_CB_T)
mnl_attr_cb_t	= _cb_factory(netlink.Nlattr, cproto.MNL_ATTR_CB_T)

from .py_class import Attribute, Header
attribute_cb	= _cb_factory(Attribute, cproto.MNL_ATTR_CB_T)
header_cb	= _cb_factory(Header, cproto.MNL_CB_T)


__all__ = ["cb_run", "cb_run2", "mnl_cb_t", "mnl_attr_cb_t", "attribute_cb", "header_cb"]
