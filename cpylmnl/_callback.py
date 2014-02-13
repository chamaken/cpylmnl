# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import sys, os, errno, ctypes

from .linux import netlinkh as netlink
from . import _cproto


def cb_run2(buf, seq, portid, cb_data, data, cb_ctls=None):
    """callback runqueue for netlink messages

    You can set the cb_ctl_array to None if you want to use the default control
    callback handlers.

    Your callback may return three possible values:
	- MNL_CB_ERROR (<=-1): an error has occurred. Stop callback runqueue.
	- MNL_CB_STOP (=0): stop callback runqueue.
	- MNL_CB_OK (>=1): no problem has occurred.

    This function propagates the callback return value. On error, it raises
    OSError. If the portID is not the expected, errno is set to ESRCH. If the
    sequence number is not the expected, errno is set to EPROTO. If the dump was
    interrupted, errno is set to EINTR and you should request a new fresh dump
    again.

    @type buf: buffer (bytearray)
    @param buf: buffer that contains the netlink messages
    @type seq: number
    @param seq: sequence number that we expect to receive
    @type portid: number
    @param portid: Netlink PortID that we expect to receive
    @type cb_data: can be used mnl_cb_t or header header_cb decorator
    @param cb_data: callback handler for data messages
    @type data: any
    @param data: data that will be passed to the data callback handler
    @type cb_ctls: map
    @param cb_ctls: dict of custom callback handlers from control messages

    @rtype: numner
    @return: callback return value - MNL_CB_ERROR, MNL_CB_STOP or MNL_CB_OK
    """
    if cb_ctls is not None:
        cb_ctls_len = netlink.NLMSG_MIN_TYPE
        c_cb_ctls = (_cproto.MNL_CB_T * cb_ctls_len)()
        for i in range(cb_ctls_len):
            c_cb_ctls[i] = cb_ctls.get(i, _cproto.MNL_CB_T())
    else:
        cb_ctls_len = 0
        c_cb_ctls = None

    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
    if cb_data is None: cb_data = _cproto.MNL_CB_T()

    ret = _cproto.c_cb_run2(c_buf, len(c_buf), seq, portid, cb_data, data, c_cb_ctls, cb_ctls_len)
    if ret < 0: raise _cproto.os_error()
    return ret


def cb_run(buf, seq, portid, cb_data, data):
    """callback runqueue for netlink messages (simplified version)

    This function is like mnl_cb_run2() but it does not allow you to set
    the control callback handlers.

    Your callback may return three possible values:
	- MNL_CB_ERROR (<=-1): an error has occurred. Stop callback runqueue.
	- MNL_CB_STOP (=0): stop callback runqueue.
	- MNL_CB_OK (>=1): no problems has occurred.

    This function propagates the callback return value or raise OSError in case
    of MNL_CB_ERROR.

    @type buf: buffer (bytearray)
    @param buf: buffer that contains the netlink messages
    @type seq: number
    @param seq: sequence number that we expect to receive
    @type portid: number
    @param portid: Netlink PortID that we expect to receive
    @type cb_data: can be used mnl_cb_t or header header_cb decorator
    @param cb_data: callback handler for data messages
    @type data: any
    @param data: data that will be passed to the data callback handler

    @rtype: numner
    @return: callback return value - MNL_CB_ERROR, MNL_CB_STOP or MNL_CB_OK
    """
    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
    if cb_data is None: cb_data = _cproto.MNL_CB_T()

    ret = _cproto.c_cb_run(c_buf, len(c_buf), seq, portid, cb_data, data)
    if ret < 0: raise _cproto.os_error()
    return ret


def _cb_factory(argcls, cftype):
    def _decorator(cbfunc):
        def _inner(ptr, data):
            o = ctypes.cast(ptr, ctypes.POINTER(argcls)).contents
            ret = cbfunc(o, data)
            return ret
        return cftype(_inner)
    return _decorator

mnl_cb_t	= _cb_factory(netlink.Nlmsghdr, _cproto.MNL_CB_T)
mnl_attr_cb_t	= _cb_factory(netlink.Nlattr, _cproto.MNL_ATTR_CB_T)
