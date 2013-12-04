# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import ctypes # for Header put_header(), print()
from . import netlink
from .attr import *
from .nlmsg import *
from .socket import *

class Attribute(netlink.Nlattr):
    def get_type(self):			return attr_get_type(self)
    def get_len(self):			return attr_get_len(self)
    def get_payload_len(self):		return attr_get_payload_len(self)
    def get_payload(self):		return attr_get_payload(self)
    def get_payload_v(self):		return attr_get_payload_v(self)
    def get_payload_as(self, c):	return attr_get_payload_as(self, c)
    def ok(self, size):			return attr_ok(self, size)
    def type_valid(self, maxtype):	return attr_type_valid(self, maxtype)
    def validate(self, t):		return attr_validate(self, t)
    def validate2(self, t, l):		return attr_validate2(self, t, l)
    def parse_nested(self, cb, d):	return attr_parse_nested(self, cb, d)
    def get_u8(self):			return attr_get_u8(self)
    def get_u16(self):			return attr_get_u16(self)
    def get_u32(self):			return attr_get_u32(self)
    def get_u64(self):			return attr_get_u64(self)
    def get_str(self):			return attr_get_str(self)
    def next_attribute(self):
        return cast(addressof(attr_next(self)), POINTER(self.__class__)).contents


class Header(netlink.Nlmsghdr):
    def attr_parse(self, o, cb, d):	return attr_parse(self, o, cb, d)
    def put(self, t, d):		attr_put(self, t, d)
    def put_u8(self, t, d):		attr_put_u8(self, t, d)
    def put_u16(self, t, d):		attr_put_u16(self, t, d)
    def put_u32(self, t, d):		attr_put_u32(self, t, d)
    def put_u64(self, t, d):		attr_put_u64(self, t, d)
    def put_str(self, t, d):		attr_put_str(self, t, d)
    def put_strz(self, t, d):		attr_put_strz(self, t, d)
    def nest_start(self, t):
        return cast(addressof(attr_nest_start(self, t)), POINTER(Attribute)).contents
    def put_check(self, l, t, d):	return attr_put_check(self, l, t, d)
    def put_u8_check(self, l, t, d):	return attr_put_u8_check(self, l, t, d)
    def put_u16_check(self, l, t, d):	return attr_put_u16_check(self, l, t, d)
    def put_u32_check(self, l, t, d):	return attr_put_u32_check(self, l, t, d)
    def put_u64_check(self, l, t, d):	return attr_put_u64_check(self, l, t, d)
    def put_str_check(self, l, t, d):	return attr_put_str_check(self, l, t, d)
    def put_strz_check(self, l, t, d): return attr_put_strz_check(self, l, t, d)
    def nest_start_check(self, l, t):
	return cast(addressof(attr_nest_start_check(self, l, t)), POINTER(Attribute)).contents
    def nest_end(self, a):		return attr_nest_end(self, a)
    def nest_cancel(self, a):		return attr_nest_cancel(self, a)

    @staticmethod
    def size(l):			return nlmsg_size(l)
    def get_payload_len(self):		return nlmsg_get_payload_len(self)
    def put_extra_header(self, l):	return nlmsg_put_extra_header(self, l)
    def put_extra_header_v(self, l):	return nlmsg_put_extra_header_v(self, l)
    def put_extra_header_as(self, l, c): return nlmsg_put_extra_header_as(self, l, c)
    def get_payload(self):		return nlmsg_get_payload(self)
    def get_payload_v(self):		return nlmsg_get_payload_v(self)
    def get_payload_as(self, c):	return nlmsg_get_payload_as(self, c)
    def get_payload_offset(self, o):	return nlmsg_get_payload_offset(self, o)
    def get_payload_offset_v(self, o):	return nlmsg_get_payload_offset_v(self, o)
    def get_payload_offset_as(self, o, c): return nlmsg_get_payload_offset_as(self, o, c)
    def ok(self, size):			return nlmsg_ok(self, size)
    def get_payload_tail(self):		return nlmsg_get_payload_tail(self)
    def seq_ok(self, seq):		return nlmsg_seq_ok(self, seq)
    def portid_ok(self, pid):		return nlmsg_portid_ok(self, pid)

    def next_header(self, size):
        nlh, size = nlmsg_next(self, size)
        return cast(addressof(nlh), POINTER(self.__class__)).contents, size

    def put_header(self):
        c_nlmsg_put_header(ctypes.addressof(self))

    def fprint(self, elen, o=None):
        nlmsg_fprint(ctypes.cast(ctypes.addressof(self), POINTER(ctypes.c_ubyte * self.len)).contents, elen, o)

# helper
def put_new_header(size):
    nlh = Header(bytearray(size))
    nlh.put_header()
    return nlh


# to implement nlmsg_batch_current
class NlmsgBatch(object):
    def __init__(self, bufsize, limit): # start
        if bufsize < limit: raise ValueError("bufsize is smaller than limit")
        self._buf = bytearray(bufsize)
        self._batch = nlmsg_batch_start(self._buf, limit)

    def stop(self):	nlmsg_batch_stop(self._batch)
    def next(self):	return nlmsg_batch_next(self._batch)
    def reset(self):	nlmsg_batch_reset(self._batch)
    def size(self):	return nlmsg_batch_size(self._batch)
    def head(self):	return nlmsg_batch_head_v(self._batch)
    def is_empty(self):	return nlmsg_batch_is_empty(self._batch)
    def current(self):
        current = nlmsg_batch_current(self._batch)
        size =  nlmsg_batch_head(self._batch) + len(self._buf) - current
        return cast(current, POINTER(c_ubyte * size)).contents

    def __enter__(self): return self
    def __exit__(self, t, v, tb):
        self.stop()
        return False


class Socket(object):
    def __init__(self, bus):		self._nls = socket_open(bus)
    def get_fd(self):			return socket_get_fd(self._nls)
    def get_portid(self):		return socket_get_portid(self._nls)
    def bind(self, groups, pid):	return socket_bind(self._nls, groups, pid)
    def sendto(self, buf):		return socket_sendto(self._nls, buf)
    def send_nlmsg(self, nlh):		return socket_send_nlmsg(self._nls, nlh)
    def recvfrom(self, size):		return socket_recvfrom(self._nls, size)
    def close(self):			return socket_close(self._nls)
    def setsockopt(self, t, b):		return socket_setsockopt(self._nls, t, b)
    def getsockopt(self, t, size):	return socket_getsockopt(self._nls, t, size)
    def __enter__(self):		return self
    def __exit__(self, t, v, tb):
	socket_close(self._nls)
        return False
