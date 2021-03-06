# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import ctypes

from .linux import netlinkh as netlink
from . import _cproto

# int mnl_socket_get_fd(const struct mnl_socket *nl)
socket_get_fd		= _cproto.c_socket_get_fd

# unsigned int mnl_socket_get_portid(const struct mnl_socket *nl)
socket_get_portid	= _cproto.c_socket_get_portid

# struct mnl_socket *mnl_socket_open(int bus)
def socket_open(bus):
    ret = _cproto.c_socket_open(bus)
    if ret is None: raise _cproto.os_error()
    return ret

# struct mnl_socket *mnl_socket_open2(int bus, int flags)
def socket_open2(bus, flags):
    ret = _cproto.c_socket_open2(bus, flags)
    if ret is None: raise _cproto.os_error()
    return ret

# struct mnl_socket *mnl_socket_fdopen(int fd)
def socket_fdopen(fd):
    ret = _cproto.c_socket_fdopen(fd)
    if ret is None: raise _cproto.os_error()
    return ret

# int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid)
def socket_bind(nl, groups, pid):
    ret = _cproto.c_socket_bind(nl, groups, pid)
    if ret < 0: raise _cproto.os_error()

# mnl_socket_sendto(const struct mnl_socket *nl, const void *buf, size_t len)
def socket_sendto(nl, buf):
    if buf is None:
        ret = _cproto.c_socket_sendto(nl, None, 0)
    else:
        # require mutable buffer
        c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
        ret = _cproto.c_socket_sendto(nl, c_buf, len(buf))
    if ret < 0: raise _cproto.os_error()
    return ret

def socket_send_nlmsg(nl, nlh):
    c_buf = (ctypes.c_ubyte * nlh.nlmsg_len).from_address(ctypes.addressof(nlh))
    ret = _cproto.c_socket_sendto(nl, c_buf, len(c_buf))
    if ret < 0: raise _cproto.os_error()
    return ret

# ssize_t
# mnl_socket_recvfrom(const struct mnl_socket *nl, void *buf, size_t bufsiz)
def socket_recv(nl, size):
    # returns mutable buffer
    buf = bytearray(size)
    ret = socket_recv_into(nl, buf)
    if ret < 0: raise _cproto.os_error()
    # We did not read as many bytes as we anticipated, resize the
    # string if possible and be successful.
    return buf[:ret]

def socket_recv_into(nl, buf):
    c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
    ret = _cproto.c_socket_recvfrom(nl, c_buf, len(c_buf))
    if ret < 0: raise _cproto.os_error()
    return ret

# int mnl_socket_close(struct mnl_socket *nl)
def socket_close(nl):
    ret = _cproto.c_socket_close(nl)
    if ret < 0: raise _cproto.os_error()
    return ret

# int mnl_socket_setsockopt(const struct mnl_socket *nl, int type,
#                           void *buf, socklen_t len)
def socket_setsockopt(nl, optype, buf):
    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer_copy(buf)
    ret = _cproto.c_socket_setsockopt(nl, optype, c_buf, len(buf))
    if ret < 0: raise _cproto.os_error()

# int mnl_socket_getsockopt(const struct mnl_socket *nl, int type,
#                           void *buf, socklen_t *len)
def socket_getsockopt(nl, optype, size):
    buf = bytearray(size)
    c_size = ctypes.c_int(size)
    c_buf = (ctypes.c_char * size).from_buffer(buf)
    ret = _cproto.c_socket_getsockopt(nl, optype, c_buf, ctypes.byref(c_size))
    if ret < 0: raise _cproto.os_error()
    return c_buf.raw

def socket_getsockopt_ctype(nl, optype, cls):
    optval = cls.__new__(cls)
    try:
        size = ctypes.sizeof(optval)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    c_size = ctypes.c_int(size)
    ret = _cproto.c_socket_getsockopt(nl, optype, ctypes.byref(optval), ctypes.byref(c_size))
    if ret < 0: raise _cproto.os_error()
    # return optval
    return optval.value
