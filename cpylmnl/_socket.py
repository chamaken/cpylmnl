# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import ctypes

from .linux import netlinkh as netlink
from . import cproto

"""
libmnl homepage is:
     http://www.netfilter.org/projects/libmnl/
"""

### obtain file descriptor from netlink socket
# int mnl_socket_get_fd(const struct mnl_socket *nl)
socket_get_fd		= cproto.c_socket_get_fd

### obtain Netlink PortID from netlink socket
# unsigned int mnl_socket_get_portid(const struct mnl_socket *nl)
socket_get_portid	= cproto.c_socket_get_portid

### open a netlink socket
# struct mnl_socket *mnl_socket_open(int bus)
def socket_open(bus):
    ret = cproto.c_socket_open(bus)
    if ret is None: raise cproto.os_error()
    return ret

### bind netlink socket
# int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid)
def socket_bind(nl, groups, pid):
    ret = cproto.c_socket_bind(nl, groups, pid)
    if ret < 0: raise cproto.os_error()

if cproto.HAS_MNL_RING:
    ### set ring opt to prepare for mnl_socket_map_ring()
    # extern int mnl_socket_set_ringopt(struct mnl_socket *nl, struct nl_mmap_req *req, enum mnl_ring_types type);
    def socket_set_ringopt(nl, rtype, block_size, block_nr, frame_size, frame_nr):
        ret = cproto.c_socket_set_ringopt(nl, rtype, block_size, block_nr, frame_size, frame_nr)
        if ret < 0: raise cproto.os_error()

    ### setup a ring for mnl_socket
    # extern int mnl_socket_map_ring(struct mnl_socket *nl);
    def socket_map_ring(nl):
        ret = cproto.c_socket_map_ring(nl)
        if ret < 0: raise cproto.os_error()

    ## unmap a ring for mnl_socket
    def socket_unmap_ring(nl):
        ret = cproto.c_socket_unmap_ring(nl)
        if ret < 0: raise cproto.os_error()

    ### get ring from mnl_socket
    # struct mnl_ring *mnl_socket_get_ring(const struct mnl_socket *nl, enum mnl_ring_types type)
    def socket_get_ring(nl, rtype):
        ret = cproto.c_socket_get_ring(nl, rtype)
        if ret is None: raise cproto.os_error()
        return ret

    ## get current frame
    # struct nl_mmap_hdr *mnl_ring_get_frame(const struct mnl_ring *ring)
    def ring_get_frame(ring):
        return cproto.c_ring_get_frame(ring).contents

    ### set forward frame pointer
    # int mnl_socket_advance_ring(const struct mnl_socket *nl, enum mnl_ring_types type)
    ring_advance = cproto.c_ring_advance
#### END HAS_MNL_RING

### send a netlink message of a certain size
# mnl_socket_sendto(const struct mnl_socket *nl, const void *buf, size_t len)
def socket_sendto(nl, buf):
    if buf is None:
        ret = cproto.c_socket_sendto(nl, None, 0)
    else:
        # require mutable buffer
        c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
        ret = cproto.c_socket_sendto(nl, c_buf, len(buf))
    if ret < 0: raise cproto.os_error()
    return ret

def socket_send_nlmsg(nl, nlh):
    c_buf = (ctypes.c_ubyte * nlh.len).from_address(ctypes.addressof(nlh))
    ret = cproto.c_socket_sendto(nl, c_buf, len(c_buf))
    if ret < 0: raise cproto.os_error()
    return ret

### receive a netlink message
# ssize_t
# mnl_socket_recvfrom(const struct mnl_socket *nl, void *buf, size_t bufsiz)
def socket_recv(nl, size):
    # returns mutable buffer
    buf = bytearray(size)
    ret = socket_recv_into(nl, buf)
    if ret < 0: raise cproto.os_error()
    # We did not read as many bytes as we anticipated, resize the
    # string if possible and be successful.
    return buf[:ret]

def socket_recv_into(nl, buf):
    c_buf = (ctypes.c_char * len(buf)).from_buffer(buf)
    ret = cproto.c_socket_recvfrom(nl, c_buf, len(c_buf))
    if ret < 0: raise cproto.os_error()
    return ret
    
### close a given netlink socket
# int mnl_socket_close(struct mnl_socket *nl)
def socket_close(nl):
    ret = cproto.c_socket_close(nl)
    if ret < 0: raise cproto.os_error()
    return ret

### set Netlink socket option
# int mnl_socket_setsockopt(const struct mnl_socket *nl, int type,
#                           void *buf, socklen_t len)
def socket_setsockopt(nl, optype, buf):
    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer_copy(buf)
    ret = cproto.c_socket_setsockopt(nl, optype, c_buf, len(buf))
    if ret < 0: raise cproto.os_error()
    return ret

### get a Netlink socket option
# int mnl_socket_getsockopt(const struct mnl_socket *nl, int type,
#                           void *buf, socklen_t *len)
def socket_getsockopt(nl, optype, size):
    buf = bytearray(size)
    c_size = ctypes.c_int(size)
    c_buf = (ctypes.c_char * size).from_buffer(buf)
    ret = cproto.c_socket_getsockopt(nl, optype, c_buf, ctypes.byref(c_size))
    if ret < 0: raise cproto.os_error()
    return c_buf.raw

def socket_getsockopt_ctype(nl, optype, cls):
    optval = cls.__new__(cls)
    try:
        size = ctypes.sizeof(optval)
    except TypeError:
        raise OSError(errno.EINVAL, "value must be ctypes type")
    c_size = ctypes.c_int(size)
    ret = cproto.c_socket_getsockopt(nl, optype, ctypes.byref(optval), ctypes.byref(c_size))
    if ret < 0: raise cproto.os_error()
    # return optval
    return optval.value
