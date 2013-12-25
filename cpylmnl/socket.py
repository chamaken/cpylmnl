# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

from ctypes import *

from . import netlink
from .cproto import *

"""
libmnl homepage is:
     http://www.netfilter.org/projects/libmnl/
"""

### obtain file descriptor from netlink socket
# int mnl_socket_get_fd(const struct mnl_socket *nl)
socket_get_fd		= c_socket_get_fd

### obtain Netlink PortID from netlink socket
# unsigned int mnl_socket_get_portid(const struct mnl_socket *nl)
socket_get_portid	= c_socket_get_portid

### open a netlink socket
# struct mnl_socket *mnl_socket_open(int bus)
def socket_open(bus):
    set_errno(0)
    ret = c_socket_open(bus)
    if ret is None: raise os_error()
    return ret

### bind netlink socket
# int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid)
def socket_bind(nl, groups, pid):
    set_errno(0)
    ret = c_socket_bind(nl, groups, pid)
    if ret < 0: raise os_error()
    return ret

### setup mmap ring
# int mnl_socket_set_ring(struct mnl_socket *nl, struct nl_mmap_req *tx_req, struct nl_mmap_req *rx_req)
def socket_set_ring(nl, tx_req, rx_req):
    set_errno(0)
    ret = c_socket_set_ring(nl, tx_req, rx_req)
    if ret < 0: raise os_error()
    return ret

### get current frame
# struct nl_mmap_hdr *mnl_socket_get_frame(const struct mnl_socket *nl, enum mnl_ring_types type)
def socket_get_frame(nl, rtype):
    return c_socket_get_frame(nl, rtype).contents

### set forward frame pointer
# int mnl_socket_advance_ring(const struct mnl_socket *nl, enum mnl_ring_types type)
def socket_advance_ring(nl, rtype):
    set_errno(0)
    ret = c_socket_advance_ring(nl, rtype)
    if ret < 0: raise os_error()
    return ret

### send a netlink message of a certain size
# mnl_socket_sendto(const struct mnl_socket *nl, const void *buf, size_t len)
def socket_sendto(nl, buf):
    set_errno(0)
    if buf is None:
        ret = c_socket_sendto(nl, None, 0)
    else:
        # require mutable buffer
        c_buf = (c_ubyte * len(buf)).from_buffer(buf)
        ret = c_socket_sendto(nl, c_buf, len(buf))
    if ret < 0: raise os_error()
    return ret

def socket_send_nlmsg(nl, nlh):
    c_buf = (c_ubyte * nlh.len).from_address(addressof(nlh))
    set_errno(0)
    ret = c_socket_sendto(nl, c_buf, len(c_buf))
    if ret < 0: raise os_error()
    return ret

### receive a netlink message
# ssize_t
# mnl_socket_recvfrom(const struct mnl_socket *nl, void *buf, size_t bufsiz)
def socket_recv(nl, size):
    # returns mutable buffer
    buf = bytearray(size)
    set_errno(0)
    ret = socket_recv_into(nl, buf)
    if ret < 0: raise os_error()
    # We did not read as many bytes as we anticipated, resize the
    # string if possible and be successful. */
    return buf[:ret]

def socket_recv_into(nl, buf):
    c_buf = (c_char * len(buf)).from_buffer(buf)
    set_errno(0)
    ret = c_socket_recvfrom(nl, c_buf, len(c_buf))
    if ret < 0: raise os_error()
    return ret
    
### close a given netlink socket
# int mnl_socket_close(struct mnl_socket *nl)
def socket_close(nl):
    set_errno(0)
    ret = c_socket_close(nl)
    if ret < 0: raise os_error()
    return ret

### set Netlink socket option
# int mnl_socket_setsockopt(const struct mnl_socket *nl, int type,
#                           void *buf, socklen_t len)
def socket_setsockopt(nl, optype, buf):
    c_buf = (c_ubyte * len(buf)).from_buffer_copy(buf)
    set_errno(0)
    ret = c_socket_setsockopt(nl, optype, c_buf, len(buf))
    if ret < 0: raise os_error()
    return ret

### get a Netlink socket option
# int mnl_socket_getsockopt(const struct mnl_socket *nl, int type,
#                           void *buf, socklen_t *len)
def soket_getsockopt(nl, optype, size):
    buf = bytearray(size)
    c_buf = (c_char * len(buf)).from_buffer(buf)
    set_errno(0)
    ret = c_socket_getsockopt(nl, optype, c_buf, len(buf))
    if ret < 0: raise os_error()
    return c_buf.raw

### wait for receiving
# int mnl_socket_poll_rx(const struct mnl_socket *nl, int timeout)
def socket_poll_rx(nl, timeout):
    set_errno(0)
    ret = c_socket_poll_rx(nl, timeout)
    if ret < 0: raise os_error()
    return ret
