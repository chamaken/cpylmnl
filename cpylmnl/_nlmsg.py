# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import sys, os, errno, ctypes

from .linux import netlinkh as netlink
from . import _cproto
from . import _libmnlh

"""
libmnl (http://www.netfilter.org/projects/libmnl/) nlmsg.c
    implementation by python ctypes
"""

### calculate the size of Netlink message (without alignment)
# size_t mnl_nlmsg_size(size_t len)
nlmsg_size		= _cproto.c_nlmsg_size

### get the length of the Netlink payload
# size_t mnl_nlmsg_get_payload_len(const struct nlmsghdr *nlh)
nlmsg_get_payload_len	= _cproto.c_nlmsg_get_payload_len

### reserve and prepare room for Netlink header
# struct nlmsghdr *mnl_nlmsg_put_header(void *buf)
def nlmsg_put_header(buf, cls=None):
    """reserve and prepare room for Netlink header

    This function sets to zero the room that is required to put the Netlink
    header in the memory buffer passed as parameter. This function also
    initializes the nlmsg_len field to the size of the Netlink header. This
    function returns Netlink header object.

    @type buf: buffer
    @param buf: memory already allocated to store the Netlink header
    @type cls: class of Nlmsghdr subclass
    @param cls: type of return class

    @rtype: Nlmsghdr or its subclass
    @return: Netlink header object
    """
    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
    ret = _cproto.c_nlmsg_put_header(c_buf)
    if cls is None:
        return ret.contents
    if not issubclass(cls, ret.contents.__class__):
        raise TypeError("not a subclass of %r: %r" % (ret.contents.__class__, cls))
    return cls(buf)


### reserve and prepare room for an extra header
# void *
# mnl_nlmsg_put_extra_header(struct nlmsghdr *nlh, size_t size)
nlmsg_put_extra_header	= _cproto.c_nlmsg_put_extra_header
def nlmsg_put_extra_header_v(nlh, size):
    return ctypes.cast(_cproto.c_nlmsg_put_extra_header(nlh, size),
                ctypes.POINTER(ctypes.c_ubyte * _libmnlh.MNL_ALIGN(size))).contents
def nlmsg_put_extra_header_as(nlh, cls, size=None):
    if size is None:
        size = ctypes.sizeof(cls)
    return ctypes.cast(_cproto.c_nlmsg_put_extra_header(nlh, size), ctypes.POINTER(cls)).contents

### get a pointer to the payload of the netlink message
# void *mnl_nlmsg_get_payload(const struct nlmsghdr *nlh)
nlmsg_get_payload	= _cproto.c_nlmsg_get_payload
def nlmsg_get_payload_v(nlh):
    return ctypes.cast(_cproto.c_nlmsg_get_payload(nlh),
                ctypes.POINTER(ctypes.c_ubyte * _cproto.c_nlmsg_get_payload_len(nlh))).contents
def nlmsg_get_payload_as(nlh, cls):
    return ctypes.cast(_cproto.c_nlmsg_get_payload(nlh), ctypes.POINTER(cls)).contents

### get a pointer to the payload of the message
# void *
# mnl_nlmsg_get_payload_offset(const struct nlmsghdr *nlh, size_t offset)
nlmsg_get_payload_offset= _cproto.c_nlmsg_get_payload_offset
def nlmsg_get_payload_offset_v(nlh, offset):
    return ctypes.cast(_cproto.c_nlmsg_get_payload_offset(nlh, offset),
                ctypes.POINTER(ctypes.c_ubyte * (_cproto.c_nlmsg_get_payload_len(nlh) - _libmnlh.MNL_ALIGN(offset)))).contents
def nlmsg_get_payload_offset_as(nlh, offset, cls):
    return ctypes.cast(_cproto.c_nlmsg_get_payload_offset(nlh, offset), ctypes.POINTER(cls)).contents

### check a there is room for netlink message
# bool mnl_nlmsg_ok(const struct nlmsghdr *nlh, int len)
nlmsg_ok		= _cproto.c_nlmsg_ok

### get the next netlink message in a multipart message
# struct nlmsghdr *
# mnl_nlmsg_next(const struct nlmsghdr *nlh, int *len)
def nlmsg_next(nlh, size):
    csize = ctypes.c_int(size)
    return _cproto.c_nlmsg_next(nlh, ctypes.byref(csize)).contents, csize.value

### get the ending of the netlink message
# void *mnl_nlmsg_get_payload_tail(const struct nlmsghdr *nlh)
nlmsg_get_payload_tail	= _cproto.c_nlmsg_get_payload_tail

### perform sequence tracking
# bool
# mnl_nlmsg_seq_ok(const struct nlmsghdr *nlh, unsigned int seq)
nlmsg_seq_ok		= _cproto.c_nlmsg_seq_ok

### perform portID origin check
# bool
# mnl_nlmsg_portid_ok(const struct nlmsghdr *nlh, unsigned int portid)
nlmsg_portid_ok		= _cproto.c_nlmsg_portid_ok

### print netlink message to file
# void
# mnl_nlmsg_fprintf(FILE *fd, const void *data, size_t datalen,
#                   size_t extra_header_size)
def nlmsg_fprint(buf, extra_header_size, out=None):
    if out is None: out = sys.__stdout__
    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
    f = c_fdopen(out.fileno(), out.mode)
    _cproto.c_nlmsg_fprintf(f, c_buf, len(buf), extra_header_size)


#
# Netlink message batch helpers
#
### initialize a batch
# struct mnl_nlmsg_batch *mnl_nlmsg_batch_start(void *buf, size_t limit)
def nlmsg_batch_start(buf, limit):
    c_buf = (ctypes.c_ubyte * len(buf)).from_buffer(buf)
    return _cproto.c_nlmsg_batch_start(c_buf, limit)

### release a batch
# void mnl_nlmsg_batch_stop(struct mnl_nlmsg_batch *b)
nlmsg_batch_stop	= _cproto.c_nlmsg_batch_stop

### get room for the next message in the batch
# bool mnl_nlmsg_batch_next(struct mnl_nlmsg_batch *b)
nlmsg_batch_next	= _cproto.c_nlmsg_batch_next

### reset the batch
# void mnl_nlmsg_batch_reset(struct mnl_nlmsg_batch *b)
nlmsg_batch_reset	= _cproto.c_nlmsg_batch_reset

### get current size of the batch
# size_t mnl_nlmsg_batch_size(struct mnl_nlmsg_batch *b)
nlmsg_batch_size	= _cproto.c_nlmsg_batch_size

### get head of this batch
# void *mnl_nlmsg_batch_head(struct mnl_nlmsg_batch *b)
nlmsg_batch_head	= _cproto.c_nlmsg_batch_head
def nlmsg_batch_head_v(b):
    return ctypes.cast(_cproto.c_nlmsg_batch_head(b), ctypes.POINTER(ctypes.c_ubyte * nlmsg_batch_size(b))).contents

### returns current position in the batch
# void *mnl_nlmsg_batch_current(struct mnl_nlmsg_batch *b)
# XXX: inoperable in python, can not determine the size of current from the APIs
nlmsg_batch_current	= _cproto.c_nlmsg_batch_current

### check if there is any message in the batch
# bool mnl_nlmsg_batch_is_empty(struct mnl_nlmsg_batch *b)
nlmsg_batch_is_empty	= _cproto.c_nlmsg_batch_is_empty
