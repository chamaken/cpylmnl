# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import sys, os, errno
from ctypes import *

from . import netlink
from .cproto import *
from .mnlh import MNL_ALIGN

"""
libmnl (http://www.netfilter.org/projects/libmnl/) nlmsg.c
    implementation by python ctypes
"""

### calculate the size of Netlink message (without alignment)
# size_t mnl_nlmsg_size(size_t len)
nlmsg_size		= c_nlmsg_size

### get the length of the Netlink payload
# size_t mnl_nlmsg_get_payload_len(const struct nlmsghdr *nlh)
nlmsg_get_payload_len	= c_nlmsg_get_payload_len

### reserve and prepare room for Netlink header
# struct nlmsghdr *mnl_nlmsg_put_header(void *buf)
def nlmsg_put_header(buf, cls=None):
    # share the buffer
    # returned nlmsghdr will be invalid if param buf is GCed - set to new value, None
    c_buf = (c_ubyte * len(buf)).from_buffer(buf)
    ret = c_nlmsg_put_header(c_buf)
    if cls is None:
        return ret.contents
    if not issubclass(cls, ret.contents.__class__):
        raise TypeError("not a subclass of %r: %r" % (ret.contents.__class__, cls))
    return cls(buf)


### reserve and prepare room for an extra header
# void *
# mnl_nlmsg_put_extra_header(struct nlmsghdr *nlh, size_t size)
nlmsg_put_extra_header	= c_nlmsg_put_extra_header
def nlmsg_put_extra_header_v(nlh, size):
    return cast(c_nlmsg_put_extra_header(nlh, size),
                POINTER(c_ubyte * MNL_ALIGN(size))).contents
def nlmsg_put_extra_header_as(nlh, cls, size=None):
    if size is None:
        size = sizeof(cls)
    return cast(c_nlmsg_put_extra_header(nlh, size), POINTER(cls)).contents

### get a pointer to the payload of the netlink message
# void *mnl_nlmsg_get_payload(const struct nlmsghdr *nlh)
nlmsg_get_payload	= c_nlmsg_get_payload
def nlmsg_get_payload_v(nlh):
    return cast(c_nlmsg_get_payload(nlh),
                POINTER(c_ubyte * c_nlmsg_get_payload_len(nlh))).contents
def nlmsg_get_payload_as(nlh, cls):
    return cast(c_nlmsg_get_payload(nlh), POINTER(cls)).contents

### get a pointer to the payload of the message
# void *
# mnl_nlmsg_get_payload_offset(const struct nlmsghdr *nlh, size_t offset)
nlmsg_get_payload_offset= c_nlmsg_get_payload_offset
def nlmsg_get_payload_offset_v(nlh, offset):
    return cast(c_nlmsg_get_payload_offset(nlh, offset),
                POINTER(c_ubyte * (c_nlmsg_get_payload_len(nlh) - MNL_ALIGN(offset)))).contents
def nlmsg_get_payload_offset_as(nlh, offset, cls):
    return cast(c_nlmsg_get_payload_offset(nlh), POINTER(cls)).contents

### check a there is room for netlink message
# bool mnl_nlmsg_ok(const struct nlmsghdr *nlh, int len)
nlmsg_ok		= c_nlmsg_ok

### get the next netlink message in a multipart message
# struct nlmsghdr *
# mnl_nlmsg_next(const struct nlmsghdr *nlh, int *len)
def nlmsg_next(nlh, size):
    csize = c_int(size)
    return c_nlmsg_next(nlh, byref(csize)).contents, csize.value

### get the ending of the netlink message
# void *mnl_nlmsg_get_payload_tail(const struct nlmsghdr *nlh)
nlmsg_get_payload_tail	= c_nlmsg_get_payload_tail

### perform sequence tracking
# bool
# mnl_nlmsg_seq_ok(const struct nlmsghdr *nlh, unsigned int seq)
nlmsg_seq_ok		= c_nlmsg_seq_ok

### perform portID origin check
# bool
# mnl_nlmsg_portid_ok(const struct nlmsghdr *nlh, unsigned int portid)
nlmsg_portid_ok		= c_nlmsg_portid_ok

### print netlink message to file
# void
# mnl_nlmsg_fprintf(FILE *fd, const void *data, size_t datalen,
#                   size_t extra_header_size)
def nlmsg_fprint(buf, extra_header_size, out=None):
    if out is None: out = sys.__stdout__
    c_buf = (c_ubyte * len(buf)).from_buffer(buf)
    f = c_fdopen(out.fileno(), out.mode)
    c_nlmsg_fprintf(f, c_buf, len(buf), extra_header_size)


#
# Netlink message batch helpers
#
### initialize a batch
# struct mnl_nlmsg_batch *mnl_nlmsg_batch_start(void *buf, size_t limit)
def nlmsg_batch_start(buf, limit):
    c_buf = (c_ubyte * len(buf)).from_buffer(buf)
    return c_nlmsg_batch_start(c_buf, limit)

### release a batch
# void mnl_nlmsg_batch_stop(struct mnl_nlmsg_batch *b)
nlmsg_batch_stop	= c_nlmsg_batch_stop

### get room for the next message in the batch
# bool mnl_nlmsg_batch_next(struct mnl_nlmsg_batch *b)
nlmsg_batch_next	= c_nlmsg_batch_next

### reset the batch
# void mnl_nlmsg_batch_reset(struct mnl_nlmsg_batch *b)
nlmsg_batch_reset	= c_nlmsg_batch_reset

### get current size of the batch
# size_t mnl_nlmsg_batch_size(struct mnl_nlmsg_batch *b)
nlmsg_batch_size	= c_nlmsg_batch_size

### get head of this batch
# void *mnl_nlmsg_batch_head(struct mnl_nlmsg_batch *b)
nlmsg_batch_head	= c_nlmsg_batch_head
def nlmsg_batch_head_v(b):
    return cast(c_nlmsg_batch_head(b), POINTER(c_ubyte * nlmsg_batch_size(b))).contents

### returns current position in the batch
# void *mnl_nlmsg_batch_current(struct mnl_nlmsg_batch *b)
# XXX: inoperable in python, can not determine the size of current from the APIs
nlmsg_batch_current	= c_nlmsg_batch_current

### check if there is any message in the batch
# bool mnl_nlmsg_batch_is_empty(struct mnl_nlmsg_batch *b)
nlmsg_batch_is_empty	= c_nlmsg_batch_is_empty
