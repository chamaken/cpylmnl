# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

from ctypes import *

from . import netlink
from .cproto import *

### a little bit differ from C macro - requires len
def MMAP_MSGHDR(hdr, size):
    return cast(addressof(hdr) + netlink.NL_MMAP_HDRLEN, POINTER(c_ubyte * size)).contents

### setup a ring descriptor
def ring_map(nl, tx_req, rx_req):
    set_errno(0)
    ret = c_ring_map(nl, tx_req, rx_req)
    if ret is None: raise os_error()
    return ret

### free a given ring descriptor
ring_unmap		= c_ring_unmap

### get current frame
def ring_get_frame(nlm, rtype):
    return c_ring_get_frame(nlm, rtype).contents

### set forward frame pointer
ring_advance		= c_ring_advance

### wait for receiving
def ring_poll(nlm, timeout):
    set_errno(0)
    ret = c_ring_poll(nlm, timeout)
    if ret < 0: raise os_error()
