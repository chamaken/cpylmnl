from __future__ import print_function, absolute_import

import sys
import struct, errno

def buf_property(fmt, start):
    fmt_len = struct.calcsize(fmt)
    # PACK_FMT, UNPACK_FMT, IDX_START, IDX_END, BUFNAME
    l = [fmt, start, start + fmt_len]

    def _getter(obj):
        return struct.unpack(l[0], obj[l[1]:l[2]])[0]

    def _setter(obj, val):
        obj[l[1]:l[2]] = struct.pack(l[0], val)

    return property(_getter, _setter)

class NlmsghdrBuf(bytearray):
    len   = buf_property("I",  0) # __u32 nlmsg_len
    type  = buf_property("H",  4) # __u16 nlmsg_type
    flags = buf_property("H",  6) # __u16 nlmsg_flags
    seq   = buf_property("I",  8) # __u32 nlmsg_seq
    pid   = buf_property("I", 12) # __u32 nlmsg_pid


class NlattrBuf(bytearray):
    len   = buf_property("H",  0) # __u16 nla_len
    type  = buf_property("H",  2) # __u16 nla_type
