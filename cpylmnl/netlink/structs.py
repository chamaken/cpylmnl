# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import sys, os
from ctypes import *

'''http://stackoverflow.com/questions/15377338/convert-ctype-byte-array-to-bytes
Convert ctype byte array to bytes

If you did want a copy, you could use bytearray:

    >>> buff = (c_ubyte * 4)(*[97,98,99,100])
    >>> bs = bytearray(buff)
    >>> bs
    bytearray(b'abcd')
    >>> str(bs)
    'abcd'

If you want to share the same buffer, you can create a c_char array:

    >>> buff2 = (c_char * len(buff)).from_buffer(buff)
    >>> buff2.value # string copy
    'abcd'
    >>> buff2[:] = 'efgh'
    >>> buff[:]  # modified original
    [101, 102, 103, 104]

Is there a reason you aren't using a c_char array to begin with? I understand if
you need to work with it as both a numeric array and as a string.

Addendum:

The 2nd method is more 'cast' like since it doesn't copy the buffer. With the
first approach it gets copied twice, once to make the bytearray and again to
make the str (bytes is an alias for str in 2.x). But a bytearray has string
methods and may be all you need; it's basically a mutable version of 3.x bytes.

c_char is the C char type. Multiplied to an array, it's a mutable buffer of
bytes like your current c_ubyte array. However, it may be more convenient than
c_ubyte since it has the value and raw descriptors that return Python byte
strings. It also indexes and iterates as single character byte strings instead
of integers.

What you're not supposed to do is create a c_char_p -- a pointer to character
data -- from a Python string if the function will modify the it. Python strings
objects are immutable; you can get weird bugs if you modify their buffer. I
recently answered a question on that topic.
'''

class UStructure(Structure):
    def __new__(cls, buf=None, offset=0):
        # share the buf
        # but hold it even if the buf has changed? - set to new value, None
        if buf == None:
            buf = bytearray(sizeof(cls))
        elif len(buf) < sizeof(cls):
            raise ValueError("too short buf size")

        v = cls.from_buffer(buf, offset)
        if hasattr(v, "len") and v.len > len(buf):
            raise ValueError("too long len attribute")

        # v._ubuf = (c_char * (len(buf) - offset)).from_buffer(buf, offset)
        return v


    def __init__(self, *args, **kwargs):
        pass


    @classmethod
    def sizeof(cls):
        return sizeof(cls)


    @classmethod
    def pointer(cls, ptr):
        return cast(ptr, POINTER(cls)).contents


    @classmethod
    def unmarshal_binary(cls, data):
        # not share, use copy
        return cls.__new__(cls, bytearray(data))


    def marshal_binary(self):
        if hasattr(self, "len") and self.len > sizeof(self): # XXX: fixed name
            size = self.len
        else:
            size = sizeof(self)

        # not share, return copy
        return bytearray(cast(addressof(self), POINTER((c_ubyte * size))).contents)


    def marshal_bytes(self):
        """
        if hasattr(self, "len"): # XXX: fixed name
            size = self.len
        else:
            sizeof(self)
        return cast(addressof(self), POINTER((c_char * size))).contents.raw
        """
        return bytes(self.marshal_binary())


# naming conversion
# * struct / class
#   starts with upper
#   convert upper just after in the middle of _ and remove _ self

# * field / attribute
#   follow ``cgo -godefs'' as possible. but the first is lower

class Nlmsghdr(UStructure):
    """struct nlmsghdr
    """
    _fields_ = [("len",		c_uint32), # __u32 nlmsg_len	/* Length of message including header */
                ("type",	c_uint16), # __u16 nlmsg_type	/* Message content */
                ("flags",	c_uint16), # __u16 nlmsg_flags	/* Additional flags */
                ("seq",		c_uint32), # __u32 nlmsg_seq	/* Sequence number */
                ("pid",		c_uint32)] # __u32 nlmsg_pid	/* Sending process port ID */


class Nlmsgerr(UStructure):
    """struct nlmsgerr
    """
    _fields_ = [("error",	c_int),    # int error
                ("msg",		Nlmsghdr)] # struct nlmsghdr msg


class NlPktinfo(Structure): # not UStructure?
    """struct nl_pktinfo
    """
    _fields_ = [("group",	c_uint32)] # __u32 group


class NlMmapReq(Structure):
    """struct nl_mmap_req
    """
    _fields_ = [("block_size", 	c_uint), # unsigned int	nm_block_size
                ("block_nr",	c_uint), # unsigned int	nm_block_nr
                ("frame_size",	c_uint), # unsigned int	nm_frame_size
                ("frame_nr",	c_uint)] # unsigned int	nm_frame_nr

class NlMmapHdr(Structure):
    """struct nl_mmap_hdr
    """
    _fields_ = [("status",	c_uint),  # unsigned int	nm_status
                ("len",		c_uint),  # unsigned int	nm_len
                ("group",	c_uint32), # __u32		nm_group;
                # credentials
                ("pid",		c_uint32), # __u32		nm_pid;
                ("uid",		c_uint32), # __u32		nm_uid;
                ("gid", 	c_uint32)] # __u32		nm_gid;

class Nlattr(UStructure):
    """struct nlattr
    """
    _fields_ = [("len",		c_uint16), # __u16 nla_len
                ("type",	c_uint16)] # __u16 nla_type
