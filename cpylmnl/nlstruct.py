# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import sys, os, ctypes


class NLStructure(ctypes.Structure):
    """This class regard memory buffer as struct"""

    def __new__(cls, buf=None, offset=0):
        """create new instance

        @type buf: buffer - bytearray or memory view
        @param buf: buffer
        @type offset: number
        @param offset: offset of struct starting
        """
        if buf == None:
            buf = bytearray(ctypes.sizeof(cls))
        elif len(buf) < ctypes.sizeof(cls):
            raise ValueError("too short buf size")

        # see http://stackoverflow.com/questions/15377338/convert-ctype-byte-array-to-bytes
        v = cls.from_buffer(buf, offset)
        if hasattr(v, "len") and v.len > len(buf):
            raise ValueError("too long len attribute")

        return v


    def __init__(self, *args, **kwargs):
        pass


    @classmethod
    def csize(cls):
        """ctypes.sizeof() wrapper
        """
        return ctypes.sizeof(cls)


    @classmethod
    def from_pointer(cls, ptr):
        """casting to this class and returns its contents
        """
        return ctypes.cast(ptr, ctypes.POINTER(cls)).contents


    @classmethod
    def unmarshal_binary(cls, data):
        """create a new instance from data buffer
        """
        # not share, use copy
        return cls.__new__(cls, bytearray(data))


    def marshal_binary(self):
        """create a buffer(bytearray) from this instance
        """
        if hasattr(self, "len") and self.len > ctypes.sizeof(self): # XXX: fixed name
            size = self.len
        else:
            size = ctypes.sizeof(self)

        # not share, return copy
        return bytearray(ctypes.cast(ctypes.addressof(self), ctypes.POINTER((ctypes.c_ubyte * size))).contents)


    def marshal_bytes(self):
        """creates a bytes from this instance
        """
        return bytes(self.marshal_binary())
