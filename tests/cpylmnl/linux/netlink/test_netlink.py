#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function, absolute_import

import sys, random, unittest, struct
from ctypes import *

from cpylmnl.linux.netlinkh import *
from .buf import *


class TestSuite(unittest.TestCase):
    def setUp(self):
        pass


    def test___new__(self):
        # empty header only
        nlh = Nlmsghdr()
        self.assertEquals(nlh.csize(), sizeof(Nlmsghdr))
        self.assertEquals(nlh.marshal_binary(), bytearray(sizeof(Nlmsghdr)))

        # short buf len
        b = bytearray(sizeof(Nlmsghdr) - 1)
        self.assertRaises(ValueError, Nlmsghdr, b)

        # invalid len attribute
        nb = NlmsghdrBuf(sizeof(Nlmsghdr))
        # does not cause Error, len(buf) becomes 18 why?
        # b[0:2] = sizeof(Nlmsghdr) + 1
        nb.len = sizeof(Nlmsghdr) + 3
        self.assertRaises(ValueError, Nlmsghdr, b)


    def test_unmarshal_binary(self):
        for i in range(256):
            b = bytearray([random.randrange(0, 255) for j in range(512)])
            nb = NlmsghdrBuf(b)
            nb.len = 512

            nlh = Nlmsghdr.unmarshal_binary(nb)
            self.assertEquals(nlh.marshal_binary(), nb)

            # not share
            mb = nlh.marshal_binary()
            nb[0] = ~nb[0] & 0xff
            self.assertNotEquals(mb, nb)


    def test_marshal_binary(self):
        # XXX: memory error
        # nlh = Nlmsghdr()
        # nlh.len = 0x100000000 - NLMSG_ALIGNTO
        # self.assertRaises(MemoryError, nlh.marshal_binary)

        for i in range(256):
            b = bytearray([random.randrange(0, 255) for j in range(512)])
            nb = NlmsghdrBuf(b)
            nb.len = 512
            nlh = Nlmsghdr(nb)

            self.assertEquals(nlh.marshal_binary(), nb)

            # share the buffer
            nb.len = 256
            self.assertEquals(nlh.marshal_binary(), nb[:256])
            newb = ~nb[10] & 0xff
            nb[10] = newb
            self.assertEquals(nlh.marshal_binary()[10], newb)

            # unshare
            nlh.len = 512
            mb = nlh.marshal_binary()
            nb[10] = ~nb[10] & 0xff
            self.assertNotEquals(mb, nb)

        


if __name__ == '__main__':
    unittest.main()
