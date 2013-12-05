#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function

import sys, random, unittest, struct
from ctypes import sizeof, set_errno

from cpylmnl import netlink
import cpylmnl as mnl
from cpylmnl import h

from .netlink.buf import *


class TestSuite(unittest.TestCase):
    def setUp(self):
        pass

    def test_Header(self):
        msg = mnl.Header()
        self.assertTrue(msg.len == 0)
        self.assertTrue(msg.type == 0)
        self.assertTrue(msg.flags == 0)
        self.assertTrue(msg.seq == 0)
        self.assertTrue(msg.pid == 0)


    def test_size(self):
        self.assertTrue(mnl.Header.size(3) == 19)


    def test_get_payload_len(self):
        msg = mnl.Header(bytearray(2048))
        msg.len = 2000
        self.assertTrue(msg.get_payload_len() == mnl.MNL_ALIGN(2000 - sizeof(netlink.Nlmsghdr)))


    def test_put_header(self):
        b = bytearray(1024)
        msg = mnl.nlmsg_put_header(b)
        self.assertTrue(msg.len == sizeof(netlink.Nlmsghdr))


    def test_put_extra_header(self):
        nb = NlmsghdrBuf(bytearray([random.randrange(0, 255) for j in range(1024)]))
        nb.len = 256
        msg = mnl.Header(nb)
        exhdr = msg.put_extra_header_v(123)
        for i in range(mnl.MNL_ALIGN(123)):
            nb[256 + i] = 0
        self.assertEquals(msg.len, 256 + mnl.MNL_ALIGN(123))
        self.assertEquals(len(exhdr), mnl.MNL_ALIGN(123))
        self.assertTrue(exhdr == nb[256:mnl.MNL_ALIGN(256 + 123)])


    def test_get_payload_v(self):
        for i in range(31):
            nb = NlmsghdrBuf(bytearray([random.randrange(0, 255) for j in range(1024)]))
            nb.len = 1024
            msg = mnl.Header(nb)
            self.assertTrue(msg.get_payload_v() == nb[mnl.MNL_NLMSG_HDRLEN:])


    def test_get_payload_offset_v(self):
        for i in range(31):
            nb = NlmsghdrBuf(bytearray([random.randrange(0, 255) for j in range(1024)]))
            nb.len = 1024
            msg = mnl.Header(nb)
            print(len(msg.get_payload_offset_v(901)))
            print(len(nb[netlink.NLMSG_HDRLEN + mnl.MNL_ALIGN(901):]))
            self.assertTrue(msg.get_payload_offset_v(901) == nb[netlink.NLMSG_HDRLEN + mnl.MNL_ALIGN(901):])


    def test_ok(self):
        msg = mnl.put_new_header(1024)
        self.assertFalse(msg.ok(15))
        self.assertTrue(msg.ok(16))
        self.assertTrue(msg.ok(17))

        msg.len = 8
        self.assertFalse(msg.ok(7))
        self.assertFalse(msg.ok(8))
        self.assertFalse(msg.ok(9))

        msg.len = 32
        self.assertFalse(msg.ok(31))
        self.assertTrue(msg.ok(32))
        self.assertTrue(msg.ok(33))



    def test_next_msg(self):
        size = 1024
        b = bytearray(size)
        i = 0
        b[i:i + 4] = struct.pack("I", mnl.MNL_ALIGN(123))

        i += mnl.MNL_ALIGN(123)
        b[i:i + 4] = struct.pack("I", mnl.MNL_ALIGN(234))

        i += mnl.MNL_ALIGN(234)
        b[i:i + 4] = struct.pack("I", mnl.MNL_ALIGN(345))

        i += mnl.MNL_ALIGN(345)
        b[i:i + 4] = struct.pack("I", mnl.MNL_NLMSG_HDRLEN)

        msg = mnl.Header(b)
        nmsg, size = msg.next_header(size)
        self.assertTrue(nmsg.len == mnl.MNL_ALIGN(234), "msg.len: %d" % msg.len)
        self.assertTrue(size == 1024 - mnl.MNL_ALIGN(123), "size: %d" % size)

        nnmsg, size = nmsg.next_header(size)
        self.assertTrue(nnmsg.len == mnl.MNL_ALIGN(345), "msg.len: %d" % msg.len)
        self.assertTrue(size == 1024 - mnl.MNL_ALIGN(123) - mnl.MNL_ALIGN(234))

        nnnmsg, size = nnmsg.next_header(size)
        self.assertTrue(nnnmsg.len == mnl.MNL_ALIGN(mnl.MNL_NLMSG_HDRLEN), "msg.len: %d" % msg.len)
        self.assertTrue(size == 1024 - mnl.MNL_ALIGN(123) - mnl.MNL_ALIGN(234) - mnl.MNL_ALIGN(345))

        # is buffer shared?
        self.assertTrue(struct.unpack("I", bytes(b[mnl.MNL_ALIGN(123):mnl.MNL_ALIGN(123) + 4]))[0] == mnl.MNL_ALIGN(234))


    # XXX: not in target
    def _test_get_payload_tail(self):
        b = bytearray([random.randrange(0, 255) for j in range(1024)])
        b[0:4] = struct.pack("I", 323)
        msg = mnl.Header(b)
        self.assertTrue(msg.get_payload_tail() == b[mnl.MNL_ALIGN(323):])


    def test_seq_ok(self):
        b = bytearray([random.randrange(0, 255) for j in range(1024)])
        b[0:4] = struct.pack("I", 1024)
        b[8:12] = struct.pack("I", 323)
        msg = mnl.Header(b)
        self.assertTrue(msg.seq_ok(323), "msg.seq: %d" % msg.seq)
        self.assertFalse(msg.seq_ok(888), "msg.seq: %d" % msg.seq)
        self.assertTrue(msg.seq_ok(0))
        msg.seq = 0
        self.assertTrue(msg.seq_ok(888))


    def test_portid_ok(self):
        b = bytearray(1024)
        b[0:4] = struct.pack("I", 1024)
        b[12:16] = struct.pack("I", 323)
        msg = mnl.Header(b)
        self.assertTrue(msg.portid_ok(323), "msg.pid: %d" % msg.pid)
        self.assertTrue(not msg.portid_ok(888), "msg.pid: %d" % msg.pid)
        self.assertTrue(msg.portid_ok(0))
        msg.pid = 0
        self.assertTrue(msg.portid_ok(888))


    # XXX: no assertion
    def _test_print(self):
        msg = mnl.put_new_header(1024)
        msg.type = netlink.NLMSG_MIN_TYPE
        msg.put_extra_header(8)
        msg.get_payload()[:8] = [1, 2, 3, 4, 5, 6, 7, 8]
        nest_start = msg.attr_nest_start(1)
        msg.put_u8(mnl.MNL_TYPE_U8, 0x10)
        msg.put_u16(mnl.MNL_TYPE_U16, 0x11)
        msg.put_u32(mnl.MNL_TYPE_U32, 0x12)
        msg.put_u64(mnl.MNL_TYPE_U64, 0x13)
        msg.attr_nest_end(nest_start)

        msg2, rest = msg.next_msg(1024)
        msg2.type = netlink.NLMSG_DONE
        msg2.len = sizeof(mnl.Header)

        msg.print(8)


    def test_batch_head(self):
        b = mnl.NlmsgBatch(301, 129)
        self.assertTrue(b.size() == 0)
        print("current len: %d" % len(b.current()), file=sys.stderr)
        self.assertTrue(len(b.current()) == 301)
        print("head len: %d" % len(b.head()), file=sys.stderr)
        self.assertTrue(len(b.head()) == 0)

        for i in range(1, 9):
            nlh = mnl.Header(b.current())
            nlh.put_header()
            self.assertTrue(b.next() == True)
            self.assertTrue(b.size() == mnl.MNL_NLMSG_HDRLEN * i,)
            self.assertTrue(len(b.current()) == (301 - mnl.MNL_NLMSG_HDRLEN * i))
            self.assertTrue(len(b.head()) == mnl.MNL_NLMSG_HDRLEN * i)

        nlh = mnl.Header(b.current())
        nlh.put_header()
        self.assertTrue(b.next() == False)
        self.assertTrue(b.size() == mnl.MNL_NLMSG_HDRLEN * i)
        self.assertTrue(len(b.current()) == (301 - mnl.MNL_NLMSG_HDRLEN * i))
        self.assertTrue(len(b.head()) == mnl.MNL_NLMSG_HDRLEN * i)

        b.reset()
        self.assertTrue(b.size() == mnl.MNL_NLMSG_HDRLEN)
        self.assertTrue(len(b.current()) == (301 - mnl.MNL_NLMSG_HDRLEN))
        self.assertTrue(len(b.head()) == mnl.MNL_NLMSG_HDRLEN)


if __name__ == '__main__':
    unittest.main()
