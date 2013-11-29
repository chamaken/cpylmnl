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
        msg.attr_put_u8(mnl.MNL_TYPE_U8, 0x10)
        msg.attr_put_u16(mnl.MNL_TYPE_U16, 0x11)
        msg.attr_put_u32(mnl.MNL_TYPE_U32, 0x12)
        msg.attr_put_u64(mnl.MNL_TYPE_U64, 0x13)
        msg.attr_nest_end(nest_start)

        msg2, rest = msg.next_msg(1024)
        msg2.type = netlink.NLMSG_DONE
        msg2.len = sizeof(mnl.Header)

        msg.print(8)


    ################################
    # from attr.c
    #

    def test_attr_parse(self):
        class _cb(object):
            def __init__(self):
                self.val = 0x10

            def __call__(self, attr, data):
                preval = self.val
                self.val += 1
                if preval == attr.get_u8() and data is None: return 1
                else: return 0

        cb = mnl.attribute_cb(_cb())
        set_errno(0)

        msg = mnl.put_new_header(1024)
        msg.type = netlink.NLMSG_MIN_TYPE
        msg.put_u8(mnl.MNL_TYPE_U8, 0x10)
        msg.put_u8(mnl.MNL_TYPE_U8, 0x11)
        msg.put_u8(mnl.MNL_TYPE_U8, 0x12)
        msg.put_u8(mnl.MNL_TYPE_U8, 0x13)
        # data: <CFunctionType object at 0x30e36d0>, self: <tests.cpylmnl.test_nlmsg._cb object at 0x30fba90>
        self.assertTrue(msg.attr_parse(0, cb, None) == mnl.MNL_CB_OK)

        msg = mnl.put_new_header(1024)
        msg.type = netlink.NLMSG_MIN_TYPE
        msg.put_u8(mnl.MNL_TYPE_U8, 0x10)
        msg.put_u8(mnl.MNL_TYPE_U8, 0x11)
        msg.put_u8(mnl.MNL_TYPE_U8, 0x12)
        msg.put_u8(mnl.MNL_TYPE_U8, 0x15)
        self.assertTrue(msg.attr_parse(0, cb, None) == mnl.MNL_CB_STOP)


    def test_attr_put(self):
        msg = mnl.put_new_header(64)
        data = bytearray([1, 2, 3])
        msg.put(1, data)
        self.assertTrue(msg.len == mnl.MNL_NLMSG_HDRLEN + mnl.MNL_ATTR_HDRLEN + mnl.MNL_ALIGN(len(data)))


    def test_attr_put_u8(self):
        msg = mnl.put_new_header(64)
        msg.put_u8(mnl.MNL_TYPE_U8, 7)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_U8)
        self.assertTrue(struct.unpack("B", msg.marshal_bytes()[20:21])[0] == 7)


    def test_attr_put_u16(self):
        b = bytearray(64)
        msg = mnl.put_new_header(64)
        msg.put_u16(mnl.MNL_TYPE_U16, 7)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_U16)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[20:22])[0] == 7)


    def test_attr_put_u32(self):
        msg = mnl.put_new_header(64)
        msg.put_u32(mnl.MNL_TYPE_U32, 7)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_U32)
        self.assertTrue(struct.unpack("I", msg.marshal_bytes()[20:24])[0] == 7)


    def test_attr_put_u64(self):
        msg = mnl.put_new_header(64)
        msg.put_u64(mnl.MNL_TYPE_U64, 7)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_U64)
        self.assertTrue(struct.unpack("Q", msg.marshal_bytes()[20:28])[0] == 7)


    def test_attr_put_str(self):
        # msg = mnl.put_new_header(64)
        mb = NlmsghdrBuf(64)
        mb.len = 16
        msg = mnl.Header(mb)
        msg.put_str(mnl.MNL_TYPE_STRING, b"abcdEFG")
        self.assertTrue(struct.unpack("H",  msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_STRING)
        self.assertTrue(struct.unpack("7B", msg.marshal_bytes()[20:27]) == tuple([ord(c) for c in "abcdEFG"]))


    def test_attr_put_strz(self):
        msg = mnl.put_new_header(128)
        msg.put_strz(mnl.MNL_TYPE_STRING, b"AbCdEfGhIj")
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_STRING)
        self.assertTrue(struct.unpack("11B", msg.marshal_bytes()[20:31]) == tuple([ord(c) for c in "AbCdEfGhIj"] + [0]))


    def test_attr_nest_start(self):
        msg = mnl.put_new_header(128)
        attr = msg.nest_start(1)
        self.assertTrue(msg.len == mnl.MNL_NLMSG_HDRLEN + mnl.MNL_ATTR_HDRLEN)
        self.assertTrue(attr.type & netlink.NLA_F_NESTED == netlink.NLA_F_NESTED)
        self.assertTrue(attr.type & 1 == 1)


    def test_attr_put_check(self):
        msg = mnl.put_new_header(64)
        data = bytearray([1, 2, 3])
        self.assertTrue(msg.put_check(64, 1, data) == True)
        self.assertTrue(msg.len == mnl.MNL_NLMSG_HDRLEN + mnl.MNL_ATTR_HDRLEN + mnl.MNL_ALIGN(len(data)))

        data = bytearray([123] * 128)
        self.assertTrue(msg.put_check(128, 1, data) == False)


    def test_attr_put_u8_check(self):
        msg = mnl.put_new_header(24)
        self.assertTrue(msg.put_u8_check(24, mnl.MNL_TYPE_U8, 7) == True)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_U8)
        self.assertTrue(struct.unpack("B", msg.marshal_bytes()[20:21])[0] == 7)

        msg = mnl.put_new_header(20)
        self.assertTrue(msg.put_u8_check(20, 1, 1) == False)


    def test_attr_put_u16_check(self):
        msg = mnl.put_new_header(24)
        self.assertTrue(msg.put_u16_check(24, mnl.MNL_TYPE_U16, 7) == True)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_U16)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[20:22])[0] == 7)

        msg = mnl.put_new_header(20)
        self.assertTrue(msg.put_u16_check(20, 1, 1) == False)


    def test_attr_put_u32_check(self):
        msg = mnl.put_new_header(24)
        self.assertTrue(msg.put_u32_check(24, mnl.MNL_TYPE_U32, 7) == True)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_U32)
        self.assertTrue(struct.unpack("I", msg.marshal_bytes()[20:24])[0] == 7)

        msg = mnl.put_new_header(20)
        self.assertTrue(msg.put_u32_check(20, 1, 1) == False)


    def test_attr_put_u64_check(self):
        msg = mnl.put_new_header(64)
        self.assertTrue(msg.put_u64_check(64, mnl.MNL_TYPE_U64, 7) == True)
        self.assertTrue(struct.unpack("H", msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_U64)
        self.assertTrue(struct.unpack("Q", msg.marshal_bytes()[20:28])[0] == 7)

        msg = mnl.put_new_header(24)
        self.assertTrue(msg.put_u64_check(24, 1, 1) == False)


    def test_attr_put_str_check(self):
        msg = mnl.put_new_header(28)
        self.assertTrue(msg.put_str_check(28, mnl.MNL_TYPE_STRING, b"abcdEFG") == True)
        self.assertTrue(struct.unpack("H",  msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_STRING)
        self.assertTrue(struct.unpack("7B", msg.marshal_bytes()[20:27]) == tuple([ord(c) for c in "abcdEFG"]))

        self.assertTrue(msg.put_str_check(28, mnl.MNL_TYPE_STRING, b"abcdEFGhijklm") == False)


    def test_attr_put_strz_check(self):
        msg = mnl.put_new_header(32)
        self.assertTrue(msg.put_strz_check(32, mnl.MNL_TYPE_STRING, b"AbCdEfGhIj") == True)
        self.assertTrue(struct.unpack("H",   msg.marshal_bytes()[18:20])[0] == mnl.MNL_TYPE_STRING)
        self.assertTrue(struct.unpack("11B", msg.marshal_bytes()[20:31]) == tuple([ord(c) for c in "AbCdEfGhIj"] + [0]))

        self.assertTrue(msg.put_strz_check(32, mnl.MNL_TYPE_STRING, b"AbCdEfGhIjklmnopqrstu") == False)


    def test_attr_nest_start_check(self):
        msg = mnl.put_new_header(32)
        attr = msg.nest_start_check(32, 1)
        self.assertTrue(msg.len == mnl.MNL_NLMSG_HDRLEN + mnl.MNL_ATTR_HDRLEN)
        self.assertTrue(attr.type & 1 == 1)
        self.assertTrue(attr.type & netlink.NLA_F_NESTED == netlink.NLA_F_NESTED)


    def test_attr_nest(self):
        msg = mnl.put_new_header(1024)
        attr_start = msg.nest_start(4)
        msg.put_u8(mnl.MNL_TYPE_U8, 1)
        msg.put_u16(mnl.MNL_TYPE_U16, 2)
        msg.put_u32(mnl.MNL_TYPE_U32, 3)
        msg.put_u64(mnl.MNL_TYPE_U64, 4)
        msg.nest_end(attr_start)

        b = bytearray(struct.pack("I", 56)  # hdr len
                      + b'\x00\x00\x00\x00'  # hdr type, flags
                      + b'\x00\x00\x00\x00'  # hdr seq
                      + b'\x00\x00\x00\x00'  # hdr port id

                      + struct.pack("H", 40)
                      + struct.pack("H", 4 | netlink.NLA_F_NESTED)

                      + struct.pack("H", 5)
                      + struct.pack("H", mnl.MNL_TYPE_U8)
                      + struct.pack("B", 1)
                      + b'\x00\x00\x00'

                      + struct.pack("H", 6)
                      + struct.pack("H", mnl.MNL_TYPE_U16)
                      + struct.pack("H", 2)
                      + b'\x00\x00'

                      + struct.pack("H", 8)
                      + struct.pack("H", mnl.MNL_TYPE_U32)
                      + struct.pack("I", 3)

                      + struct.pack("H", 12)
                      + struct.pack("H", mnl.MNL_TYPE_U64)
                      + struct.pack("Q", 4))

        self.assertTrue(msg.marshal_binary()[:msg.len] == b)


    def test_attr_nest_cancel(self):
        msg = mnl.put_new_header(1024)
        attr_start = msg.nest_start(4)
        msg.put_u8(mnl.MNL_TYPE_U8, 1)
        msg.put_u16(mnl.MNL_TYPE_U16, 2)
        msg.put_u32(mnl.MNL_TYPE_U32, 3)
        msg.put_u64(mnl.MNL_TYPE_U64, 4)
        msg.nest_end(attr_start)

        msg.nest_cancel(attr_start)
        self.assertTrue(msg.len == mnl.MNL_NLMSG_HDRLEN)


if __name__ == '__main__':
    unittest.main()
