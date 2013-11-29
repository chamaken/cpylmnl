#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function

import sys, random, unittest, struct, errno
import ctypes

from cpylmnl import netlink
import cpylmnl as mnl

from .netlink.buf import *

# XXX: assumpt little endian
class TestSuite(unittest.TestCase):
    def setUp(self):
        pass


    def test_Attribute(self):
        ab = NlattrBuf(16)
        nla = mnl.Attribute(ab)
        self.assertTrue(nla.len == 0)
        self.assertTrue(nla.type == 0)
        nla.len = 4
        self.assertTrue(nla.marshal_binary()[0] == ab[0])

        ab.len = 10
        ab.type = 2
        nla = mnl.Attribute(ab)
        self.assertTrue(nla.len == 10)
        self.assertTrue(nla.type == 2)


    def test_get_type(self):
        ab = NlattrBuf(16)
        ab.type = 2
        nla = mnl.Attribute(ab)
        self.assertTrue(nla.get_type() == 2)
        nla.type = 2 | netlink.NLA_F_NESTED
        self.assertTrue(nla.get_type() == 2)


    def test_get_len(self):
        ab = NlattrBuf(16)
        ab.len = 10
        nla = mnl.Attribute(ab)
        self.assertTrue(nla.get_len() == 10)


    def test_get_payload_len(self):
        ab = NlattrBuf(bytearray([random.randrange(0, 255) for j in range(4000)]))
        ab.len = mnl.MNL_ALIGN(3001)
        nla = mnl.Attribute(ab)
        self.assertTrue(nla.get_payload_len() == mnl.MNL_ALIGN(3001) - mnl.MNL_ATTR_HDRLEN)
        self.assertTrue(nla.get_payload_len() != mnl.MNL_ALIGN(4000) - mnl.MNL_ATTR_HDRLEN)


    def test_get_payload_v(self):
        ab = NlattrBuf(bytearray([random.randrange(0, 255) for j in range(4000)]))
        ab.len = mnl.MNL_ALIGN(2004)
        nla = mnl.Attribute(ab)
        self.assertTrue(bytearray(nla.get_payload_v()) == ab[4:2004])


    def test_ok(self):
        ab = NlattrBuf(bytearray([random.randrange(0, 255) for j in range(4000)]))
        ab.len = 3
        nla = mnl.Attribute(ab)

        self.assertTrue(nla.ok(3) == False)
        self.assertTrue(nla.ok(4) == False)
        self.assertTrue(nla.ok(5) == False)

        nla.len = 4
        self.assertTrue(nla.ok(3) == False)
        self.assertTrue(nla.ok(4) == True)
        self.assertTrue(nla.ok(5) == True)

        nla.len = 8
        self.assertTrue(nla.ok(6) == False)
        self.assertTrue(nla.ok(7) == False)
        self.assertTrue(nla.ok(8) == True)


    def test_next_attr(self):
        ab = NlattrBuf(bytearray([random.randrange(0, 255) for j in range(512)]))
        ab.len = 256
        ab[256:258] = struct.pack("H", 128) # XXX
        nla = mnl.Attribute(ab)
        nnla = nla.next_attribute()

        self.assertTrue(nnla.len == 128)
        self.assertTrue(nnla.marshal_binary() == ab[256:256 + 128])


    def test_type_valid(self):
        ab = NlattrBuf(bytearray([random.randrange(0, 255) for j in range(4000)]))
        ab.len = mnl.MNL_ALIGN(256)
        nla = mnl.Attribute(ab)
        for i in range(mnl.MNL_TYPE_MAX):
            nla.type = i
            self.assertTrue(nla.type_valid(i + 1) == 1)
        nla.type = mnl.MNL_TYPE_MAX + 1
        self.assertRaises(OSError, nla.type_valid, mnl.MNL_TYPE_MAX)
        self.assertTrue(ctypes.get_errno() == errno.EOPNOTSUPP)


    def test_validate(self):
        ab = NlattrBuf(bytearray([random.randrange(0, 255) for j in range(256)]))
        ab.len = mnl.MNL_ALIGN(256)
        nla = mnl.Attribute(ab)

        self.assertRaises(OSError, nla.validate, mnl.MNL_TYPE_MAX)
        self.assertRaises(OSError, nla.validate2, mnl.MNL_TYPE_MAX, 1)

        valid_len = {
            # {data_type: (nla.len, exp_len)
            mnl.MNL_TYPE_UNSPEC		: (0, 0),
            mnl.MNL_TYPE_U8		: (1, 1),
            mnl.MNL_TYPE_U16		: (2, 2),
            mnl.MNL_TYPE_U32		: (4, 4),
            mnl.MNL_TYPE_U64		: (8, 8),
            mnl.MNL_TYPE_STRING		: (64, 64),
            mnl.MNL_TYPE_FLAG		: (0, 0),
            mnl.MNL_TYPE_MSECS		: (2, 2),
            mnl.MNL_TYPE_NESTED		: (32, 32),
            mnl.MNL_TYPE_NESTED_COMPAT	: (32, 32),
            mnl.MNL_TYPE_NUL_STRING	: (64, 64),
            mnl.MNL_TYPE_BINARY		: (64, 64),
            # mnl.TYPE_MAX		: (, ),
        }
        invalid_len = {
            mnl.MNL_TYPE_UNSPEC		: (8, 16),
            mnl.MNL_TYPE_U8		: (2, 3),
            mnl.MNL_TYPE_U16		: (3, 4),
            mnl.MNL_TYPE_U32		: (5, 6),
            mnl.MNL_TYPE_U64		: (9, 10),
            mnl.MNL_TYPE_STRING		: (0, 0),
            mnl.MNL_TYPE_FLAG		: (1, 1),
            mnl.MNL_TYPE_MSECS		: (2, 3),
            mnl.MNL_TYPE_NESTED		: (32, 12),
            mnl.MNL_TYPE_NESTED_COMPAT	: (32, 12),
            mnl.MNL_TYPE_NUL_STRING	: (0, 0),
            mnl.MNL_TYPE_BINARY		: (2, 1),
            # mnl.TYPE.MAX		: (, ),
        }

        for t in valid_len:
            nla.len = mnl.MNL_ATTR_HDRLEN + valid_len[t][0]
            if t == mnl.MNL_TYPE_NUL_STRING:
                # for non-null-terminated
                nla.get_payload_v()[nla.get_payload_len() - 1] = 1
                self.assertRaises(OSError, nla.validate2, t, invalid_len[t][1])
                self.assertTrue(ctypes.get_errno() == errno.EINVAL)

                nla.get_payload_v()[nla.get_payload_len() - 1] = 0
            if t in (mnl.MNL_TYPE_U8,
                     mnl.MNL_TYPE_U16,
                     mnl.MNL_TYPE_U32,
                     mnl.MNL_TYPE_U64):
                self.assertTrue(nla.validate(t) == 0)

            # XXX
            # print(nla.validate2(t, valid_len[t][1]), file=sys.stderr)
            # self.assertTrue(nla.validate2(t, valid_len[t][1]) == (0, 0))

            nla.len = mnl.MNL_ATTR_HDRLEN + invalid_len[t][0]
            if t in (mnl.MNL_TYPE_U8,
                     mnl.MNL_TYPE_U16,
                     mnl.MNL_TYPE_U32,
                     mnl.MNL_TYPE_U64):
                self.assertRaises(OSError, nla.validate, t)
                self.assertTrue(ctypes.get_errno() == errno.ERANGE)
            self.assertRaises(OSError, nla.validate2, t, invalid_len[t][1])

        # for nested payload
        nla = mnl.Attribute(bytearray(ctypes.sizeof(mnl.Attribute)))
        nla.len = 4
        nla.type = mnl.MNL_TYPE_NESTED
        self.assertTrue(nla.validate2(mnl.MNL_TYPE_NESTED, 0) == 0)
        nla.len = 6
        self.assertRaises(OSError, nla.validate2, mnl.MNL_TYPE_NESTED, 0)
        self.assertTrue(ctypes.get_errno() == errno.ERANGE)


    def test_get_u8(self):
        nla = mnl.Attribute(bytearray([5, 0, mnl.MNL_TYPE_U8, 0, 0x11, 0, 0, 0]))
        self.assertTrue(nla.get_u8() == 0x11)


    def test_get_u16(self):
        nla = mnl.Attribute(bytearray([6, 0, mnl.MNL_TYPE_U16, 0, 0x11, 0x22, 0, 0]))
        self.assertTrue(nla.get_u16() == struct.unpack("H", b"\x11\x22")[0])


    def test_get_u32(self):
        nla = mnl.Attribute(bytearray([8, 0, mnl.MNL_TYPE_U32, 0, 0x11, 0x22, 0x33, 0x44]))
        self.assertTrue(nla.get_u32() == struct.unpack("I", b"\x11\x22\x33\x44")[0])


    def test_get_u64(self):
        nla = mnl.Attribute(bytearray([12, 0, mnl.MNL_TYPE_U64, 0,
                                   0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]))
        self.assertTrue(nla.get_u64() == struct.unpack("Q", b"\x11\x22\x33\x44\x55\x66\x77\x88")[0])


    def test_get_str(self):
        nla = mnl.Attribute(bytearray([10, 0, mnl.MNL_TYPE_STRING, 0]
                                  + [ord(c) for c in 'abcDEF'] + [0, 0]))
        self.assertTrue(nla.get_str() == b'abcDEF', "get_str(): %s, should be: %s" % (nla.get_str(), b"abcDEF"))


    def test_parse_nested(self):
        b = bytearray([28, 0, 1, 0,
                       5, 0, 2, 0, 10, 0, 0, 0,
                       5, 0, 3, 0, 20, 0, 0, 0,
                       5, 0, 4, 0, 30, 0, 0, 0,])
        nla = mnl.Attribute(b)

        atype = [2]
        @mnl.mnl_attr_cb_t
        def cb(attr, data):
            if not data: return mnl.MNL_CB_STOP
            if atype[0] != attr.type: return mnl.MNL_CB_ERROR
            atype[0] += 1
            return mnl.MNL_CB_OK

        self.assertTrue(nla.parse_nested(cb, True) == mnl.MNL_CB_OK)
        self.assertTrue(nla.parse_nested(cb, False) == mnl.MNL_CB_STOP)


    def test_attr_parse_payload(self):
        b = bytearray([5, 0, 2, 0, 10, 0, 0, 0,
                       5, 0, 3, 0, 20, 0, 0, 0,
                       5, 0, 4, 0, 30, 0, 0, 0,])

        atype = [2]
        @mnl.mnl_attr_cb_t
        def cb(attr, data):
            if not data: return mnl.MNL_CB_STOP
            if atype[0] != attr.type: return mnl.MNL_CB_ERROR
            atype[0] += 1
            return mnl.MNL_CB_OK

        self.assertTrue(mnl.attr_parse_payload(b, cb, True) == mnl.MNL_CB_OK)
        self.assertTrue(mnl.attr_parse_payload(b, cb, False) == mnl.MNL_CB_STOP)


if __name__ == '__main__':
    unittest.main()
