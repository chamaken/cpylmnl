#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function

import sys, random, unittest, struct
import ctypes

import cpylmnl.linux.netlinkh as netlink
import cpylmnl as mnl
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl # for _as() casting

from .linux.netlink.buf import *


class TestSuite(unittest.TestCase):
    def setUp(self):
        self.buflen = 512

        self.msg_attr_hlen = mnl.MNL_NLMSG_HDRLEN + mnl.MNL_ATTR_HDRLEN

        # nlmsghdr
        self.hbuf = NlmsghdrBuf(self.buflen)
        self.nlh = mnl.Nlmsg(self.hbuf)
        self.rand_hbuf = NlmsghdrBuf(bytearray([random.randrange(0, 255) for j in range(self.buflen)]))
        self.rand_hbuf.len = self.buflen
        self.rand_nlh = mnl.Nlmsg(self.rand_hbuf)

        # nlattr
        self.abuf = NlattrBuf(self.buflen)
        self.nla = mnl.Attr(self.abuf)
        self.rand_abuf = NlattrBuf(bytearray([random.randrange(0, 255) for j in range(self.buflen)]))
        self.rand_abuf.len = self.buflen
        self.rand_nla = mnl.Attr(self.rand_abuf)


    def test_Nlmsg(self):
        self.assertTrue(self.nlh.nlmsg_len == 0)
        self.assertTrue(self.nlh.nlmsg_type == 0)
        self.assertTrue(self.nlh.nlmsg_flags == 0)
        self.assertTrue(self.nlh.nlmsg_seq == 0)
        self.assertTrue(self.nlh.nlmsg_pid == 0)

        self.nlh.nlmsg_len = 0x12345678
        self.nlh.nlmsg_type = 0x9abc
        self.nlh.nlmsg_flags = 0xdef0
        self.nlh.nlmsg_seq = 0x23456789
        self.nlh.nlmsg_pid = 0xabcdef01

        self.assertTrue(self.hbuf.len == 0x12345678)
        self.assertTrue(self.hbuf.type == 0x9abc)
        self.assertTrue(self.hbuf.flags == 0xdef0)
        self.assertTrue(self.hbuf.seq == 0x23456789)
        self.assertTrue(self.hbuf.pid == 0xabcdef01)


    def test_size(self):
        self.assertTrue(mnl.Nlmsg.size(3) == 19)


    def test_get_payload_len(self):
        self.hbuf.len = mnl.MNL_ALIGN(123)
        self.assertTrue(self.nlh.get_payload_len() == mnl.MNL_ALIGN(123) - mnl.MNL_NLMSG_HDRLEN)


    def test_nlmsg_put_header(self):
        nlh = mnl.nlmsg_put_header(self.hbuf)
        self.assertTrue(nlh.nlmsg_len == mnl.MNL_NLMSG_HDRLEN)
        h = mnl.nlmsg_put_header(self.hbuf, mnl.Nlmsg)
        self.assertTrue(h.nlmsg_len == mnl.MNL_NLMSG_HDRLEN)
        self.assertRaises(TypeError, mnl.nlmsg_put_header, self.hbuf, list)


    def test_put_new_header(self):
        nlh = mnl.Nlmsg.put_new_header(128)
        self.assertTrue(nlh.nlmsg_len == mnl.MNL_NLMSG_HDRLEN)


    def test_put_extra_header_v(self):
        # rand len was set 512 at setUp()
        self.rand_hbuf.len = 256
        exhdr = self.rand_nlh.put_extra_header_v(123)
        self.assertTrue(len(exhdr) == mnl.MNL_ALIGN(123))
        self.assertTrue(self.rand_nlh.nlmsg_len == 256 + mnl.MNL_ALIGN(123))
        [self.assertTrue(i == 0) for i in exhdr]
        [self.assertTrue(self.rand_hbuf[i] == 0) for i in range(256, 256 + mnl.MNL_ALIGN(123))]


    def test_put_extra_header_as(self):
        self.rand_hbuf.len = mnl.MNL_ALIGN(256)
        exhdr = self.rand_nlh.put_extra_header_as(nfnl.Nfgenmsg)
        self.assertTrue(self.rand_nlh.nlmsg_len == mnl.MNL_ALIGN(256) + mnl.MNL_ALIGN(nfnl.Nfgenmsg.csize()))
        self.assertTrue(isinstance(exhdr, nfnl.Nfgenmsg))
        self.assertTrue(exhdr.nfgen_family == 0)
        self.assertTrue(exhdr.version == 0)
        self.assertTrue(exhdr.res_id == 0)


    def test_get_payload(self):
        self.rand_nlh.nlmsg_len = mnl.MNL_ALIGN(384)
        p = self.rand_nlh.get_payload()
        b = ctypes.cast(p, ctypes.POINTER((ctypes.c_ubyte * (384 - mnl.MNL_NLMSG_HDRLEN)))).contents
        self.assertTrue(b == self.rand_hbuf[mnl.MNL_NLMSG_HDRLEN:mnl.MNL_ALIGN(384)])


    def test_get_payload_v(self):
        self.rand_nlh.nlmsg_len = mnl.MNL_ALIGN(384)
        b = self.rand_nlh.get_payload_v()
        self.assertTrue(len(b) == 384 - mnl.MNL_NLMSG_HDRLEN)
        self.assertTrue(b == self.rand_hbuf[mnl.MNL_NLMSG_HDRLEN:mnl.MNL_ALIGN(384)])


    def test_get_payload_offset(self):
        p = self.rand_nlh.get_payload_offset(191)
        buflen = self.buflen - mnl.MNL_NLMSG_HDRLEN - mnl.MNL_ALIGN(191)
        b = ctypes.cast(p, ctypes.POINTER((ctypes.c_ubyte * buflen))).contents
        self.assertTrue(b == self.rand_hbuf[mnl.MNL_NLMSG_HDRLEN + mnl.MNL_ALIGN(191):])


    def test_get_payload_offset_v(self):
        b = self.rand_nlh.get_payload_offset_v(191)
        self.assertTrue(len(b) == self.buflen - mnl.MNL_NLMSG_HDRLEN - mnl.MNL_ALIGN(191))
        self.assertTrue(b == self.rand_hbuf[mnl.MNL_NLMSG_HDRLEN + mnl.MNL_ALIGN(191):])


    def test_get_payload_offset_as(self):
        exhdr = self.nlh.get_payload_offset_as(191, nfnl.Nfgenmsg)
        self.assertTrue(isinstance(exhdr, nfnl.Nfgenmsg))
        self.assertTrue(exhdr.nfgen_family == 0)
        self.assertTrue(exhdr.version == 0)
        self.assertTrue(exhdr.res_id == 0)


    def test_ok(self):
        self.hbuf.len = 16
        self.assertFalse(self.nlh.ok(15))
        self.assertTrue(self.nlh.ok(16))
        self.assertTrue(self.nlh.ok(17))

        self.hbuf.len = 8
        self.assertFalse(self.nlh.ok(7))
        self.assertFalse(self.nlh.ok(8))
        self.assertFalse(self.nlh.ok(9))

        self.hbuf.len = 32
        self.assertFalse(self.nlh.ok(31))
        self.assertTrue(self.nlh.ok(32))
        self.assertTrue(self.nlh.ok(33))


    def test_next_header(self):
        # 256 bytes + 128 bytes + 64 bytes
        self.hbuf.len = mnl.MNL_ALIGN(256)
        self.hbuf[mnl.MNL_ALIGN(256):mnl.MNL_ALIGN(256) + 4] = struct.pack("I", 128)
        self.hbuf[mnl.MNL_ALIGN(256) + mnl.MNL_ALIGN(128):mnl.MNL_ALIGN(256) + mnl.MNL_ALIGN(128) + 4] = struct.pack("I", 64)

        next_nlh, rest = self.nlh.next_header(self.buflen)
        self.assertTrue(rest == self.buflen - 256)
        self.assertTrue(next_nlh.nlmsg_len == mnl.MNL_ALIGN(128))
        # ok()'s job
        self.assertTrue(next_nlh.ok(rest))

        next_nlh, rest = next_nlh.next_header(rest)
        self.assertTrue(rest == self.buflen - 256 - 128)
        self.assertTrue(next_nlh.nlmsg_len == mnl.MNL_ALIGN(64))
        self.assertTrue(next_nlh.ok(rest))

        next_nlh, rest = next_nlh.next_header(rest)
        self.assertTrue(rest == self.buflen - 256 - 128 - 64)
        self.assertFalse(next_nlh.ok(rest)) # because next_nlh.nlmsg_len == 0


    def test_get_payload_tail(self):
        self.hbuf.len = mnl.MNL_ALIGN(323)
        self.hbuf[323] = 0x55
        a = ctypes.addressof(self.nlh)
        self.assertTrue(self.nlh.get_payload_tail() == a + mnl.MNL_ALIGN(323))


    def test_seq_ok(self):
        self.rand_hbuf.seq = 0x12345678
        self.assertTrue(self.rand_nlh.seq_ok(0x12345678))
        self.assertFalse(self.rand_nlh.seq_ok(0x1234))
        self.assertTrue(self.rand_nlh.seq_ok(0))
        self.rand_hbuf.seq = 0
        self.assertTrue(self.rand_nlh.seq_ok(888))


    def test_portid_ok(self):
        self.rand_hbuf.pid = 0x12345678
        self.assertTrue(self.rand_nlh.portid_ok(0x12345678))
        self.assertFalse(self.rand_nlh.portid_ok(0x1234))
        self.assertTrue(self.rand_nlh.portid_ok(0))
        self.rand_hbuf.pid = 0
        self.assertTrue(self.rand_nlh.portid_ok(888))


    # XXX: no assertion
    def _test_print(self):
        self.nlh.nlmsg_type = netlink.NLMSG_MIN_TYPE
        self.nlh.put_extra_header(8)
        nest_start = self.nlh.attr_nest_start(1)
        self.nlh.put_u8(mnl.MNL_TYPE_U8, 0x10)
        self.nlh.put_u16(mnl.MNL_TYPE_U16, 0x11)
        self.nlh.put_u32(mnl.MNL_TYPE_U32, 0x12)
        self.nlh.put_u64(mnl.MNL_TYPE_U64, 0x13)
        self.nlh.attr_nest_end(nest_start)

        next_nlh, rest = msg.next_msg(self.buflen)
        next_nlh.put_header()
        next_nlh.nlmsg_type = netlink.NLMSG_DONE

        msg.print(8)


    def test_batches(self):
        b = mnl.NlmsgBatch(301, 163) # bufsize, limit

        # empty
        self.assertTrue(b.size() == 0)
        self.assertTrue(len(b.current_v()) == 301)
        self.assertTrue(len(b.head()) == 0)
        self.assertTrue(b.is_empty() == True)

        # make buf full
        for i in range(1, 11):
            nlh = mnl.Nlmsg.from_pointer(b.current())
            nlh.put_header()
            self.assertTrue(b.next_batch() == True)
            self.assertTrue(b.size() == mnl.MNL_NLMSG_HDRLEN * i,)
            self.assertTrue(len(b.current_v()) == (301 - mnl.MNL_NLMSG_HDRLEN * i))
            self.assertTrue(len(b.head()) == mnl.MNL_NLMSG_HDRLEN * i)
            self.assertTrue(b.is_empty() == False)

        # after full
        nlh = mnl.Nlmsg.from_pointer(b.current())
        nlh.put_header()
        self.assertTrue(b.next_batch() == False)
        self.assertTrue(b.size() == mnl.MNL_NLMSG_HDRLEN * i)
        self.assertTrue(len(b.current_v()) == (301 - mnl.MNL_NLMSG_HDRLEN * i))
        self.assertTrue(len(b.head()) == mnl.MNL_NLMSG_HDRLEN * i)
        self.assertTrue(b.is_empty() == False)

        # reset
        b.reset()
        self.assertTrue(b.size() == mnl.MNL_NLMSG_HDRLEN)
        self.assertTrue(len(b.current_v()) == (301 - mnl.MNL_NLMSG_HDRLEN))
        self.assertTrue(len(b.head()) == mnl.MNL_NLMSG_HDRLEN)
        self.assertTrue(b.is_empty() == False)

        # reset again, buf will empty after next
        b.next_batch()
        b.reset()
        self.assertTrue(b.is_empty() == True)

        # just call stop
        b.stop()


if __name__ == '__main__':
    unittest.main()
