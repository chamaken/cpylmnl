#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function

import sys, random, unittest, struct, ctypes, errno

import cpylmnl.linux.netlinkh as netlink
import cpylmnl as mnl

class TestSuite(unittest.TestCase):
    def setUp(self):
        pass


    def test_cb_run2(self):
        # return _cb_run(buf, seq, portid, cb_data, data, cb_ctl)
        b = bytearray()
        b += bytearray(struct.pack("I", 16) \
                           + struct.pack("H", netlink.NLMSG_NOOP) + struct.pack("H", netlink.NLM_F_REQUEST) \
                           + struct.pack("I", 1) \
                           + struct.pack("I", 1))
        self.assertEqual(mnl.cb_run2(b, 1, 1, None, None), mnl.MNL_CB_OK)

        b += bytearray(struct.pack("I", 16) \
                           + struct.pack("H", netlink.NLMSG_MIN_TYPE) + struct.pack("H", netlink.NLM_F_REQUEST) \
                           + struct.pack("I", 1) \
                           + struct.pack("I", 1))
        self.assertEqual(mnl.cb_run2(b, 1, 1, None, None), mnl.MNL_CB_OK)

        eb = bytearray()
        eb += bytearray(struct.pack("I", 16) \
                            + struct.pack("H", netlink.NLMSG_ERROR) + struct.pack("H", netlink.NLM_F_REQUEST) \
                            + struct.pack("I", 1) \
                            + struct.pack("I", 1))
        eb += bytearray(struct.pack("i", errno.EPERM))
        eb += bytearray(struct.pack("I", 16) \
                            + struct.pack("H", netlink.NLMSG_ERROR) + struct.pack("H", netlink.NLM_F_REQUEST) \
                            + struct.pack("I", 1) \
                            + struct.pack("I", 1))
        self.assertRaises(OSError, mnl.cb_run2, eb, 1, 1, None, None)

        eb[:4] = struct.pack("I", len(eb))
        self.assertRaises(OSError, mnl.cb_run2, b + eb, 1, 1, None, None)
        self.assertEqual(ctypes.get_errno(), errno.EPERM)


        # cb_data = lambda h, d: h.type == 0xff and (mnl.MNL_CB_ERROR, Exception("cb error")) or (mnl.MNL_CB_OK, None)
        @mnl.mnl_cb_t
        def cb_data(h, d):
            if h.type == 0xff: return mnl.MNL_CB_ERROR
            else: return mnl.MNL_CB_OK

        eb = bytearray()
        eb += bytearray(struct.pack("I", 16) \
                            + struct.pack("H", 0xff) + struct.pack("H", netlink.NLM_F_REQUEST) \
                            + struct.pack("I", 1) \
                            + struct.pack("I", 1))
        ret = mnl.cb_run2(b + eb, 1, 1, cb_data, None)
        self.assertEqual(ret, mnl.MNL_CB_ERROR)

        eb = bytearray(struct.pack("I", 16) \
                           + struct.pack("H", 0xff) + struct.pack("H", netlink.NLM_F_REQUEST) \
                           + struct.pack("I", 1) \
                           + struct.pack("I", 2))
        self.assertRaises(OSError, mnl.cb_run2, b + eb, 1, 1, cb_data, None)
        self.assertEqual(ctypes.get_errno(), errno.ESRCH)

        eb = bytearray(struct.pack("I", 16) \
                           + struct.pack("H", 0xff) + struct.pack("H", netlink.NLM_F_REQUEST) \
                           + struct.pack("I", 2) \
                           + struct.pack("I", 1))
        self.assertRaises(OSError, mnl.cb_run2, b + eb, 1, 1, cb_data, None)
        self.assertEqual(ctypes.get_errno(), errno.EPROTO)

        eb = bytearray(struct.pack("I", 16) \
                           + struct.pack("H", 0xff) + struct.pack("H", netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP_INTR) \
                           + struct.pack("I", 1) \
                           + struct.pack("I", 1))
        self.assertRaises(OSError, mnl.cb_run2, b + eb, 1, 1, cb_data, None)
        self.assertEqual(ctypes.get_errno(), errno.EINTR)
        
        self.assertRaises(OSError, mnl.cb_run, b + eb, 1, 1, cb_data, None)
        self.assertEqual(ctypes.get_errno(), errno.EINTR)


        # XXX: no cb_ctls specifying

if __name__ == '__main__':
    unittest.main()
