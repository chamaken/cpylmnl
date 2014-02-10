#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function

import sys, random, unittest, struct, ctypes, errno
from ctypes import set_errno

import cpylmnl.linux.netlinkh as netlink
import cpylmnl as mnl

from .linux.netlink.buf import *

class TestSuite(unittest.TestCase):
    def setUp(self):
        self.nlmsghdr_noop = NlmsghdrBuf(16)
        self.nlmsghdr_noop.len = 16
        self.nlmsghdr_noop.type = netlink.NLMSG_NOOP
        self.nlmsghdr_noop.flags = netlink.NLM_F_REQUEST
        self.nlmsghdr_noop.seq = 1
        self.nlmsghdr_noop.pid = 1

        self.nlmsghdr_done = NlmsghdrBuf(16)
        self.nlmsghdr_done.len = 16
        self.nlmsghdr_done.type = netlink.NLMSG_DONE
        self.nlmsghdr_done.flags = netlink.NLM_F_REQUEST
        self.nlmsghdr_done.seq = 1
        self.nlmsghdr_done.pid = 1

        self.nlmsghdr_overrun = NlmsghdrBuf(16)
        self.nlmsghdr_overrun.len = 16
        self.nlmsghdr_overrun.type = netlink.NLMSG_OVERRUN
        self.nlmsghdr_overrun.flags = netlink.NLM_F_REQUEST
        self.nlmsghdr_overrun.seq = 1
        self.nlmsghdr_overrun.pid = 1


        mintype_msg = NlmsghdrBuf(16)
        mintype_msg.len = 16
        mintype_msg.type = netlink.NLMSG_MIN_TYPE
        mintype_msg.flags = netlink.NLM_F_REQUEST
        mintype_msg.seq = 1
        mintype_msg.pid = 1
        self.nlmsghdr_mintype = self.nlmsghdr_noop + mintype_msg

        intsize = struct.calcsize("i")
        self.nlmsghdr_error = NlmsghdrBuf(16)
        self.nlmsghdr_error.type = netlink.NLMSG_ERROR
        self.nlmsghdr_error.flags = netlink.NLM_F_REQUEST
        self.nlmsghdr_error.seq = 1
        self.nlmsghdr_error.pid = 1
        self.nlmsghdr_error += struct.pack("i", errno.EPERM)
        error_msg = NlmsghdrBuf(16)
        error_msg.len = 16
        error_msg.type = netlink.NLMSG_ERROR
        error_msg.flags = netlink.NLM_F_REQUEST
        error_msg.seq = 1
        error_msg.pid = 1
        self.nlmsghdr_error += error_msg
        self.nlmsghdr_error.len = len(self.nlmsghdr_error)

        type7F_msg = NlmsghdrBuf(16)
        type7F_msg.len = 16
        type7F_msg.type = 0x7f
        type7F_msg.flags = netlink.NLM_F_REQUEST
        type7F_msg.seq = 1
        type7F_msg.pid = 1
        self.nlmsghdr_type7F = self.nlmsghdr_mintype + type7F_msg

        typeFF_msg = NlmsghdrBuf(16)
        typeFF_msg.len = 16
        typeFF_msg.type = 0xff
        typeFF_msg.flags = netlink.NLM_F_REQUEST
        typeFF_msg.seq = 1
        typeFF_msg.pid = 1
        self.nlmsghdr_typeFF = self.nlmsghdr_mintype + typeFF_msg

        pid2_msg = NlmsghdrBuf(16)
        pid2_msg.len = 16
        pid2_msg.type =0xff
        pid2_msg.flags = netlink.NLM_F_REQUEST
        pid2_msg.seq = 1
        pid2_msg.pid = 2
        self.nlmsghdr_pid2 = self.nlmsghdr_mintype + pid2_msg

        seq2_msg = NlmsghdrBuf(16)
        seq2_msg.len = 16
        seq2_msg.type = 0xff
        seq2_msg.flags = netlink.NLM_F_REQUEST
        seq2_msg.seq = 2
        seq2_msg.pid = 1
        self.nlmsghdr_seq2 = self.nlmsghdr_mintype + seq2_msg

        intr_msg = NlmsghdrBuf(16)
        intr_msg.len = 16
        intr_msg.type = 0xff
        intr_msg.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP_INTR
        intr_msg.seq = 1
        intr_msg.pid = 1
        self.nlmsghdr_intr = self.nlmsghdr_mintype + intr_msg



    def test_cb_run2(self):
        self.assertEqual(mnl.cb_run2(self.nlmsghdr_noop, 1, 1, None, None), mnl.MNL_CB_OK)
        self.assertEqual(mnl.cb_run2(self.nlmsghdr_mintype, 1, 1, None, None), mnl.MNL_CB_OK)
        try:
            mnl.cb_run2(self.nlmsghdr_error, 1, 1, None, None)
        except OSError as e:
            self.assertEquals(e.errno, errno.EPERM)
        else:
            self.fail("not raise OSError")

        @mnl.mnl_cb_t
        def cb_data(h, d):
            d is not None and d.append(h.type)
            if h.type == 0xff:
                ctypes.set_errno(errno.ENOBUFS)
                return mnl.MNL_CB_ERROR
            elif h.type == 0x7f: return mnl.MNL_CB_STOP
            else: return mnl.MNL_CB_OK

        l = []
        try:
            mnl.cb_run2(self.nlmsghdr_typeFF, 1, 1, cb_data, l)
        except OSError as e:
            self.assertEquals(e.errno, errno.ENOBUFS)
        else:
            self.fail("not raise OSError")

        l = []
        ret = mnl.cb_run2(self.nlmsghdr_type7F, 1, 1, cb_data, l)
        self.assertEqual(ret, mnl.MNL_CB_STOP)
        self.assertEqual(l[0], netlink.NLMSG_MIN_TYPE)
        self.assertEqual(l[1], 0x7f)

        try:
            mnl.cb_run2(self.nlmsghdr_pid2, 1, 1, cb_data, None)
        except OSError as e:
            self.assertEqual(e.errno, errno.ESRCH)
        else:
            self.fail("not raise OSError")

        try:
            mnl.cb_run2(self.nlmsghdr_seq2, 1, 1, cb_data, None)
        except OSError as e:
            self.assertEqual(e.errno, errno.EPROTO)
        else:
            self.fail("not raise OSError")

        # Python2.6 returns -1 but could not get EINTR?
        if sys.version_info < (2, 7):
            ret = mnl.cb_run2(self.nlmsghdr_intr, 1, 1, cb_data, None)
            self.assertEquals(ret, mnl.MNL_CB_ERROR)
        else:
            try:
                mnl.cb_run2(self.nlmsghdr_intr, 1, 1, cb_data, None)
            except OSError as e:
                self.assertEqual(e.errno, errno.EINTR)
            else:
                self.fail("not raise OSError")

        # with crl cb
        @mnl.header_cb
        def cb_done(nlh, d):
            return mnl.MNL_CB_STOP

        @mnl.header_cb
        def cb_overrun(nlh, d):
            set_errno(errno.ENOSPC)
            return mnl.MNL_CB_ERROR

        @mnl.header_cb
        def cb_err(nlh, d):
            err = nlh.get_payload_as(netlink.Nlmsgerr)
            if nlh.len < nlh.size(netlink.Nlmsgerr.csize()):
                set_errno(errno.EBADMSG)
                return mnl.MNL_CB_ERROR
            if err.error < 0:
                en = - err.error
            else:
                en = err.error
            if errno == 0:
                return mnl.MNL_CB_STOP
            else:
                set_errno(en)
                return mnl.MNL_CB_ERROR

        cb_ctls = {netlink.NLMSG_OVERRUN: cb_overrun,
                   netlink.NLMSG_DONE: cb_done,
                   netlink.NLMSG_ERROR: cb_err}
        self.assertEqual(mnl.cb_run2(self.nlmsghdr_noop, 1, 1, None, None, cb_ctls), mnl.MNL_CB_OK)
        self.assertEqual(mnl.cb_run2(self.nlmsghdr_done, 1, 1, None, None, cb_ctls), mnl.MNL_CB_STOP)
        try:
            mnl.cb_run2(self.nlmsghdr_overrun, 1, 1, None, None, cb_ctls)
        except OSError as e:
            self.assertEqual(e.errno, errno.ENOSPC)
        else:
            self.fail("not raise OSError")
        try:
            mnl.cb_run2(self.nlmsghdr_error, 1, 1, None, None, cb_ctls)
        except OSError as e:
            self.assertEqual(e.errno, errno.EPERM)
        else:
            self.fail("not raise OSError")


if __name__ == '__main__':
    unittest.main()
