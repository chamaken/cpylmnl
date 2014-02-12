#! /usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import print_function

import sys, os, unittest, stat, errno
import struct, fcntl
import ctypes

import cpylmnl.linux.netlinkh as netlink
import cpylmnl as mnl


class TestSuite(unittest.TestCase):
    """Almost just calling them
    """
    def setUp(self):
        self.nl = mnl.Socket(netlink.NETLINK_NETFILTER)


    def tearDown(self):
        if self.nl: self.nl.close()


    def test_fd(self):
        fd = self.nl.get_fd()
        self.assertTrue(stat.S_ISSOCK(os.fstat(fd).st_mode))
        self.assertEqual(self.nl.close(), 0)
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except IOError as e:
            self.assertEqual(e.errno, errno.EBADF)
        else:
            self.fail("socket is still open")
        self.nl = None # or double free occur


    def test_port_bind(self):
        self.assertEqual(self.nl.get_portid(), 0)
        self.nl.bind(0, 65432) # it may fail
        self.assertEqual(self.nl.get_portid(), 65432)

        try:
            self.nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        except OSError as e:
            self.assertEqual(e.errno, errno.EINVAL)
        else:
            self.fail("not raise OSError")


    def test_send_recv(self):
        self.nl.bind(0, mnl.MNL_SOCKET_AUTOPID)

        nlh = mnl.Header.put_new_header(mnl.MNL_NLMSG_HDRLEN)
        nlh.type = netlink.NLMSG_NOOP
        nlh.flags = netlink.NLM_F_ECHO|netlink.NLM_F_ACK
        nlh.pid = self.nl.get_portid()
        nlh.seq = 1234

        # sendto & recv
        self.assertEqual(self.nl.sendto(nlh.marshal_binary()), mnl.MNL_NLMSG_HDRLEN)
        nlr = mnl.Header(self.nl.recv(256))

        self.assertEqual(nlr.len, 36)
        self.assertEqual(nlr.type, netlink.NLMSG_ERROR)
        nle = netlink.Nlmsgerr(nlr.get_payload_v())
        self.assertEquals(abs(nle.error), errno.EPERM)
        self.assertEquals(nle.msg.len, mnl.MNL_NLMSG_HDRLEN)
        self.assertEquals(nle.msg.type, netlink.NLMSG_NOOP)
        self.assertEquals(nle.msg.flags, netlink.NLM_F_ECHO|netlink.NLM_F_ACK)
        self.assertEquals(nle.msg.pid, self.nl.get_portid())
        self.assertEquals(nle.msg.seq, 1234)

        # send_nlmsg & recv_into
        b = bytearray(256)
        self.assertEqual(self.nl.send_nlmsg(nlh), mnl.MNL_NLMSG_HDRLEN)
        nrcv = self.nl.recv_into(b)
        nlr = mnl.Header(b[:nrcv])
        # repeat
        self.assertEqual(nlr.len, 36)
        self.assertEqual(nlr.type, netlink.NLMSG_ERROR)
        nle = netlink.Nlmsgerr(nlr.get_payload_v())
        self.assertEquals(abs(nle.error), errno.EPERM)
        self.assertEquals(nle.msg.len, mnl.MNL_NLMSG_HDRLEN)
        self.assertEquals(nle.msg.type, netlink.NLMSG_NOOP)
        self.assertEquals(nle.msg.flags, netlink.NLM_F_ECHO|netlink.NLM_F_ACK)
        self.assertEquals(nle.msg.pid, self.nl.get_portid())
        self.assertEquals(nle.msg.seq, 1234)


    def test_opt(self):
        on = struct.pack("i", 1)
        self.nl.setsockopt(netlink.NETLINK_BROADCAST_ERROR, on)
        opt = self.nl.getsockopt(netlink.NETLINK_BROADCAST_ERROR, 4)
        self.assertEquals(struct.unpack("i", bytes(opt))[0], 1)
        self.assertEquals(self.nl.getsockopt_as(netlink.NETLINK_BROADCAST_ERROR, ctypes.c_int), 1)


if __name__ == '__main__':
    unittest.main()
