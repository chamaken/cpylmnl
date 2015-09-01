#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, socket, logging, time, select, errno
import mmap

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnl
import cpylmnl.linux.if_linkh as if_link
from cpylmnl.linux import ifh
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attr_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(if_link.IFLA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    ftbl = {if_link.IFLA_ADDRESS: lambda x: x.validate(mnl.MNL_TYPE_BINARY),
            if_link.IFLA_MTU:     lambda x: x.validate(mnl.MNL_TYPE_U32),
            if_link.IFLA_IFNAME:  lambda x: x.validate(mnl.MNL_TYPE_STRING)}
    try:
        ftbl.get(attr_type, lambda a: (0, None))(attr)
    except OSError as e:
        print("mnl_attr_validate: %s" % e, file=sys.stderr)
        return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.nlmsg_cb
def data_cb(nlh, tb):
    ifm = nlh.get_payload_as(rtnl.Ifinfomsg)
    print("index=%d type=%d flags=%d family=%d " % (ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family), end='')

    if ifm.ifi_flags & ifh.IFF_RUNNING:
        print("[RUNNING] ", end='')
    else:
        print("[NOT RUNNING] ", end='')

    tb = dict()
    nlh.parse(ifm.csize(), data_attr_cb, tb)
    if if_link.IFLA_MTU in tb:
        print("mtu=%d " % (tb[if_link.IFLA_MTU].get_u32()), end='')
    if if_link.IFLA_IFNAME in tb:
        print("name=%s " % (tb[if_link.IFLA_IFNAME].get_str()), end='')
    if if_link.IFLA_ADDRESS in tb:
        hwaddr = (tb[if_link.IFLA_ADDRESS].get_payload_v())
        print("hwaddr=%s" % ":".join("%02x" % i for i in hwaddr), end='')

    print()
    return mnl.MNL_CB_OK


def mnl_socket_poll(nl):
    fd = nl.get_fd()
    p = select.poll()
    while True:
        p.register(fd, select.POLLIN | select.POLLERR)
        try:
            events = p.poll(-1)
        except select.error as e:
            if e[0] == errno.EINTR:
                continue
            raise
        for efd, event in events:
            if efd == fd:
                if event == select.POLLIN:
                    return 0
                if event == select.POLLERR:
                    return -1


def main():
    frame_size = 16384
    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.set_ringopt(mnl.MNL_RING_RX, mnl.MNL_SOCKET_BUFFER_SIZE * 16, 64,
                       frame_size, int(64 * mnl.MNL_SOCKET_BUFFER_SIZE * 16 / frame_size))
        nl.set_ringopt(mnl.MNL_RING_TX, mnl.MNL_SOCKET_BUFFER_SIZE * 16, 64,
                       frame_size, int(64 * mnl.MNL_SOCKET_BUFFER_SIZE * 16 / frame_size))
        nl.map_ring(mmap.MAP_SHARED)
        txring = nl.get_ring(mnl.MNL_RING_TX)
        frame = txring.current_frame()
        buf = mnl.MNL_FRAME_PAYLOAD(frame, frame_size)

        nlh = mnl.nlmsg_put_header(buf, mnl.Nlmsg)
        nlh.nlmsg_type = rtnl.RTM_GETLINK
        nlh.nlmsg_flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
        seq = int(time.time())
        nlh.nlmsg_seq = seq
        rt = nlh.put_extra_header_as(rtnl.Rtgenmsg)
        rt.rtm_family = socket.AF_PACKET

        frame.nm_len = nlh.nlmsg_len
        frame.nm_status = netlink.NL_MMAP_STATUS_VALID

        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        # ??? commit a8866ff6a5bce7d0ec465a63bc482a85c09b0d39
        # nl.sendto(None)
        nl.send_nlmsg(nlh)
        txring.advance()

        rxring = nl.get_ring(mnl.MNL_RING_RX)
        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            # XXX: no try / except
            mnl_socket_poll(nl)
            frame = rxring.current_frame()
            if frame.nm_status == netlink.NL_MMAP_STATUS_VALID:
                buf = mnl.MNL_FRAME_PAYLOAD(frame, frame.nm_len)
            elif frame.nm_status == netlink.NL_MMAP_STATUS_COPY:
                buf = nl.recv(frame_size * 2)
            else:
                frame.nm_status = netlink.NL_MMAP_STATUS_UNUSED
                rxring.advance()
                continue

            try:
                ret = mnl.cb_run(buf, seq, portid, data_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise
            frame.nm_status = netlink.NL_MMAP_STATUS_UNUSED
            rxring.advance()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
