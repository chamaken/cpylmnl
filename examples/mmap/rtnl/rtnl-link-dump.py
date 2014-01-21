#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, socket, logging, time, select, errno

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnl
import cpylmnl.linux.if_linkh as if_link
from cpylmnl.linux import ifh
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.mnl_attr_cb_t
def data_attr_cb(attr, tb):
    attr_type = mnl.attr_get_type(attr)

    # skip unsupported attribute in user-space
    try:
        mnl.attr_type_valid(attr, if_link.IFLA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    ftbl = {if_link.IFLA_ADDRESS: lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_BINARY),
            if_link.IFLA_MTU:     lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_U32),
            if_link.IFLA_IFNAME:  lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_STRING)}
    try:
        ftbl.get(attr_type, lambda a: (0, None))(attr)
    except OSError as e:
        print("mnl_attr_validate: %s" % e, file=sys.stderr)
        return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.mnl_cb_t
def data_cb(nlh, tb):
    ifm = mnl.nlmsg_get_payload_as(nlh, rtnl.Ifinfomsg)
    print("index=%d type=%d flags=%d family=%d " % (ifm.index, ifm.type, ifm.flags, ifm.family), end='')

    if ifm.flags & ifh.IFF_RUNNING:
        print("[RUNNING] ", end='')
    else:
        print("[NOT RUNNING] ", end='')

    tb = dict()
    mnl.attr_parse(nlh, ifm.sizeof(), data_attr_cb, tb)
    if if_link.IFLA_MTU in tb:
        print("mtu=%d " % mnl.attr_get_u32(tb[if_link.IFLA_MTU]), end='')
    if if_link.IFLA_IFNAME in tb:
        print("name=%s " % mnl.attr_get_str(tb[if_link.IFLA_IFNAME]), end='')
    if if_link.IFLA_ADDRESS in tb:
        hwaddr = mnl.attr_get_payload_v(tb[if_link.IFLA_ADDRESS])
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
        except OSError as e:
            if e.errno == errno.EINTR:
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
                       frame_size, 64 * mnl.MNL_SOCKET_BUFFER_SIZE * 16 / frame_size)
        nl.set_ringopt(mnl.MNL_RING_TX, mnl.MNL_SOCKET_BUFFER_SIZE * 16, 64,
                       frame_size, 64 * mnl.MNL_SOCKET_BUFFER_SIZE * 16 / frame_size)
        nl.map_ring()
        txring = nl.get_ring(mnl.MNL_RING_TX)
        frame = txring.get_frame()
        buf = mnl.MNL_FRAME_PAYLOAD(frame, frame_size)

        nlh = mnl.nlmsg_put_header(buf, mnl.Header)
        nlh.type = rtnl.RTM_GETLINK
        nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
        seq = int(time.time())
        nlh.seq = seq
        rt = nlh.put_extra_header_as(rtnl.Rtgenmsg)
        rt.family = socket.AF_PACKET

        frame.len = nlh.len
        frame.status = netlink.NL_MMAP_STATUS_VALID

        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()
        nl.sendto(None)
        txring.advance()

        rxring = nl.get_ring(mnl.MNL_RING_RX)
        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            # XXX: no try / except
            mnl_socket_poll(nl)
            frame = rxring.get_frame();
            if frame.status == netlink.NL_MMAP_STATUS_VALID:
                buf = mnl.MNL_FRAME_PAYLOAD(frame, frame.len)
            elif frame.status == netlink.NL_MMAP_STATUS_COPY:
                buf = nl.recv(frame_size * 2)
            else:
                frame.status = netlink.NL_MMAP_STATUS_UNUSED
                rxring.advance()
                continue

            try:
                ret = mnl.cb_run(buf, seq, portid, data_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise
            frame.status = netlink.NL_MMAP_STATUS_UNUSED
            rxring.advance()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
