#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, socket, logging, time

import cpylmnl as mnl
from cpylmnl import netlink

import cpylmnl.nlstructs.rtnetlink as rtnl
from cpylmnl.nlstructs import if_link

import cpylmnl.h as h
# from pylmnl.linux import ifh


log = logging.getLogger(__name__)


@mnl.mnl_attr_cb_t
def data_attr_cb(attr, tb):
    attr_type = mnl.attr_get_type(attr)

    # skip unsupported attribute in user-space
    try:
        mnl.attr_type_valid(attr, h.IFLA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    ftbl = {h.IFLA_ADDRESS: lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_BINARY),
            h.IFLA_MTU:     lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_U32),
            h.IFLA_IFNAME:  lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_STRING)}
    # try
    rc = ftbl.get(attr_type, lambda a: (0, None))(attr)
    if rc < 0:
        return mnl.MNL_CB_ERROR
    # raise OSError(err, os.strerror(err))
    # return mnl.MNL_CB_ERROR, err

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.mnl_cb_t
def data_cb(nlh, tb):
    ifm = mnl.nlmsg_get_payload_as(nlh, rtnl.Ifinfomsg)
    print("index=%d type=%d flags=%d family=%d " % (ifm.index, ifm.type, ifm.flags, ifm.family), end='')

    if ifm.flags & h.IFF_RUNNING:
        print("[RUNNING] ", end='')
    else:
        print("[NOT RUNNING] ", end='')

    tb = dict()
    mnl.attr_parse(nlh, ifm.sizeof(), data_attr_cb, tb)
    if h.IFLA_MTU in tb:
        print("mtu=%d " % mnl.attr_get_u32(tb[h.IFLA_MTU]), end='')
    if h.IFLA_IFNAME in tb:
        print("name=%s " % mnl.attr_get_str(tb[h.IFLA_IFNAME]), end='')
        # print("ifname_len=%d " % tb[h.IFLA_IFNAME].get_payload_len())
    if h.IFLA_ADDRESS in tb:
        hwaddr = mnl.attr_get_payload_v(tb[h.IFLA_ADDRESS])
        print("hwaddr=%s" % ":".join("%02x" % i for i in hwaddr), end='')

    print()
    return mnl.MNL_CB_OK


def main():
    frame_size = 16384
    nlmr = netlink.NlMmapReq(block_size = mnl.MNL_SOCKET_BUFFER_SIZE * 16,
                             block_nr = 64,
                             frame_size = frame_size,
                             frame_nr = 64 * mnl.MNL_SOCKET_BUFFER_SIZE * 16 / frame_size)
    nl = mnl.socket_open(netlink.NETLINK_ROUTE)
    nlm = mnl.ring_map(nl, nlmr, nlmr)
    hdr = mnl.ring_get_frame(nlm, mnl.MNL_RING_TX)
    buf = mnl.MMAP_MSGHDR(hdr, frame_size)

    nlh = mnl.nlmsg_put_header(buf)
    nlh.type = h.RTM_GETLINK
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.seq = seq
    rt = mnl.nlmsg_put_extra_header_as(nlh, rtnl.Rtgenmsg)
    rt.family = socket.AF_PACKET

    hdr.len = nlh.len
    hdr.status = netlink.NL_MMAP_STATUS_VALID

    mnl.socket_bind(nl, 0, mnl.MNL_SOCKET_AUTOPID)
    portid = mnl.socket_get_portid(nl)
    mnl.socket_sendto(nl, None)
    mnl.ring_advance(nlm, mnl.MNL_RING_TX)

    ret = mnl.MNL_CB_OK
    while ret > mnl.MNL_CB_STOP:
        # XXX: no try / except
        mnl.ring_poll(nlm, -1)
        hdr = mnl.ring_get_frame(nlm, mnl.MNL_RING_RX);
        if hdr.status == netlink.NL_MMAP_STATUS_VALID:
            buf = mnl.MMAP_MSGHDR(hdr, hdr.len)
        else:
            buf = mnl.socket_recv(nl, frame_size)
        
        ret = mnl.cb_run(buf, seq, portid, data_cb, None)
        hdr.status = netlink.NL_MMAP_STATUS_UNUSED
        mnl.ring_advance(nlm, mnl.MNL_RING_RX)

    if ret < 0: # not valid. cb_run may raise Exception
        print("mnl_cb_run returns ERROR", file=sys.stderr)

    mnl.ring_unmap(nlm)
    mnl.socket_close(nl)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
