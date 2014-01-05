#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, socket, logging, time

import cpylmnl as mnl
import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnl
import cpylmnl.linux.if_linkh as if_link
from cpylmnl.linux import ifh


log = logging.getLogger(__name__)


@mnl.mnl_attr_cb_t
def data_attr_cb(attr, tb):
    attr_type = mnl.attr_get_type(attr)

    # skip unsupported attribute in user-space
    try:
        mnl.attr_type_valid(attr, if_link.IFLA_MAX)
    except OSError as e:
        print("mnl_attr_validate: %s" % e, file=sys.stderr)
        return mnl.MNL_CB_OK

    ftbl = {if_link.IFLA_ADDRESS: lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_BINARY),
            if_link.IFLA_MTU:     lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_U32),
            if_link.IFLA_IFNAME:  lambda x: mnl.attr_validate(x, mnl.MNL_TYPE_STRING)}
    try:
        ftbl.get(attr_type, lambda a: (0, None))(attr)
    except OSError as e:
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
        # print("ifname_len=%d " % tb[h.IFLA_IFNAME].get_payload_len())
    if if_link.IFLA_ADDRESS in tb:
        hwaddr = mnl.attr_get_payload_v(tb[if_link.IFLA_ADDRESS])
        print("hwaddr=%s" % ":".join("%02x" % i for i in hwaddr), end='')

    print()
    return mnl.MNL_CB_OK


def main():
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh = mnl.nlmsg_put_header(buf)
    nlh.type = rtnl.RTM_GETLINK
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.seq = seq
    rt = mnl.nlmsg_put_extra_header_as(nlh, rtnl.Rtgenmsg)
    rt.family = socket.AF_PACKET

    nl = mnl.socket_open(netlink.NETLINK_ROUTE)
    mnl.socket_bind(nl, 0, mnl.MNL_SOCKET_AUTOPID)
    portid = mnl.socket_get_portid(nl)
    mnl.socket_sendto(nl, buf[:nlh.len])

    ret = mnl.MNL_CB_OK
    while ret > mnl.MNL_CB_STOP:
        try:
            buf = mnl.socket_recv(nl, mnl.MNL_SOCKET_BUFFER_SIZE)
        except Exception as e:
            print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
            raise
        if len(buf) == 0: break
        try:
            ret = mnl.cb_run(buf, seq, portid, data_cb, None)
        except Exception as e:
            print("mnl_cb_run: %s" % e, file=sys.stderr)
            raise

    mnl.socket_close(nl)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
