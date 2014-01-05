#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

import cpylmnl as mnl
import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnl
from cpylmnl.linux import if_link, ifh


log = logging.getLogger(__name__)


@mnl.attribute_cb
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
        ftbl.get(attr_type, lambda x: 0)(attr)
    except OSError as e:
        print("mnl_attr_validate: %s" % e, file=sys.stderr)
        return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def data_cb(nlh, tb):
    ifm = nlh.get_payload_as(rtnl.Ifinfomsg)
    print("index=%d type=%d flags=%d family=%d " % (ifm.index, ifm.type, ifm.flags, ifm.family), end='')

    if ifm.flags & ifh.IFF_RUNNING:
        print("[RUNNING] ", end='')
    else:
        print("[NOT RUNNING] ", end='')

    tb = dict()
    nlh.parse(rtnl.Ifinfomsg.sizeof(), data_attr_cb, tb)

    if if_link.IFLA_MTU in tb:
        print("mtu=%d " % tb[if_link.IFLA_MTU].get_u32(), end='')
    if if_link.IFLA_IFNAME in tb:
        print("name=%s " % tb[if_link.IFLA_IFNAME].get_str(), end='')
    if if_link.IFLA_ADDRESS in tb:
        hwaddr = tb[if_link.IFLA_ADDRESS].get_payload_v()
        print("hwaddr=%s" % ":".join("%02x" % i for i in hwaddr), end='')

    print()
    return mnl.MNL_CB_OK


def main():
    nlh = mnl.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = rtnl.RTM_GETLINK
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.seq = seq
    rt = nlh.put_extra_header_as(rtnl.Rtgenmsg)
    rt.family = socket.AF_PACKET

    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()
        nl.send_nlmsg(nlh)

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            try:
                buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            except Exception as e:
                print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
                raise
            if len(buf) == 0: break
            try:
                ret = mnl.cb_run(buf, nlh.seq, portid, data_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
