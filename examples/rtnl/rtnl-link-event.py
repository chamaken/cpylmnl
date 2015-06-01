#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

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

    ftbl = {if_link.IFLA_MTU:		lambda x: x.validate(mnl.MNL_TYPE_U32),
            if_link.IFLA_IFNAME:	lambda x: x.validate(mnl.MNL_TYPE_STRING)}
    try:
        ftbl.get(attr_type, lambda x: 0)(attr)
    except OSError as e:
        print("mnl_attr_validate: %s" % e, file=sys.stderr)
        return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.nlmsg_cb
def data_cb(nlh, tb):
    ifm = nlh.get_payload_as(rtnl.Ifinfomsg)

    print("index=%d type=%d flags=%d family=%d " % (ifm.ifi_index, ifm.ifi_type, ifm.ifi_flags, ifm.ifi_family), end='')

    if ifm.flags & ifh.IFF_RUNNING:
        print("[RUNNING] ", end='')
    else:
        print("[NOT RUNNING] ", end='')

    tb = dict()
    nlh.parse(rtnl.Ifinfomsg.csize(), data_attr_cb, tb)
    if if_link.IFLA_MTU in tb:
        print("mtu=%d " % tb[if_link.IFLA_MTU].get_u32(), end='')
    if if_link.IFLA_IFNAME in tb:
        print("name=%s" % tb[if_link.IFLA_IFNAME].get_str(), end='')
    print()

    return mnl.MNL_CB_OK


def main():
    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.bind(rtnl.RTMGRP_LINK, mnl.MNL_SOCKET_AUTOPID)
        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            try:
                buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            except Exception as e:
                print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
                raise
            if len(buf) == 0: break
            try:
                ret = mnl.cb_run(buf, 0, 0, data_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
