#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl.nlstructs.rtnetlink as rtnl
from cpylmnl.nlstructs import if_link
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attribute_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(h.IFLA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    ftbl = {h.IFLA_MTU:		lambda x: x.validate(mnl.MNL_TYPE_U32),
            h.IFLA_IFNAME:	lambda x: x.validate(mnl.MNL_TYPE_STRING)}
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

    if ifm.flags & h.IFF_RUNNING:
        print("[RUNNING] ", end='')
    else:
        print("[NOT RUNNING] ", end='')

    tb = dict()
    nlh.parse(rtnl.Ifinfomsg.sizeof(), data_attr_cb, tb)
    if h.IFLA_MTU in tb:
        print("mtu=%d " % tb[h.IFLA_MTU].get_u32(), end='')
    if h.IFLA_IFNAME in tb:
        print("name=%s" % tb[h.IFLA_IFNAME].get_str(), end='')
    print()

    return mnl.MNL_CB_OK


def main():
    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.bind(h.RTMGRP_LINK, mnl.MNL_SOCKET_AUTOPID)
        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            ret = mnl.cb_run(buf, 0, 0, data_cb, None)

    if ret < 0: # not valid. cb_run will raise Exception
        print("mnl_cb_run returns ERROR", file=sys.stderr)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
