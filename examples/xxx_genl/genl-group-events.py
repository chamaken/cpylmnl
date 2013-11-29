#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from pylmnl import netlink
import pylmnl.netlink.rtnetlink as rtnl
import pylmnl.netlink.genetlink as genl
import pylmnl as mnl

log = logging.getLogger(__name__)

group = 0

def data_cb(nlh, data):
    print("received event type=%d from genetlink group %d" % (nlh.type, group))
    return mnl.CB.OK, None


def main():
    if len(sys.argv) != 2:
        print("%s [group]" % sys.argv[0])
        sys.exit(-1)

    group = int(sys.argv[1])

    nl = mnl.Socket()
    nl.open(netlink.NETLINK_PROTO.GENERIC)
    nl.bind(0, mnl.SOCKET_AUTOPID)
    nl.setsockopt(netlink.NETLINK_SOCKOPT.ADD_MEMBERSHIP, group)

    buf = nl.recvfrom(mnl.SOCKET_BUFFER_SIZE)
    while len(buf) > 0:
        ret, err = mnl.cb_run(buf, 0, 0, data_cb, None)
        if ret <= 0:
            break
        buf = nl.recvfrom(mnl.SOCKET_BUFFER_SIZE)

    if err is not None:
        print("error: %s" % err, file=sys.stderr)
        sys.exit(-1)

    nl.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
