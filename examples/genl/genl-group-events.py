#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time, struct

from cpylmnl import netlink
import cpylmnl as mnl


log = logging.getLogger(__name__)
group = 0


@mnl.attribute_cb
def data_cb(nlh, data):
    print("received event type=%d from genetlink group %d" % (nlh.type, group))
    return mnl.MNL_CB_OK


def main():
    if len(sys.argv) != 2:
        print("%s [group]" % sys.argv[0])
        sys.exit(-1)

    global group
    group = int(sys.argv[1])

    with mnl.Socket(netlink.NETLINK_GENERIC) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        nl.setsockopt(netlink.NETLINK_ADD_MEMBERSHIP, struct.pack("i", group))

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            ret = mnl.cb_run(buf, 0, 0, data_cb, None)

    if ret < 0: # not valid. cb_run may raise Exception
        print("mnl_cb_run returns ERROR", file=sys.stderr)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
