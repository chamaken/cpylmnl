#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time, struct

import cpylmnl.linux.netlinkh as netlink
import cpylmnl as mnl


log = logging.getLogger(__name__)
group = 0


@mnl.attribute_cb
def data_cb(nlh, data):
    print("received event type=%d from genetlink group %d" % (nlh.nlmsg_type, group))
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
            try:
                buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
                ret = mnl.cb_run(buf, 0, 0, data_cb, None)
            except Exception as e:
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
