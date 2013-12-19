#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl as mnl


log = logging.getLogger(__name__)


def main():
    with mnl.Socket(netlink.NETLINK_KOBJECT_UEVENT) as nl:
        nl.bind((1 << 0), mnl.MNL_SOCKET_AUTOPID)
        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            for c in nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE):
                print("%c" % c)
            print()


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
