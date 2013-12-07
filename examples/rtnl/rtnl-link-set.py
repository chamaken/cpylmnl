#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl.nlstructs.rtnetlink as rtnl
from cpylmnl.nlstructs import if_link
import cpylmnl as mnl


log = logging.getLogger(__name__)


def main():
    if len(sys.argv) != 3:
        print("Usage: %s [ifname] [up|down]" % sys.argv[0])
        sys.exit(-1)

    change = 0
    flags = 0
    if sys.argv[2].lower() == "up":
        change |= h.IFF_UP
        flags |= h.IFF_UP
    elif sys.argv[2].lower() == "down":
        change |= h.IFF_UP
        flags &= ~h.IFF_UP
    else:
        print("%s is not `up' nor 'down'" % sys.argv[2], file=sys.stderr)
        sys.exit(-1)

    nlh = mnl.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = h.RTM_NEWLINK
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_ACK
    seq = int(time.time())
    nlh.seq = seq
    ifm = nlh.put_extra_header_as(rtnl.Ifinfomsg.sizeof(), rtnl.Ifinfomsg)
    ifm.family = socket.AF_UNSPEC
    ifm.change = change
    ifm.flags = flags

    nlh.put_str(h.IFLA_IFNAME, sys.argv[1])

    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        nlh.fprint(rtnl.Ifinfomsg.sizeof(), out=sys.stdout)

        nl.send_nlmsg(nlh)
        buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)

        # cb_run will raise OSException in case of error
        if mnl.cb_run(buf, seq, portid, None, None) < mnl.MNL_CB_STOP:
            print("cb_run returns ERROR", file=sys.stderr)
            os.exit(-1)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
