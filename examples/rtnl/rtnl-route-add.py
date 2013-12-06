#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time, struct

from cpylmnl import netlink, h
import cpylmnl.nlstructs.rtnetlink as rtnl
from cpylmnl.nlstructs import if_addr
import cpylmnl as mnl


log = logging.getLogger(__name__)


def if_nametoindex (name): # https://gist.github.com/trhura/5811896
    import ctypes
    import ctypes.util
 
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
 
    if not isinstance (name, str):
        raise TypeError ('name must be a string.')
    ret = libc.if_nametoindex (name)
    if not ret:
        raise RunTimeError ("Invalid Name")
    return ret


def main():
    if len(sys.argv) <= 3:
        print("Usage: %s iface destination cidr [gateway]" % sys.argv[0])
        print("Example: %s eth0 10.0.1.12 32 10.0.1.11" % sys.argv[0])
        print("	 %s eth0 ffff::10.0.1.12 128 fdff::1" % sys.argv[0])
        sys.exit(-1)
        
    iface = if_nametoindex(sys.argv[1])

    try:
        # dst = struct.unpack("I", socket.inet_pton(socket.AF_INET, sys.argv[2]))[0]
        dst = bytearray(socket.inet_pton(socket.AF_INET, sys.argv[2]))
        family = socket.AF_INET
    except OSError as e:
        dst = bytearray(socket.inet_pton(socket.AF_INET6, sys.argv[2]))
        family = socket.AF_INET6

    prefix = int(sys.argv[3])

    if len(sys.argv) == 5:
        gw = bytearray(socket.inet_pton(family, sys.argv[4]))

    nlh = mnl.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = h.RTM_NEWROUTE
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_CREATE | netlink.NLM_F_ACK
    seq = int(time.time())
    nlh.seq = seq

    rtm = nlh.put_extra_header_as(rtnl.Rtmsg.sizeof(), rtnl.Rtmsg)
    rtm.family = family
    rtm.dst_len = prefix
    rtm.src_len = 0
    rtm.tos = 0
    rtm.protocol = h.RTPROT_STATIC
    rtm.table = h.RT_TABLE_MAIN
    rtm.type = h.RTN_UNICAST
    # is there any gateway?
    rtm.scope = len(sys.argv) == 4 and h.RT_SCOPE_LINK or h.RT_SCOPE_UNIVERSE
    rtm.flags = 0

    log.debug("family: %d, dst len: %d" % (family, len(dst)))
    nlh.put(h.RTA_DST, dst)

    nlh.put_u32(h.RTA_OIF, iface)
    if len(sys.argv) == 5:
        log.info("family: %d, gw len: %d" % (family, len(gw)))
        nlh.put(h.RTA_GATEWAY, gw)

    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        nl.send_nlmsg(nlh)
        buf = nl.recvfrom(mnl.MNL_SOCKET_BUFFER_SIZE)

        if mnl.cb_run(buf, seq, portid, None, None) < 0:
            print("mnl_cb_run returns ERROR", file=sys.stderr)
            sys.exit(-1)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
