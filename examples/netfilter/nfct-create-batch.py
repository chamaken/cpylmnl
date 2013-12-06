#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, logging, socket, time, select
import ipaddr

from cpylmnl import netlink, h
import cpylmnl.nlstructs.nfnetlink as nfnl
import cpylmnl as mnl


log = logging.getLogger(__name__)


def put_msg(buf, i, seq):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (h.NFNL_SUBSYS_CTNETLINK << 8) | h.IPCTNL_MSG_CT_NEW
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_CREATE | netlink.NLM_F_EXCL | netlink.NLM_F_ACK
    nlh.seq = seq

    nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg.sizeof(), nfnl.Nfgenmsg)
    nfh.family = socket.AF_INET
    nfh.version = h.NFNETLINK_V0
    nfh.res_id = 0

    # 1.1.1.1:i -> 2.2.2.2:1025
    nest1 = nlh.nest_start(h.CTA_TUPLE_ORIG)
    nest2 = nlh.nest_start(h.CTA_TUPLE_IP)
    nlh.put_u32(h.CTA_IP_V4_SRC, int(ipaddr.IPv4Address("1.1.1.1")))
    nlh.put_u32(h.CTA_IP_V4_DST, int(ipaddr.IPv4Address("2.2.2.2")))
    nlh.nest_end(nest2)
    nest2 = nlh.nest_start(h.CTA_TUPLE_PROTO)
    nlh.put_u8(h.CTA_PROTO_NUM, socket.IPPROTO_TCP)
    nlh.put_u16(h.CTA_PROTO_SRC_PORT, socket.htons(i))
    nlh.put_u16(h.CTA_PROTO_DST_PORT, socket.htons(1025))
    nlh.nest_end(nest2)
    nlh.nest_end(nest1)

    # 2.2.2.2:1025 -> 1.1.1.1:i
    nest1 = nlh.nest_start(h.CTA_TUPLE_REPLY)
    nest2 = nlh.nest_start(h.CTA_TUPLE_IP)
    nlh.put_u32(h.CTA_IP_V4_SRC, int(ipaddr.IPv4Address("2.2.2.2")))
    nlh.put_u32(h.CTA_IP_V4_DST, int(ipaddr.IPv4Address("1.1.1.1")))
    nlh.nest_end(nest2)
    nest2 = nlh.nest_start(h.CTA_TUPLE_PROTO)
    nlh.put_u8(h.CTA_PROTO_NUM, socket.IPPROTO_TCP)
    nlh.put_u16(h.CTA_PROTO_SRC_PORT, socket.htons(1025))
    nlh.put_u16(h.CTA_PROTO_DST_PORT, socket.htons(i))
    nlh.nest_end(nest2)
    nlh.nest_end(nest1)

    # TCP SYN
    nest1 = nlh.nest_start(h.CTA_PROTOINFO)
    nest2 = nlh.nest_start(h.CTA_PROTOINFO_TCP)
    nlh.put_u8(h.CTA_PROTOINFO_TCP_STATE, h.TCP_CONNTRACK_SYN_SENT)
    nlh.nest_end(nest2)
    nlh.nest_end(nest1)

    # status and timeout
    nlh.put_u32(h.CTA_STATUS, socket.htonl(h.IPS_CONFIRMED))
    nlh.put_u32(h.CTA_TIMEOUT, socket.htonl(1000))


@mnl.header_cb
def cb_err(nlh, data):
    err = nlh.get_payload_as(netlink.Nlmsgerr)
    if err.error != 0:
        print("message with seq %u has failed: %s" % (nlh.seq, os.strerror(-err.error)), file=sys.stderr)

    return mnl.MNL_CB_OK


# CB_CTL_ARRAY = [None] * (netlink.NLMSG_MIN_TYPE - 1)
CB_CTL_ARRAY = {netlink.NLMSG_ERROR: cb_err}

def send_batch(nl, b, portid):
    fd = nl.get_fd()
    size = b.size()

    ## try... except
    nl.sendto(b.head())

    while True:
        rlist, _wlist, _xlist = select.select([fd], [], [], 0.0)
        # rlist, _wlist, _xlist = select.select([fd], [], [], 1.0)
        if not fd in rlist:
            break

        rcv_buf = nl.recvfrom(mnl.MNL_SOCKET_BUFFER_SIZE)
        ret = mnl.cb_run2(rcv_buf, 0, portid, None, None, CB_CTL_ARRAY)
        if ret == mnl.MNL_CB_ERROR: # may invalid, raises Exception at cb_run2
            print("mnl_cb_run returns ERROR", file=sys.stderr)
            sys.exit(-1)


def main():
    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        with mnl.NlmsgBatch(mnl.MNL_SOCKET_BUFFER_SIZE * 2, mnl.MNL_SOCKET_BUFFER_SIZE) as b:
            seq = int(time.time())
            for j, i in enumerate(list(range(1024, 65535))):
                put_msg(b.current(), i, seq + j)
                if b.next():
                    continue

                send_batch(nl, b, portid)
                b.reset()

            if not b.is_empty():
                send_batch(nl, b, portid)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
