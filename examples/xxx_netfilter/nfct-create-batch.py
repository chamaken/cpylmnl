#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, logging, socket, time, select
import ipaddr

from pylmnl import netlink
import pylmnl.netlink.nfnetlink as nfnl
import pylmnl.netlink.nfnetlink.conntrack as nfnlct
import pylmnl as mnl
from pylmnl.linux.netfilter.conntrack import tcp as nfcttcp
from pylmnl.linux.netfilter.conntrack import common as nfctcommon

log = logging.getLogger(__name__)


def put_msg(buf, i, seq):
    nlh = mnl.Message(buf)
    nlh = nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS.CTNETLINK << 8) | nfnlct.IPCTNL_MSG.CT_NEW
    nlh.flags = netlink.NLM_F.REQUEST | netlink.NLM_F.CREATE | netlink.NLM_F.EXCL | netlink.NLM_F.ACK
    nlh.seq = seq

    nfh = nfnl.NFGenMsg(nlh.put_extra_header(nfnl.NFGenMsg.SIZEOF))
    nfh.family = socket.AF_INET
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    # 2.2.2.2:i -> 1.1.1.1:1025
    nest1 = nlh.attr_nest_start(nfnlct.CTA.TUPLE_ORIG)
    nest2 = nlh.attr_nest_start(nfnlct.CTA_TUPLE.IP)
    nlh.attr_put_u32(nfnlct.CTA_IP.V4_SRC, int(ipaddr.IPv4Address("2.2.2.2")))
    nlh.attr_put_u32(nfnlct.CTA_IP.V4_DST, int(ipaddr.IPv4Address("1.1.1.1")))
    nlh.attr_nest_end(nest2)

    nest2 = nlh.attr_nest_start(nfnlct.CTA_TUPLE.PROTO)
    nlh.attr_put_u8(nfnlct.CTA_PROTO.NUM, socket.IPPROTO_TCP)
    nlh.attr_put_u16(nfnlct.CTA_PROTO.SRC_PORT, socket.htons(i))
    nlh.attr_put_u16(nfnlct.CTA_PROTO.DST_PORT, socket.htons(1025))
    nlh.attr_nest_end(nest2)
    nlh.attr_nest_end(nest1)

    # 2.2.2.2:1025 -> 1.1.1.1:i
    nest1 = nlh.attr_nest_start(nfnlct.CTA.TUPLE_REPLY)
    nest2 = nlh.attr_nest_start(nfnlct.CTA_TUPLE.IP)
    nlh.attr_put_u32(nfnlct.CTA_IP.V4_SRC, int(ipaddr.IPv4Address("2.2.2.2")))
    nlh.attr_put_u32(nfnlct.CTA_IP.V4_DST, int(ipaddr.IPv4Address("1.1.1.1")))
    nlh.attr_nest_end(nest2)

    nest2 = nlh.attr_nest_start(nfnlct.CTA_TUPLE.PROTO)
    nlh.attr_put_u8(nfnlct.CTA_PROTO.NUM, socket.IPPROTO_TCP)
    nlh.attr_put_u16(nfnlct.CTA_PROTO.SRC_PORT, socket.htons(1025))
    nlh.attr_put_u16(nfnlct.CTA_PROTO.DST_PORT, socket.htons(i))
    nlh.attr_nest_end(nest2)
    nlh.attr_nest_end(nest1)

    # 
    nest1 = nlh.attr_nest_start(nfnlct.CTA.PROTOINFO)
    nest2 = nlh.attr_nest_start(nfnlct.CTA_PROTOINFO.TCP)
    nlh.attr_put_u8(nfnlct.CTA_PROTOINFO_TCP.STATE, nfcttcp.TCP_CONNTRACK.SYN_SENT)
    nlh.attr_nest_end(nest2)
    nlh.attr_nest_end(nest1)

    #
    nlh.attr_put_u32(nfnlct.CTA.STATUS, socket.htonl(nfctcommon.IPS.CONFIRMED))
    nlh.attr_put_u32(nfnlct.CTA.TIMEOUT, socket.htonl(1000))


def cb_err(nlh, data):
    err = netlink.NLMsgErr(nlh.get_payload())
    if err.error != 0:
        print("message with seq %u has failed: %s" % (nlh.seq, os.strerror(-err.error)))

    return mnl.CB.OK, None

CB_CTL_ARRAY = { netlink.NLMSG.ERROR: cb_err }


def send_batch(nl, b, portid):
    fd = nl.get_fd()
    size = b.size()

    ## try... except
    nl.sendto(b.head().marshal_binary())

    while True:
        rlist, _wlist, _xlist = select.select([fd], [], [], 0.0)
        if not fd in rlist:
            break

        rcv_buf = nl.recvfrom(mnl.SOCKET_BUFFER_SIZE)
        ret, err = mnl.cb_run2(rcv_buf, 0, portid, None, None, CB_CTL_ARRAY)
        if not ret:
            print("mnl_cb_run: %s" % err, file=sys.stderr)
            sys.exit(-1)


def main():
    nl = mnl.Socket()
    nl.open(netlink.NETLINK_PROTO.NETFILTER)
    nl.bind(0, mnl.SOCKET_AUTOPID)
    portid = nl.get_portid()

    # The buffer that we use to batch messages is MNL_SOCKET_BUFFER_SIZE
    # multiplied by 2 bytes long, but we limit the batch to half of it
    # since the last message that does not fit the batch goes over the
    # upper boundary, if you break this rule, expect memory corruptions.
    b = mnl.MessageBatch(mnl.SOCKET_BUFFER_SIZE * 2)

    seq = int(time.time())
    for j, i in enumerate(list(range(1024, 65535))):
        put_msg(b.current(), i, seq + j)
        # is there room for more messages in this batch?
        # if so, continue.
        if b.next_batch():
            continue

        send_batch(nl, b, portid)

        # this moves the last message that did not fit into the
        # batch to the head of it.
        b.reset()

    # check if there is any message in the batch not sent yet.
    if not b.is_empty():
        send_batch(nl, b, portid)

    b.stop()
    nl.close()

    return 0

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
