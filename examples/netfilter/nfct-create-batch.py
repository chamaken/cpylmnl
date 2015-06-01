#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, logging, socket, time, select
import ipaddr

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl.linux.netfilter.nf_conntrack_tcph as nfcttcp
import cpylmnl.linux.netfilter.nf_conntrack_commonh as nfctcm
import cpylmnl as mnl


log = logging.getLogger(__name__)


def put_msg(buf, i, seq):
    nlh = mnl.Nlmsg(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_NEW
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST | netlink.NLM_F_CREATE | netlink.NLM_F_EXCL | netlink.NLM_F_ACK
    nlh.nlmsg_seq = seq

    nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfh.nfgen_family = socket.AF_INET
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    # 1.1.1.1:i -> 2.2.2.2:1025
    nest1 = nlh.nest_start(nfnlct.CTA_TUPLE_ORIG)
    nest2 = nlh.nest_start(nfnlct.CTA_TUPLE_IP)
    nlh.put_u32(nfnlct.CTA_IP_V4_SRC, int(ipaddr.IPv4Address("1.1.1.1")))
    nlh.put_u32(nfnlct.CTA_IP_V4_DST, int(ipaddr.IPv4Address("2.2.2.2")))
    nlh.nest_end(nest2)
    nest2 = nlh.nest_start(nfnlct.CTA_TUPLE_PROTO)
    nlh.put_u8(nfnlct.CTA_PROTO_NUM, socket.IPPROTO_TCP)
    nlh.put_u16(nfnlct.CTA_PROTO_SRC_PORT, socket.htons(i))
    nlh.put_u16(nfnlct.CTA_PROTO_DST_PORT, socket.htons(1025))
    nlh.nest_end(nest2)
    nlh.nest_end(nest1)

    # 2.2.2.2:1025 -> 1.1.1.1:i
    nest1 = nlh.nest_start(nfnlct.CTA_TUPLE_REPLY)
    nest2 = nlh.nest_start(nfnlct.CTA_TUPLE_IP)
    nlh.put_u32(nfnlct.CTA_IP_V4_SRC, int(ipaddr.IPv4Address("2.2.2.2")))
    nlh.put_u32(nfnlct.CTA_IP_V4_DST, int(ipaddr.IPv4Address("1.1.1.1")))
    nlh.nest_end(nest2)
    nest2 = nlh.nest_start(nfnlct.CTA_TUPLE_PROTO)
    nlh.put_u8(nfnlct.CTA_PROTO_NUM, socket.IPPROTO_TCP)
    nlh.put_u16(nfnlct.CTA_PROTO_SRC_PORT, socket.htons(1025))
    nlh.put_u16(nfnlct.CTA_PROTO_DST_PORT, socket.htons(i))
    nlh.nest_end(nest2)
    nlh.nest_end(nest1)

    # TCP SYN
    nest1 = nlh.nest_start(nfnlct.CTA_PROTOINFO)
    nest2 = nlh.nest_start(nfnlct.CTA_PROTOINFO_TCP)
    nlh.put_u8(nfnlct.CTA_PROTOINFO_TCP_STATE, nfcttcp.TCP_CONNTRACK_SYN_SENT)
    nlh.nest_end(nest2)
    nlh.nest_end(nest1)

    # status and timeout
    nlh.put_u32(nfnlct.CTA_STATUS, socket.htonl(nfctcm.IPS_CONFIRMED))
    nlh.put_u32(nfnlct.CTA_TIMEOUT, socket.htonl(1000))


@mnl.nlmsg_cb
def cb_err(nlh, data):
    err = nlh.get_payload_as(netlink.Nlmsgerr)
    if err.error != 0:
        print("message with seq %u has failed: %s" % (nlh.nlmsg_seq, os.strerror(-err.error)), file=sys.stderr)

    return mnl.MNL_CB_OK


CB_CTL_ARRAY = {netlink.NLMSG_ERROR: cb_err}

def send_batch(nl, b, portid):
    fd = nl.get_fd()
    size = b.size()

    try:
        nl.sendto(b.head())
    except Exception as e:
        print("mnl_socket_sendto: %s" % e, file=sys.stderr)
        raise

    while True:
        rlist, _wlist, _xlist = select.select([fd], [], [], 0.0)
        if not fd in rlist:
            break

        try:
            rcv_buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            if len(rcv_buf) == 0: break
        except Exception as e:
            print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
            raise

        try:
            mnl.cb_run2(rcv_buf, 0, portid, None, None, CB_CTL_ARRAY)
        except Exception as e:
            print("mnl_cb_run2: %s" % e, file=sys.stderr)
            raise


def main():
    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        with mnl.NlmsgBatch(mnl.MNL_SOCKET_BUFFER_SIZE * 2, mnl.MNL_SOCKET_BUFFER_SIZE) as b:
            seq = int(time.time())
            for j, i in enumerate(list(range(1024, 65535))):
                put_msg(b.current_v(), i, seq + j)
                if b.next_batch():
                    continue

                send_batch(nl, b, portid)
                b.reset()

            if not b.is_empty():
                send_batch(nl, b, portid)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
