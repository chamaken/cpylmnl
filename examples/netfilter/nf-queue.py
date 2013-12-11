#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl.nlstructs.nfnetlink as nfnl
import cpylmnl.nlstructs.nfnetlink_queue as nfqnl
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attribute_cb
def parse_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(h.NFQA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type in (h.NFQA_MARK, h.NFQA_IFINDEX_INDEV, h.NFQA_IFINDEX_OUTDEV,
                     h.NFQA_IFINDEX_PHYSINDEV, h.NFQA_IFINDEX_PHYSOUTDEV):
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == h.NFQA_TIMESTAMP:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfqnl.NfqnlMsgPacketTimestamp.sizeof())
        except OSError as e:
            print("mnl_attr_validate2: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == h.NFQA_HWADDR:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfqnl.NfqnlMsgPacketHw.sizeof())
        except OSError as e:
            print("mnl_attr_validate2: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == h.NFQA_PAYLOAD:
        pass

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def queue_cb(nlh, tb):
    tb = dict()
    packet_id = 0
    nlh.parse(nfnl.Nfgenmsg.sizeof(), parse_attr_cb, tb)
    if h.NFQA_PACKET_HDR in tb:
        ph = tb[h.NFQA_PACKET_HDR].get_payload_as(nfqnl.NfqnlMsgPacketHdr)
        packet_id = socket.ntohl(ph.packet_id)
        print("packet received (id=%u hw=0x%04x hook=%u)" \
                  % (packet_id, socket.ntohs(ph.hw_protocol), ph.hook))

    return mnl.MNL_CB_OK + packet_id


def nfq_build_cfg_pf_request(buf, command):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (h.NFNL_SUBSYS_QUEUE << 8) | h.NFQNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.family = socket.AF_UNSPEC
    nfg.version = h.NFNETLINK_V0

    cmd = nfqnl.NfqnlMsgConfigCmd()
    cmd.command = command
    cmd.pf = socket.htons(socket.AF_INET)
    nlh.put(h.NFQA_CFG_CMD, cmd)

    return nlh


def nfq_build_cfg_request(buf, command, queue_num):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (h.NFNL_SUBSYS_QUEUE << 8) | h.NFQNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.family = socket.AF_UNSPEC
    nfg.version = h.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    cmd = nfqnl.NfqnlMsgConfigCmd()
    cmd.command = command
    cmd.pf = socket.htons(socket.AF_INET)
    nlh.put(h.NFQA_CFG_CMD, cmd)

    return nlh


def nfq_build_cfg_params(buf, copy_mode, copy_range, queue_num):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (h.NFNL_SUBSYS_QUEUE << 8) | h.NFQNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.family = socket.AF_UNSPEC
    nfg.version = h.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    params = nfqnl.NfqnlMsgConfigParams()
    params.copy_range = socket.htonl(copy_range)
    params.copy_mode = copy_mode
    nlh.put(h.NFQA_CFG_PARAMS, params)

    return nlh


def nfq_build_verdict(buf, packet_id, queue_num, verd):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (h.NFNL_SUBSYS_QUEUE << 8) | h.NFQNL_MSG_VERDICT
    nlh.flags = netlink.NLM_F_REQUEST
    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.family = socket.AF_UNSPEC
    nfg.version = h.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    vh = nfqnl.NfqnlMsgVerdictHdr()
    vh.verdict = socket.htonl(verd)
    vh.id = socket.htonl(packet_id)
    nlh.put(h.NFQA_VERDICT_HDR, vh)

    return nlh


def main():
    if len(sys.argv) != 2:
        print("Usage: %s [queue_num]" % sys.argv[0])
        sys.exit(-1)

    queue_num = int(sys.argv[1])

    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)

        nlh = nfq_build_cfg_pf_request(buf, h.NFQNL_CFG_CMD_PF_UNBIND)
        nl.send_nlmsg(nlh)

        nlh = nfq_build_cfg_pf_request(buf, h.NFQNL_CFG_CMD_PF_BIND)
        nl.send_nlmsg(nlh)

        nlh = nfq_build_cfg_request(buf, h.NFQNL_CFG_CMD_BIND, queue_num)
        nl.send_nlmsg(nlh)

        nlh = nfq_build_cfg_params(buf, h.NFQNL_COPY_PACKET, 0xFFFF, queue_num)
        nl.send_nlmsg(nlh)

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            nrecv = nl.recv_into(buf)
            ret = mnl.cb_run(buf[:nrecv], 0, portid, queue_cb, None)

            packet_id = ret - mnl.MNL_CB_OK
            nlh = nfq_build_verdict(buf, packet_id, queue_num, h.NF_ACCEPT)
            nl.send_nlmsg(nlh)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
