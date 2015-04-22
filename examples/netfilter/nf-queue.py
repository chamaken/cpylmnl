#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_queueh as nfqnl
import cpylmnl.linux.netfilterh as nf
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attr_cb
def parse_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(nfqnl.NFQA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type in (nfqnl.NFQA_MARK,
                     nfqnl.NFQA_IFINDEX_INDEV,
                     nfqnl.NFQA_IFINDEX_OUTDEV,
                     nfqnl.NFQA_IFINDEX_PHYSINDEV,
                     nfqnl.NFQA_IFINDEX_PHYSOUTDEV):
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == nfqnl.NFQA_TIMESTAMP:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfqnl.NfqnlMsgPacketTimestamp.csize())
        except OSError as e:
            print("mnl_attr_validate2: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == nfqnl.NFQA_HWADDR:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfqnl.NfqnlMsgPacketHw.csize())
        except OSError as e:
            print("mnl_attr_validate2: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == nfqnl.NFQA_PAYLOAD:
        pass

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.msghdr_cb
def queue_cb(nlh, tb):
    tb = dict()
    packet_id = 0

    nlh.parse(nfnl.Nfgenmsg.csize(), parse_attr_cb, tb)
    if nfqnl.NFQA_PACKET_HDR in tb:
        ph = tb[nfqnl.NFQA_PACKET_HDR].get_payload_as(nfqnl.NfqnlMsgPacketHdr)
        packet_id = socket.ntohl(ph.packet_id)
        print("packet received (id=%u hw=0x%04x hook=%u)" \
                  % (packet_id, socket.ntohs(ph.hw_protocol), ph.hook))

    return mnl.MNL_CB_OK + packet_id


def nfq_build_cfg_pf_request(buf, command):
    nlh = mnl.Msghdr(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_QUEUE << 8) | nfqnl.NFQNL_MSG_CONFIG
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0

    cmd = nfqnl.NfqnlMsgConfigCmd()
    cmd.command = command
    cmd.pf = socket.htons(socket.AF_INET)
    nlh.put(nfqnl.NFQA_CFG_CMD, cmd)

    return nlh


def nfq_build_cfg_request(buf, command, queue_num):
    nlh = mnl.Msghdr(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_QUEUE << 8) | nfqnl.NFQNL_MSG_CONFIG
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    cmd = nfqnl.NfqnlMsgConfigCmd()
    cmd.command = command
    cmd.pf = socket.htons(socket.AF_INET)
    nlh.put(nfqnl.NFQA_CFG_CMD, cmd)

    return nlh


def nfq_build_cfg_params(buf, copy_mode, copy_range, queue_num):
    nlh = mnl.Msghdr(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_QUEUE << 8) | nfqnl.NFQNL_MSG_CONFIG
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    params = nfqnl.NfqnlMsgConfigParams()
    params.copy_range = socket.htonl(copy_range)
    params.copy_mode = copy_mode
    nlh.put(nfqnl.NFQA_CFG_PARAMS, params)

    return nlh


def nfq_build_verdict(buf, packet_id, queue_num, verd):
    nlh = mnl.Msghdr(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_QUEUE << 8) | nfqnl.NFQNL_MSG_VERDICT
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST
    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(queue_num)

    vh = nfqnl.NfqnlMsgVerdictHdr()
    vh.verdict = socket.htonl(verd)
    vh.id = socket.htonl(packet_id)
    nlh.put(nfqnl.NFQA_VERDICT_HDR, vh)

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

        nlh = nfq_build_cfg_pf_request(buf, nfqnl.NFQNL_CFG_CMD_PF_UNBIND)
        nl.send_nlmsg(nlh)

        nlh = nfq_build_cfg_pf_request(buf, nfqnl.NFQNL_CFG_CMD_PF_BIND)
        nl.send_nlmsg(nlh)

        nlh = nfq_build_cfg_request(buf, nfqnl.NFQNL_CFG_CMD_BIND, queue_num)
        nl.send_nlmsg(nlh)

        nlh = nfq_build_cfg_params(buf, nfqnl.NFQNL_COPY_PACKET, 0xFFFF, queue_num)
        nl.send_nlmsg(nlh)

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            try:
                nrecv = nl.recv_into(buf)
                if nrecv == 0: break
            except Exception as e:
                print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
                raise

            try:
                ret = mnl.cb_run(buf[:nrecv], 0, portid, queue_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise

            packet_id = ret - mnl.MNL_CB_OK
            nlh = nfq_build_verdict(buf, packet_id, queue_num, nf.NF_ACCEPT)
            try:
                nl.send_nlmsg(nlh)
            except Exception as e:
                print("mnl_socket_sendto: %s" % e, file=sys.stderr)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
