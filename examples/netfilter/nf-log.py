#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_logh as nfulnl
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attr_cb
def parse_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(nfulnl.NFULA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type in (nfulnl.NFULA_MARK,
                     nfulnl.NFULA_IFINDEX_INDEV,
                     nfulnl.NFULA_IFINDEX_OUTDEV,
                     nfulnl.NFULA_IFINDEX_PHYSINDEV,
                     nfulnl.NFULA_IFINDEX_PHYSOUTDEV):
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == nfulnl.NFULA_TIMESTAMP:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfulnl.NfulnlMsgPacketTimestamp.csize())
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == nfulnl.NFULA_HWADDR:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfulnl.NfulnlMsgPacketHw.csize())
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == nfulnl.NFULA_PREFIX:
        try:
            attr.validate(mnl.MNL_TYPE_NUL_STRING)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == nfulnl.NFULA_PAYLOAD:
        pass

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.nlmsg_cb
def log_cb(nlh, data):
    tb = dict()
    prefix = ""
    mark = 0
    payload_len = 0

    nlh.parse(nfnl.Nfgenmsg.csize(), parse_attr_cb, tb)
    if nfulnl.NFULA_PACKET_HDR in tb:
        ph = tb[nfulnl.NFULA_PACKET_HDR].get_payload_as(nfulnl.NfulnlMsgPacketHdr)
    if nfulnl.NFULA_PREFIX in tb:
        prefix = tb[nfulnl.NFULA_PREFIX].get_str()
    if nfulnl.NFULA_MARK in tb:
        mark = socket.ntohl(tb[nfulnl.NFULA_MARK].get_u32())

    # not exist in original
    if nfulnl.NFULA_PAYLOAD in tb:
        payload_len = tb[nfulnl.NFULA_PAYLOAD].get_payload_len()

    print("log received (prefix=\"%s\" hw=0x%04x hook=%u mark=%u payload_len=%u)" % \
              (prefix, socket.ntohs(ph.hw_protocol), ph.hook, mark, payload_len))

    return mnl.MNL_CB_OK


def nflog_build_cfg_pf_request(buf, command):
    nlh = mnl.Nlmsg(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_ULOG << 8) | nfulnl.NFULNL_MSG_CONFIG
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_INET
    nfg.version = nfnl.NFNETLINK_V0

    cmd = nfulnl.NfulnlMsgConfigCmd()
    cmd.command = command
    nlh.put(nfulnl.NFULA_CFG_CMD, cmd)

    return nlh


def nflog_build_cfg_request(buf, command, qnum):
    nlh = mnl.Nlmsg(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_ULOG << 8) | nfulnl.NFULNL_MSG_CONFIG
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_INET
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(qnum)

    cmd = nfulnl.NfulnlMsgConfigCmd()
    cmd.command = command
    nlh.put(nfulnl.NFULA_CFG_CMD, cmd)

    return nlh


def nflog_build_cfg_params(buf, mode, copy_range, qnum):
    nlh = mnl.Nlmsg(buf)
    nlh.put_header()
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_ULOG << 8) | nfulnl.NFULNL_MSG_CONFIG
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.nfgen_family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(qnum)

    params = nfulnl.NfulnlMsgConfigMode()
    params.copy_range = socket.htonl(copy_range)
    params.copy_mode = mode
    nlh.put(nfulnl.NFULA_CFG_MODE, params)

    return nlh


def main():
    if len(sys.argv) != 2:
        print("Usage: %s [queue_num]" % sys.argv[0])
        sys.exit(-1)
    qnum = int(sys.argv[1])
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)

    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        nlh = nflog_build_cfg_pf_request(buf, nfulnl.NFULNL_CFG_CMD_PF_UNBIND)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_pf_request(buf, nfulnl.NFULNL_CFG_CMD_PF_BIND)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_request(buf, nfulnl.NFULNL_CFG_CMD_BIND, qnum)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_params(buf, nfulnl.NFULNL_COPY_PACKET, 0xFFFF, qnum)
        nl.send_nlmsg(nlh)

        ret = mnl.MNL_CB_OK
        while ret >= mnl.MNL_CB_STOP:
            try:
                nrecv = nl.recv_into(buf)
                if nrecv == 0: break
                ret = mnl.cb_run(buf[:nrecv], 0, portid, log_cb, None)
            except Exception as e:
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
