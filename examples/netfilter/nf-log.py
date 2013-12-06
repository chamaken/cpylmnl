#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl.nlstructs.nfnetlink as nfnl
import cpylmnl.nlstructs.nfnetlink_log as nfulnl
import cpylmnl.nlstructs.nfnetlink_compat as nfnl_compat
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attribute_cb
def parse_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(h.NFULA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK, None

    # http://stackoverflow.com/questions/60208/replacements-for-switch-statement-in-python
    class switch(object):
        _value = None
        def __new__(klass, v):
            klass._value = v
            return True

    def case(*args):
        return any((arg == switch._value for arg in args))

    while switch(attr_type):
        if case(h.NFULA_MARK,
                h.NFULA_IFINDEX_INDEV,
                h.NFULA_IFINDEX_OUTDEV,
                h.NFULA_IFINDEX_PHYSINDEV,
                h.NFULA_IFINDEX_PHYSOUTDEV):
            try:
                attr.validate(mnl.MNL_TYPE_U32)
            except OSError as e:
                print("mnl_attr_validate: %s" % e, file=sys.stderr)
                return mnl.MNL_CB_ERROR
            break
        if case(h.NFULA_TIMESTAMP):
            try:
                attr.validate2(mnl.MNL_TYPE_UNSPEC, nfulnl.NfulnlMsgPacketTimestamp.sizeof())
            except OSError as e:
                print("mnl_attr_validate: %s" % e, file=sys.stderr)
                return mnl.MNL_CB_ERROR
            break
        if case(h.NFULA_HWADDR):
            try:
                attr.validate2(mnl.MNL_TYPE_UNSPEC, nfulnl.NfulnlMsgPacketHw.sizeof())
            except OSError as e:
                print("mnl_attr_validate: %s" % e, file=sys.stderr)
                return mnl.MNL_CB_ERROR
            break
        if case(h.NFULA_PREFIX):
            try:
                attr.validate(mnl.MNL_TYPE_NUL_STRING)
            except OSError as e:
                print("mnl_attr_validate: %s" % e, file=sys.stderr)
                return mnl.MNL_CB_ERROR
            break
        if case(h.NFULA_PAYLOAD):
            break

        # DO NOT FORGET
        break

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def log_cb(nlh, data):
    tb = dict()
    prefix = ""
    mark = 0
    payload_len = 0

    nlh.attr_parse(nfnl.Nfgenmsg.sizeof(), parse_attr_cb, tb)
    if h.NFULA_PACKET_HDR in tb:
        ph = tb[h.NFULA_PACKET_HDR].get_payload_as(nfulnl.NfulnlMsgPacketHdr)
    if h.NFULA_PREFIX in tb:
        prefix = tb[h.NFULA_PREFIX].get_str()
    if h.NFULA_MARK in tb:
        mark = socket.ntohl(tb[h.NFULA_MARK].get_u32())

    # not exist in original
    if h.NFULA_PAYLOAD in tb:
        payload_len = nfnl_compat.NFA_PAYLOAD(tb[h.NFULA_PAYLOAD])

    print("log received (prefix=\"%s\" hw=0x%04x hook=%u mark=%u payload_len=%u)" % \
              (prefix, socket.ntohs(ph.hw_protocol), ph.hook, mark, payload_len))

    return mnl.MNL_CB_OK


def nflog_build_cfg_pf_request(buflen, command):
    nlh = mnl.put_new_header(buflen)
    nlh.type = (h.NFNL_SUBSYS_ULOG << 8) | h.NFULNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg.sizeof(), nfnl.Nfgenmsg)
    nfg.family = socket.AF_INET
    nfg.version = h.NFNETLINK_V0

    cmd = nfulnl.NfulnlMsgConfigCmd()
    cmd.command = command
    nlh.put(h.NFULA_CFG_CMD, cmd)

    return nlh


def nflog_build_cfg_request(buflen, command, qnum):
    nlh = mnl.put_new_header(buflen)
    nlh.type = (h.NFNL_SUBSYS_ULOG << 8) | h.NFULNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg.sizeof(), nfnl.Nfgenmsg)
    nfg.family = socket.AF_INET
    nfg.version = h.NFNETLINK_V0
    nfg.res_id = socket.htons(qnum)

    cmd = nfulnl.NfulnlMsgConfigCmd()
    cmd.command = command
    nlh.put(h.NFULA_CFG_CMD, cmd)

    return nlh


def nflog_build_cfg_params(buflen, mode, copy_range, qnum):
    nlh = mnl.put_new_header(buflen)
    nlh.type = (h.NFNL_SUBSYS_ULOG << 8) | h.NFULNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg.sizeof(), nfnl.Nfgenmsg)
    nfg.family = socket.AF_UNSPEC
    nfg.version = h.NFNETLINK_V0
    nfg.res_id = socket.htons(qnum)

    params = nfulnl.NfulnlMsgConfigMode()
    params.copy_range = socket.htonl(copy_range)
    params.copy_mode = mode
    nlh.put(h.NFULA_CFG_MODE, params)

    return nlh


def main():
    if len(sys.argv) != 2:
        print("Usage: %s [queue_num]", sys.argv[0])
        sys.exit(-1)
    qnum = int(sys.argv[1])

    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        nlh = nflog_build_cfg_pf_request(mnl.MNL_SOCKET_BUFFER_SIZE, h.NFULNL_CFG_CMD_PF_UNBIND)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_pf_request(mnl.MNL_SOCKET_BUFFER_SIZE, h.NFULNL_CFG_CMD_PF_BIND)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_request(mnl.MNL_SOCKET_BUFFER_SIZE, h.NFULNL_CFG_CMD_BIND, qnum)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_params(mnl.MNL_SOCKET_BUFFER_SIZE, h.NFULNL_COPY_PACKET, 0xFFFF, qnum)
        nl.send_nlmsg(nlh)

        ret = mnl.MNL_CB_OK
        while ret >= mnl.MNL_CB_STOP:
            buf = nl.recvfrom(mnl.MNL_SOCKET_BUFFER_SIZE)
            ret = mnl.cb_run(buf, 0, portid, log_cb, None)

    if ret < 0: # not valid. cb_run may raise Exception
        print("mnl_cb_run", file=sys.stderr)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
