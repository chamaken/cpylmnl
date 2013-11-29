#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from pylmnl import netlink
import pylmnl.netlink.nfnetlink as nfnl
import pylmnl.netlink.nfnetlink.log as nfnllog
import pylmnl as mnl


log = logging.getLogger(__name__)

def parse_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    rc, err = attr.type_valid(nfnllog.NFULA.MAX)
    if not rc:
        return mnl.CB.OK, None

    # http://stackoverflow.com/questions/60208/replacements-for-switch-statement-in-python
    class switch(object):
        _value = None
        def __new__(klass, v):
            klass._value = v
            return True

    def case(*args):
        return any((arg == switch._value for arg in args))

    while switch(attr_type):
        if case(nfnllog.NFULA.MARK,
                nfnllog.NFULA.IFINDEX_INDEV,
                nfnllog.NFULA.IFINDEX_OUTDEV,
                nfnllog.NFULA.IFINDEX_PHYSINDEV,
                nfnllog.NFULA.IFINDEX_PHYSOUTDEV):
            rc, err = attr.validate(mnl.TYPE.U32)
            if rc < 0:
                print("mnl_attr_validate: %s" % err, file=sys.stderr)
                return mnl.CB.ERROR, err
            break
        if case(nfnllog.NFULA.TIMESTAMP):
            rc, err = attr.validate2(mnl.TYPE.UNSPEC, nfnllog.NFULNLMsgPacketTimestamp.SIZEOF)
            if rc < 0:
                print("mnl_attr_validate: %s" % err, file=sys.stderr)
                return mnl.CB.ERROR, err
            break
        if case(nfnllog.NFULA.HWADDR):
            rc, err = attr.validate2(mnl.TYPE.UNSPEC, nfnllog.NFULNLMsgPacketHw.SIZEOF)
            if rc < 0:
                print("mnl_attr_validate: %s" % err, file=sys.stderr)
                return mnl.CB.ERROR, err
            break
        if case(nfnllog.NFULA.PREFIX):
            rc, err = attr.validate(mnl.TYPE.NUL_STRING)
            if rc < 0:
                print("mnl_attr_validate: %s" % err, file=sys.stderr)
                return mnl.CB.ERROR, err
            break
        if case(nfnllog.NFULA.PAYLOAD):
            break

        # print("not validate nfulnl_attr_type: %s" % nfnllog.NFULA.code[attr_type])
        # DO NOT FORGET
        break

    tb[attr_type] = attr
    return mnl.CB.OK, None


def log_cb(nlh, data):
    tb = dict()

    nlh.attr_parse(nfnl.NFGenMsg.SIZEOF, parse_attr_cb, tb)

    prefix = ""
    mark = 0
    payload_len = 0
    if nfnllog.NFULA.PACKET_HDR in tb:
        ph = nfnllog.NFULNLMsgPacketHdr(tb[nfnllog.NFULA.PACKET_HDR].get_payload())
        del tb[nfnllog.NFULA.PACKET_HDR]
    if nfnllog.NFULA.PREFIX in tb:
        prefix = tb[nfnllog.NFULA.PREFIX].get_str()
        del tb[nfnllog.NFULA.PREFIX]
    if nfnllog.NFULA.MARK in tb:
        mark = socket.ntohl(tb[nfnllog.NFULA.MARK].get_u32())
        del tb[nfnllog.NFULA.MARK]
    if nfnllog.NFULA.PAYLOAD in tb:
        payload_len = nfnl.NFA_PAYLOAD(tb[nfnllog.NFULA.PAYLOAD])
        del tb[nfnllog.NFULA.PAYLOAD]


    print(" ".join([nfnllog.NFULA.code[k] for k in list(tb.keys())]))
    print("log received (prefix=\"%s\" hw=0x%04x hook=%u mark=%u payload_len=%u)" % \
              (prefix, ph.hw_protocol, ph.hook, mark, payload_len))

    return mnl.CB.OK, None


def nflog_build_cfg_pf_request(buflen, command):
    nlh = mnl.Message()
    nlh = nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS.ULOG << 8) | nfnllog.NFULNL_MSG.CONFIG
    nlh.flags = netlink.NLM_F.REQUEST

    nfg = nfnl.NFGenMsg(nlh.put_extra_header(nfnl.NFGenMsg.SIZEOF))
    nfg.family = socket.AF_INET
    nfg.version = nfnl.NFNETLINK_V0

    cmd = nfnllog.NFULNLMsgConfigCmd()
    cmd.command = command
    nlh.attr_put(nfnllog.NFULA_CFG.CMD, cmd)

    return nlh


def nflog_build_cfg_request(buflen, command, qnum):
    nlh = mnl.Message()
    nlh = nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS.ULOG << 8) | nfnllog.NFULNL_MSG.CONFIG
    nlh.flags = netlink.NLM_F.REQUEST

    nfg = nfnl.NFGenMsg(nlh.put_extra_header(nfnl.NFGenMsg.SIZEOF))
    nfg.family = socket.AF_INET
    nfg.version = nfnl.NFNETLINK_V0
    # nfg.res_id = socket.htons(qnum)
    nfg.res_id = qnum

    cmd = nfnllog.NFULNLMsgConfigCmd()
    cmd.command = command
    nlh.attr_put(nfnllog.NFULA_CFG.CMD, cmd)

    return nlh


def nflog_build_cfg_params(buflen, mode, copy_range, qnum):
    nlh = mnl.Message()
    nlh = nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS.ULOG << 8) | nfnllog.NFULNL_MSG.CONFIG
    nlh.flags = netlink.NLM_F.REQUEST

    nfg = nfnl.NFGenMsg(nlh.put_extra_header(nfnl.NFGenMsg.SIZEOF))
    nfg.family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    # nfg.res_id = socket.htons(qnum)
    nfg.res_id = qnum

    params = nfnllog.NFULNLMsgConfigMode()
    params.copy_range = socket.htonl(copy_range)
    params.copy_mode = mode
    nlh.attr_put(nfnllog.NFULA_CFG.MODE, params)

    return nlh


def main():
    if len(sys.argv) != 2:
        print("Usage: %s [queue_num]", sys.argv[0])
        sys.exit(-1)
    qnum = int(sys.argv[1])

    nl = mnl.Socket()
    nl.open(netlink.NETLINK_PROTO.NETFILTER)
    nl.bind(0, mnl.SOCKET_AUTOPID)
    portid = nl.get_portid()

    nlh = nflog_build_cfg_pf_request(mnl.SOCKET_BUFFER_SIZE, nfnllog.NFULNL_CFG_CMD.PF_UNBIND)
    nl.send_nlmsg(nlh)

    nlh = nflog_build_cfg_pf_request(mnl.SOCKET_BUFFER_SIZE, nfnllog.NFULNL_CFG_CMD.PF_BIND)
    nl.send_nlmsg(nlh)

    nlh = nflog_build_cfg_request(mnl.SOCKET_BUFFER_SIZE, nfnllog.NFULNL_CFG_CMD.BIND, qnum)
    nl.send_nlmsg(nlh)

    nlh = nflog_build_cfg_params(mnl.SOCKET_BUFFER_SIZE, nfnllog.NFULNL_COPY.PACKET, 0xFFFF, qnum)
    nl.send_nlmsg(nlh)

    buf = nl.recvfrom(mnl.SOCKET_BUFFER_SIZE)
    # log.warn("received: ")
    # msg = mnl.Message(buf).print(0)
    while len(buf) > 0:
        ret, err = mnl.cb_run(buf, 0, portid, log_cb, None)
        if ret < 0:
            print("mnl_cb_run: %s" % err)
            sys.exit(-1)

        buf = nl.recvfrom(mnl.SOCKET_BUFFER_SIZE)

    nl.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
