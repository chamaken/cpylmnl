#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from pylmnl import netlink
import pylmnl.netlink.nfnetlink as nfnl
import pylmnl.netlink.nfnetlink.conntrack as nfnlct
import pylmnl as mnl


log = logging.getLogger(__name__)


def parse_counters_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA_COUNTERS.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == nfnlct.CTA_COUTERS_PACKETS or attr_type == nfnlct.CTA_COUNTERS.BYTES:
        rc, err = attr.validate(mnl.TYPE.U64)
        if rc < 0:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, err

    tb[attr_type] = attr
    return mnl.CB.OK, None


def print_counters(nest):
    tb = dict()

    nest.parse_nested(parse_counters_cb, tb)
    if nfnlct.CTA_COUNTERS.PACKETS in tb:
        print("packets=%u " % struct.unpack("Q", struct.pack(">Q", tb[nfnlct.CTA_COUNTERS.PACKETS].get_u64())), end='')
    if nfnlct.CTA_COUNTERS.BYTES in tb:
        print("bytes=%u " % struct.unpack("Q", struct.pack(">Q", tb[nfnlct.CTA_COUNTERS.BYTES].get_u64())), end='')


def parse_ip_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA_IP.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == nfnlct.CTA_IP.V4_SRC or attr_type == nfnlct.CTA_IP.V4_DST:
        rc, err = attr.validate(mnl.TYPE.U32)
        if rc < 0:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.CB.ERROR, err
    elif attr_type == nfnlct.CTA_IP.V6_SRC or attr_type == nfnlct.CTA_IP.V6_DST:
        rc, err = attr.validate2(mnl.TYPE.BINARY, 16) # XXX: sizeof(struct in6_addr)
        if rc < 0:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.CB.ERROR, err

    tb[attr_type] = attr
    return mnl.CB.OK, None


def print_ip(nest):
    tb = dict()

    nest.parse_nested(parse_ip_cb, tb)
    if nfnlct.CTA_IP.V4_SRC in tb:
        print("src=%s " % socket.inet_ntoa(tb[nfnlct.CTA_IP.V4_SRC].get_value().marshal_binary()), end='')
    if nfnlct.CTA_IP.V4_DST in tb:
        print("dst=%s " % socket.inet_ntoa(tb[nfnlct.CTA_IP.V4_DST].get_value().marshal_binary()), end='')
    if nfnlct.CTA_IP.V6_SRC in tb:
        print("src=%s " % socket.inet_ntop(socket.AF_INET6, tb[nfnlct.CTA_IP.V6_SRC].get_value().marshal_binary()), end='')
    if nfnlct.CTA_IP.V6_DST in tb:
        print("dst=%s " % socket.inet_ntop(socket.AF_INET6, tb[nfnlct.CTA_IP.V6_DST].get_value().marshal_binary()), end='')


def parse_proto_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA_PROTO.MAX)
    if not rc:
        return mnl.CB.OK, None

    attr_type > nfnlct.CTA_PROTO.MAX and print("too big type? %d" % attr_type)

    if attr_type == nfnlct.CTA_PROTO.NUM \
            or attr_type == nfnlct.CTA_PROTO.ICMP_TYPE \
            or attr_type == nfnlct.CTA_PROTO.ICMP_CODE:
        rc, err = attr.validate(mnl.TYPE.U8)
        if rc < 0:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.CB.ERROR, err
    elif attr_type == nfnlct.CTA_PROTO.SRC_PORT \
            or attr_type == nfnlct.CTA_PROTO.DST_PORT \
            or attr_type == nfnlct.CTA_PROTO.ICMP_ID:
        rc, err = attr.validate(mnl.TYPE.U16)
        if rc < 0:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)

    tb[attr_type] = attr
    return mnl.CB.OK, None


def print_proto(nest):
    tb = dict()

    nest.parse_nested(parse_proto_cb, tb)
    nfnlct.CTA_PROTO.NUM in tb       and print("proto=%u " % tb[nfnlct.CTA_PROTO.NUM].get_u8(), end='')
    if nfnlct.CTA_PROTO.SRC_PORT in tb:
        print("sport=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO.SRC_PORT].get_u16()), end='')
    if nfnlct.CTA_PROTO.DST_PORT in tb:
        print("dport=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO.DST_PORT].get_u16()), end='')
    nfnlct.CTA_PROTO.ICMP_ID in tb   and print("id=%u " % tb[nfnlct.CTA_PROTO.ICMP_ID].get_u16(), end='')
    nfnlct.CTA_PROTO.ICMP_TYPE in tb and print("type=%u " % tb[nfnlct.CTA_PROTO.ICMP_TYPE].get_u8(), end='')
    nfnlct.CTA_PROTO.ICMP_CODE in tb and print("code=%u " % tb[nfnlct.CTA_PROTO.ICMP_CODE].get_u8(), end='')


def parse_tuple_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA_TUPLE.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == nfnlct.CTA_TUPLE.IP:
        rc, err = attr.validate(mnl.TYPE.NESTED)
        if rc < 0:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.CB.ERROR, err
    elif attr_type == nfnlct.CTA_TUPLE.PROTO:
        rc, err = attr.validate(mnl.TYPE.NESTED)
        if rc < 0:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.CB.ERROR, err

    tb[attr_type] = attr
    return mnl.CB.OK, None


def print_tuple(nest):
    tb = dict()

    nest.parse_nested(parse_tuple_cb, tb)
    nfnlct.CTA_TUPLE.IP in tb    and print_ip(tb[nfnlct.CTA_TUPLE.IP])
    nfnlct.CTA_TUPLE.PROTO in tb and print_proto(tb[nfnlct.CTA_TUPLE.PROTO])


def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == nfnlct.CTA.TUPLE_ORIG \
            or attr_type == nfnlct.CTA.COUNTERS_ORIG \
            or attr_type == nfnlct.CTA.COUNTERS_REPLY:
        rc, err = attr.validate(mnl.TYPE.NESTED)
        if rc < 0:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, err
    elif attr_type == nfnlct.CTA.TIMEOUT \
            or attr_type == nfnlct.CTA.MARK \
            or attr_type == nfnlct.CTA.SECMARK:
        rc, err = attr.validate(mnl.TYPE.U32)
        if rc < 0:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, err

    tb[attr_type] = attr
    return mnl.CB.OK, None


def data_cb(nlh, data):
    tb = dict()
    nfg = nfnl.NFGenMsg(nlh.get_payload())

    nlh.attr_parse(nfnl.NFGenMsg.SIZEOF, data_attr_cb, tb)
    nfnlct.CTA.TUPLE_ORIG in tb     and print_tuple(tb[nfnlct.CTA.TUPLE_ORIG])
    nfnlct.CTA.MARK in tb           and print("mark=%u " % socket.ntohl(tb[nfnlct.CTA.MARK].get_u32()), end='')
    nfnlct.CTA.SECMARK in tb        and print("secmark=%u " % socket.ntohl(tb[nfnlct.CTA.SECMARK].get_u32()), end='')
    nfnlct.CTA.COUNTERS_ORIG in tb  and print("original ", end='') and print_counters(tb[nfnlct.CTA.COUNTERS_ORIG])
    nfnlct.CTA.COUNTERS_REPLY in tb and print("reply ", end='') and print_counters(tb[nfnlct.CTA.COUNTERS_REPLY])
    print()

    return mnl.CB.OK, None


def main():
    nl = mnl.RingSocket()
    nl.mmap_prepare(netlink.NETLINK_PROTO.NETFILTER)
    nl.bind(0, mnl.SOCKET_AUTOPID)

    nlh = mnl.Message()
    nlh = nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS.CTNETLINK << 8) | nfnlct.IPCTNL_MSG.CT_GET
    nlh.flags = netlink.NLM_F.REQUEST|netlink.NLM_F.DUMP
    seq = int(time.time())
    nlh.seq = seq

    nfh = nfnl.NFGenMsg(nlh.put_extra_header(nfnl.NFGenMsg.SIZEOF))
    nfh.family = socket.AF_INET
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    nl.send_nlmsg(nlh)
    portid = nl.get_portid()

    for msg in nl.mmap_nlmsgs():
        ret, err = mnl.cb_run(msg.marshal_binary(), seq, portid, data_cb, None)
        if ret == -1:
            print("mnl_cb_run: %s" % err, file=sys.stdout)
            sys.exit(-1)
        elif ret <= mnl.CB.STOP:
            break

    nl.close()
    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
