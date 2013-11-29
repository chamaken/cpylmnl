#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from pylmnl import netlink
import pylmnl.netlink.nfnetlink as nfnl
import pylmnl.netlink.nfnetlink.conntrack as nfnlct
import pylmnl as mnl


log = logging.getLogger(__name__)


def parse_ip_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA_IP.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == nfnlct.CTA_IP.V4_SRC or attr_type == nfnlct.CTA_IP.V4_DST:
        rc, err = attr.validate(mnl.TYPE.U32)
        if rc < 0:
            print("mnl_attr_validate: %s" % err)
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


def parse_proto_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA_PROTO.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == nfnlct.CTA_PROTO.NUM \
            or attr_type == nfnlct.CTA_PROTO.ICMP_TYPE \
            or attr_type == nfnlct.CTA_PROTO.ICMP_CODE:
        rc, err = attr.validate(mnl.TYPE.U8)
        if not rc:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, err
    if attr_type == nfnlct.CTA_PROTO.SRC_PORT \
            or attr_type == nfnlct.CTA_PROTO.DST_PORT \
            or attr_type == nfnlct.CTA_PROTO.ICMP_ID:
        rc, err = attr.validate(mnl.TYPE.U16)
        if not rc:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, err

    tb[attr_type] = attr
    return mnl.CB.OK, None


def print_proto(nest):
    tb = dict()

    nest.parse_nested(parse_proto_cb, tb)
    if nfnlct.CTA_PROTO.NUM in tb:       print("proto=%u " % tb[nfnlct.CTA_PROTO.NUM].get_u8(), end='')
    if nfnlct.CTA_PROTO.SRC_PORT in tb:
        print("sport=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO.SRC_PORT].get_u16()), end='')
    if nfnlct.CTA_PROTO.DST_PORT in tb:
        print("dport=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO.DST_PORT].get_u16()), end='')
    if nfnlct.CTA_PROTO.ICMP_ID in tb:
        print("id=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO.ICMP_ID].get_u16()), end='')
    if nfnlct.CTA_PROTO.ICMP_TYPE in tb: print("type=%u " % tb[nfnlct.CTA_PROTO.ICMP_TYPE].get_u8(), end='')
    if nfnlct.CTA_PROTO.ICMP_CODE in tb: print("code=%u " % tb[nfnlct.CTA_PROTO.ICMP_CODE].get_u8(), end='')


def parse_tuple_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA_TUPLE.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == nfnlct.CTA_TUPLE.IP:
        rc, err = attr.validate(mnl.TYPE.NESTED)
        if not rc:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.CB.ERROR, err
    elif attr_type == nfnlct.CTA_TUPLE.PROTO:
        rc, err = attr.validate(mnl.TYPE.NESTED)
        if not rc:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.CB.ERROR, err

    tb[attr_type] = attr
    return mnl.CB.OK, None


def print_tuple(nest):
    tb = dict()

    nest.parse_nested(parse_tuple_cb, tb)
    if nfnlct.CTA_TUPLE.IP in tb:    print_ip(tb[nfnlct.CTA_TUPLE.IP])
    if nfnlct.CTA_TUPLE.PROTO in tb: print_proto(tb[nfnlct.CTA_TUPLE.PROTO])


def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(nfnlct.CTA.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == nfnlct.CTA.TUPLE_ORIG:
        rc, err = attr.validate(mnl.TYPE.NESTED)
        if not rc:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.CB.ERROR, err
    elif attr_type == nfnlct.CTA.TIMEOUT \
            or attr_type == nfnlct.CTA.MARK \
            or attr_type == nfnlct.CTA.SECMARK:
        rc, err = attr.validate(mnl.TYPE.U32)
        if not rc:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, err

    tb[attr_type] = attr
    return mnl.CB.OK, None


def data_cb(nlh, tb):
    tb = dict()
    nfg = nfnl.NFGenMsg(nlh.get_payload())

    if nlh.type & 0xff == nfnlct.IPCTNL_MSG.CT_NEW:
        if nlh.flags & (netlink.NLM_F.CREATE|netlink.NLM_F.EXCL):
            print("%9s " % "[NEW] ", end='')
        else:
            print("%9s " % "[UPDATE] ", end='')
    elif nlh.type & 0xff == nfnlct.IPCTNL_MSG.CT_DELETE:
        print("%9s " % "[DESTROY] ", end='')

    nlh.attr_parse(nfnl.NFGenMsg.SIZEOF, data_attr_cb, tb)
    if nfnlct.CTA.TUPLE_ORIG in tb: print_tuple(tb[nfnlct.CTA.TUPLE_ORIG])
    if nfnlct.CTA.MARK in tb:       print("mark=%u " % socket.ntohl(tb[CTA.MARK].get_u32()), end='')
    if nfnlct.CTA.SECMARK in tb:    print("secmark=%u " % socket.ntohl(tb[CTA.SECMARK].get_u32()), end='')
    print()

    return mnl.CB.OK, None


def main():
    nl = mnl.Socket()
    nl.open(netlink.NETLINK_PROTO.NETFILTER)
    nl.bind(nfnl.NF_NETLINK_CONNTRACK.NEW | \
                nfnl.NF_NETLINK_CONNTRACK.UPDATE | \
                nfnl.NF_NETLINK_CONNTRACK.DESTROY,
            mnl.SOCKET_AUTOPID)

    while True:
        buf = nl.recvfrom(mnl.SOCKET_BUFFER_SIZE)
        ret, err = mnl.cb_run(buf, 0, 0, data_cb, None)
        if ret == -1:
            print("mnl_cb_run: %s" % err)
            sys.exit(-1)

    nl.close()

    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
