#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl.nlstructs.nfnetlink as nfnl
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attribute_cb
def parse_counters_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTA_COUNTERS_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTA_COUTERS_PACKETS or attr_type == h.CTA_COUNTERS.BYTES:
        try:
            attr.validate(mnl.MNL_TYPE_U64)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def print_counters(nest):
    tb = dict()

    nest.parse_nested(parse_counters_cb, tb)
    if h.CTA_COUNTERS_PACKETS in tb:
        print("packets=%u " % struct.unpack("Q", struct.pack(">Q", tb[h.CTA_COUNTERS.PACKETS].get_u64())), end='')
    if h.CTA_COUNTERS_BYTES in tb:
        print("bytes=%u " % struct.unpack("Q", struct.pack(">Q", tb[h.CTA_COUNTERS.BYTES].get_u64())), end='')


@mnl.attribute_cb
def parse_ip_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTA_IP_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTA_IP_V4_SRC or h == h.CTA_IP_V4_DST:
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == h.CTA_IP_V6_SRC or attr_type == h.CTA_IP_V6_DST:
        try:
            attr.validate2(mnl.MNL_TYPE_BINARY, 16) # XXX: sizeof(struct in6_addr)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK, None


def print_ip(nest):
    tb = dict()

    nest.parse_nested(parse_ip_cb, tb)
    if h.CTA_IP_V4_SRC in tb:
        print("src=%s " % socket.inet_ntoa(tb[h.CTA_IP_V4_SRC].get_value().marshal_binary()), end='')
    if h.CTA_IP_V4_DST in tb:
        print("dst=%s " % socket.inet_ntoa(tb[h.CTA_IP_V4_DST].get_value().marshal_binary()), end='')
    if h.CTA_IP_V6_SRC in tb:
        print("src=%s " % socket.inet_ntop(socket.AF_INET6, tb[h.CTA_IP_V6_SRC].get_value().marshal_binary()), end='')
    if h.CTA_IP_V6_DST in tb:
        print("dst=%s " % socket.inet_ntop(socket.AF_INET6, tb[h.CTA_IP_V6_DST].get_value().marshal_binary()), end='')


@mnl.attribute_cb
def parse_proto_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTA_PROTO_MAX)
    except OSError as e:
        return mnl.CB_OK

    attr_type > h.CTA_PROTO_MAX and print("too big type? %d" % attr_type)

    if attr_type == h.CTA_PROTO_NUM \
            or attr_type == h.CTA_PROTO_ICMP_TYPE \
            or attr_type == h.CTA_PROTO_ICMP_CODE:
        try:
            attr.validate(mnl.MNL_TYPE_U8)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    elif attr_type == h.CTA_PROTO_SRC_PORT \
            or attr_type == h.CTA_PROTO_DST_PORT \
            or attr_type == h.CTA_PROTO_ICMP_ID:
        try:
            attr.validate(mnl.MNL_TYPE_U16)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def print_proto(nest):
    tb = dict()

    nest.parse_nested(parse_proto_cb, tb)
    h.CTA_PROTO_NUM in tb       and print("proto=%u " % tb[h.CTA_PROTO_NUM].get_u8(), end='')
    h.CTA_PROTO_SRC_PORT in tb	and \
        print("sport=%u " % socket.ntohs(tb[h.CTA_PROTO_SRC_PORT].get_u16()), end='')
    h.CTA_PROTO_DST_PORT in tb	and \
        print("dport=%u " % socket.ntohs(tb[h.CTA_PROTO_DST_PORT].get_u16()), end='')
    h.CTA_PROTO_ICMP_ID in tb   and print("id=%u " % tb[h.CTA_PROTO_ICMP_ID].get_u16(), end='')
    h.CTA_PROTO_ICMP_TYPE in tb and print("type=%u " % tb[h.CTA_PROTO_ICMP_TYPE].get_u8(), end='')
    h.CTA_PROTO_ICMP_CODE in tb and print("code=%u " % tb[h.CTA_PROTO_ICMP_CODE].get_u8(), end='')


@mnl.attribute_cb
def parse_tuple_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTA_TUPLE_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTA_TUPLE_IP:
        try:
            attr.validate(mnl.MNL_TYPE_NESTED)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    elif attr_type == h.CTA_TUPLE_PROTO:
        try:
            attr.validate(mnl.MNL_TYPE_NESTED)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def print_tuple(nest):
    tb = dict()

    nest.parse_nested(parse_tuple_cb, tb)
    h.CTA_TUPLE_IP in tb    and print_ip(tb[h.CTA_TUPLE_IP])
    h.CTA_TUPLE_PROTO in tb and print_proto(tb[h.CTA_TUPLE_PROTO])


@mnl.attribute_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTA_TUPLE_ORIG \
            or attr_type == h.CTA_COUNTERS_ORIG \
            or attr_type == h.CTA_COUNTERS_REPLY:
        try:
            attr.validate(mnl.MNL_TYPE_NESTED)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    elif attr_type == h.CTA_TIMEOUT \
            or attr_type == h.CTA_MARK \
            or attr_type == h.CTA_SECMARK:
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def data_cb(nlh, data):
    tb = dict()
    nfg = nlh.get_payload_as(nfnl.Nfgenmsg)

    nlh.parse(nfnl.Nfgenmsg.sizeof(), data_attr_cb, tb)
    h.CTA_TUPLE_ORIG in tb     and print_tuple(tb[h.CTA_TUPLE_ORIG])
    h.CTA_MARK in tb           and print("mark=%u " % socket.ntohl(tb[h.CTA_MARK].get_u32()), end='')
    h.CTA_SECMARK in tb        and print("secmark=%u " % socket.ntohl(tb[h.CTA_SECMARK].get_u32()), end='')
    h.CTA_COUNTERS_ORIG in tb  and print("original ", end='') and print_counters(tb[h.CTA_COUNTERS_ORIG])
    h.CTA_COUNTERS_REPLY in tb and print("reply ", end='') and print_counters(tb[h.CTA_COUNTERS_REPLY])
    print()

    return mnl.MNL_CB_OK


def main():
    nlh = mnl.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = (h.NFNL_SUBSYS_CTNETLINK << 8) | h.IPCTNL_MSG_CT_GET
    nlh.flags = netlink.NLM_F_REQUEST|netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.seq = seq

    nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg.sizeof(), nfnl.Nfgenmsg)
    nfh.family = socket.AF_INET
    nfh.version = h.NFNETLINK_V0
    nfh.res_id = 0

    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        nl.send_nlmsg(nlh)
        portid = nl.get_portid()

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            ret = mnl.cb_run(buf, seq, portid, data_cb, None)

    if ret < 0: # not valid. cb_run may raise Exception
        print("mnl_cb_run", file=sys.stderr)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
