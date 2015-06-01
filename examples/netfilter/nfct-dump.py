#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time, struct

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attr_cb
def parse_counters_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_COUNTERS_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type in (nfnlct.CTA_COUNTERS_PACKETS, nfnlct.CTA_COUNTERS_BYTES):
        try:
            attr.validate(mnl.MNL_TYPE_U64)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def print_counters(prefix, nest):
    tb = dict()
    nest.parse_nested(parse_counters_cb, tb)
    print("%s " % prefix, end='')
    if nfnlct.CTA_COUNTERS_PACKETS in tb:
        print("packets=%u " % struct.unpack("Q", struct.pack(">Q", tb[nfnlct.CTA_COUNTERS_PACKETS].get_u64())), end='')
    if nfnlct.CTA_COUNTERS_BYTES in tb:
        print("bytes=%u " % struct.unpack("Q", struct.pack(">Q", tb[nfnlct.CTA_COUNTERS_BYTES].get_u64())), end='')


@mnl.attr_cb
def parse_ip_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_IP_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type in (nfnlct.CTA_IP_V4_SRC,
                     nfnlct.CTA_IP_V4_DST):
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type in (nfnlct.CTA_IP_V6_SRC,
                       nfnlct.CTA_IP_V6_DST):
        try:
            attr.validate2(mnl.MNL_TYPE_BINARY, 16) # XXX: sizeof(struct in6_addr)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def print_ip(nest):
    tb = dict()

    nest.parse_nested(parse_ip_cb, tb)
    if nfnlct.CTA_IP_V4_SRC in tb:
        print("src=%s " % socket.inet_ntoa(tb[nfnlct.CTA_IP_V4_SRC].get_payload_v()), end='')
    if nfnlct.CTA_IP_V4_DST in tb:
        print("dst=%s " % socket.inet_ntoa(tb[nfnlct.CTA_IP_V4_DST].get_payload_v()), end='')
    if nfnlct.CTA_IP_V6_SRC in tb:
        print("src=%s " % socket.inet_ntop(socket.AF_INET6, tb[nfnlct.CTA_IP_V6_SRC].get_payload_v()), end='')
    if nfnlct.CTA_IP_V6_DST in tb:
        print("dst=%s " % socket.inet_ntop(socket.AF_INET6, tb[nfnlct.CTA_IP_V6_DST].get_payload_v()), end='')


@mnl.attr_cb
def parse_proto_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_PROTO_MAX)
    except OSError as e:
        return mnl.CB_OK

    if attr_type in (nfnlct.CTA_PROTO_NUM,
                     nfnlct.CTA_PROTO_ICMP_TYPE,
                     nfnlct.CTA_PROTO_ICMP_CODE):
        try:
            attr.validate(mnl.MNL_TYPE_U8)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    elif attr_type in (nfnlct.CTA_PROTO_SRC_PORT,
                       nfnlct.CTA_PROTO_DST_PORT,
                       nfnlct.CTA_PROTO_ICMP_ID):
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
    nfnlct.CTA_PROTO_NUM in tb       and print("proto=%u " % tb[nfnlct.CTA_PROTO_NUM].get_u8(), end='')
    nfnlct.CTA_PROTO_SRC_PORT in tb  and \
        print("sport=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO_SRC_PORT].get_u16()), end='')
    nfnlct.CTA_PROTO_DST_PORT in tb  and \
        print("dport=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO_DST_PORT].get_u16()), end='')
    nfnlct.CTA_PROTO_ICMP_ID in tb   and print("id=%u " % tb[nfnlct.CTA_PROTO_ICMP_ID].get_u16(), end='')
    nfnlct.CTA_PROTO_ICMP_TYPE in tb and print("type=%u " % tb[nfnlct.CTA_PROTO_ICMP_TYPE].get_u8(), end='')
    nfnlct.CTA_PROTO_ICMP_CODE in tb and print("code=%u " % tb[nfnlct.CTA_PROTO_ICMP_CODE].get_u8(), end='')


@mnl.attr_cb
def parse_tuple_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_TUPLE_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == nfnlct.CTA_TUPLE_IP:
        try:
            attr.validate(mnl.MNL_TYPE_NESTED)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    elif attr_type == nfnlct.CTA_TUPLE_PROTO:
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
    nfnlct.CTA_TUPLE_IP in tb    and print_ip(tb[nfnlct.CTA_TUPLE_IP])
    nfnlct.CTA_TUPLE_PROTO in tb and print_proto(tb[nfnlct.CTA_TUPLE_PROTO])


@mnl.attr_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type in (nfnlct.CTA_TUPLE_ORIG,
                     nfnlct.CTA_COUNTERS_ORIG,
                     nfnlct.CTA_COUNTERS_REPLY):
        try:
            attr.validate(mnl.MNL_TYPE_NESTED)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    elif attr_type in (nfnlct.CTA_TIMEOUT,
                       nfnlct.CTA_MARK,
                       nfnlct.CTA_SECMARK):
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.nlmsg_cb
def data_cb(nlh, data):
    tb = dict()
    nfg = nlh.get_payload_as(nfnl.Nfgenmsg)

    nlh.parse(nfnl.Nfgenmsg.csize(), data_attr_cb, tb)
    nfnlct.CTA_TUPLE_ORIG in tb     and print_tuple(tb[nfnlct.CTA_TUPLE_ORIG])
    nfnlct.CTA_MARK in tb           and print("mark=%u " % socket.ntohl(tb[nfnlct.CTA_MARK].get_u32()), end='')
    nfnlct.CTA_SECMARK in tb        and print("secmark=%u " % socket.ntohl(tb[nfnlct.CTA_SECMARK].get_u32()), end='')
    nfnlct.CTA_COUNTERS_ORIG in tb  and print_counters("original", tb[nfnlct.CTA_COUNTERS_ORIG])
    nfnlct.CTA_COUNTERS_REPLY in tb and print_counters("reply", tb[nfnlct.CTA_COUNTERS_REPLY])
    print()

    return mnl.MNL_CB_OK


def main():
    nlh = mnl.Nlmsg.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_GET
    nlh.nlmsg_flags = netlink.NLM_F_REQUEST|netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.nlmsg_seq = seq

    nfh = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfh.nfgen_family = socket.AF_INET
    nfh.version = nfnl.NFNETLINK_V0
    nfh.res_id = 0

    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        nl.send_nlmsg(nlh)
        portid = nl.get_portid()

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            try:
                buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
                if len(buf) == 0: break
            except Exception as e:
                print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
                raise
            try:
                ret = mnl.cb_run(buf, seq, portid, data_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
