#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl.nlstructs.nfnetlink as nfnl
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attribute_cb
def parse_ip_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTA_IP_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTA_IP_V4_SRC or attr_type == h.CTA_IP_V4_DST:
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def print_ip(nest):
    tb = dict()

    nest.parse_nested(parse_ip_cb, tb)
    if h.CTA_IP_V4_SRC in tb:
        # socket.inet_ntoa can accept (ctypes.c_ubyte * n) !
        print("src=%s " % socket.inet_ntoa(tb[h.CTA_IP_V4_SRC].get_payload_v()), end='')
    if h.CTA_IP_V4_DST in tb:
        print("dst=%s " % socket.inet_ntoa(tb[h.CTA_IP_V4_DST].get_payload_v()), end='')


@mnl.attribute_cb
def parse_proto_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTA_PROTO_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTA_PROTO_NUM \
            or attr_type == h.CTA_PROTO_ICMP_TYPE \
            or attr_type == h.CTA_PROTO_ICMP_CODE:
        try:
            attr.validate(mnl.MNL_TYPE_U8)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    if attr_type == h.CTA_PROTO_SRC_PORT \
            or attr_type == h.CTA_PROTO_DST_PORT \
            or attr_type == h.CTA_PROTO_ICMP_ID:
        try:
            attr.validate(mnl.MNL_TYPE_U16)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def print_proto(nest):
    tb = dict()

    nest.parse_nested(parse_proto_cb, tb)
    if h.CTA_PROTO_NUM in tb:       print("proto=%u " % tb[h.CTA_PROTO_NUM].get_u8(), end='')
    if h.CTA_PROTO_SRC_PORT in tb:
        print("sport=%u " % socket.ntohs(tb[h.CTA_PROTO_SRC_PORT].get_u16()), end='')
    if h.CTA_PROTO_DST_PORT in tb:
        print("dport=%u " % socket.ntohs(tb[h.CTA_PROTO_DST_PORT].get_u16()), end='')
    if h.CTA_PROTO_ICMP_ID in tb:
        print("id=%u " % socket.ntohs(tb[h.CTA_PROTO_ICMP_ID].get_u16()), end='')
    if h.CTA_PROTO_ICMP_TYPE in tb: print("type=%u " % tb[h.CTA_PROTO_ICMP_TYPE].get_u8(), end='')
    if h.CTA_PROTO_ICMP_CODE in tb: print("code=%u " % tb[h.CTA_PROTO_ICMP_CODE].get_u8(), end='')


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
        except Exception as e:
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
    if h.CTA_TUPLE_IP in tb:    print_ip(tb[h.CTA_TUPLE_IP])
    if h.CTA_TUPLE_PROTO in tb: print_proto(tb[h.CTA_TUPLE_PROTO])


@mnl.attribute_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTA_TUPLE_ORIG:
        try:
            attr.validate(mnl.MNL_TYPE_NESTED)
        except Exception as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
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
def data_cb(nlh, tb):
    tb = dict()
    nfg = nlh.get_payload_as(nfnl.Nfgenmsg)
    if nlh.type & 0xff == h.IPCTNL_MSG_CT_NEW:
        if nlh.flags & (netlink.NLM_F_CREATE|netlink.NLM_F_EXCL):
            print("%9s " % "[NEW] ", end='')
        else:
            print("%9s " % "[UPDATE] ", end='')
    elif nlh.type & 0xff == h.IPCTNL_MSG_CT_DELETE:
        print("%9s " % "[DESTROY] ", end='')

    nlh.parse(nfnl.Nfgenmsg.sizeof(), data_attr_cb, tb)
    if h.CTA_TUPLE_ORIG in tb: print_tuple(tb[h.CTA_TUPLE_ORIG])
    if h.CTA_MARK in tb:       print("mark=%u " % socket.ntohl(tb[h.CTA_MARK].get_u32()), end='')
    if h.CTA_SECMARK in tb:    print("secmark=%u " % socket.ntohl(tb[h.CTA_SECMARK].get_u32()), end='')
    print()

    return mnl.MNL_CB_OK


def main():
    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(h.NF_NETLINK_CONNTRACK_NEW | \
                    h.NF_NETLINK_CONNTRACK_UPDATE | \
                    h.NF_NETLINK_CONNTRACK_DESTROY,
                mnl.MNL_SOCKET_AUTOPID)

        ret = mnl.MNL_CB_OK
        while ret >= mnl.MNL_CB_STOP:
            buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            ret = mnl.cb_run(buf, 0, 0, data_cb, None)

    if ret < 0: # not valid. cb_run may raise Exception
        print("mnl_cb_run", file=sys.stderr)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
