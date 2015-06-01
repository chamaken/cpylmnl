#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl.linux.netfilter.nfnetlink_compath as nfnlcm
import cpylmnl as mnl


log = logging.getLogger(__name__)


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
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def print_ip(nest):
    tb = dict()

    nest.parse_nested(parse_ip_cb, tb)
    if nfnlct.CTA_IP_V4_SRC in tb:
        # socket.inet_ntoa can accept (ctypes.c_ubyte * n) !
        print("src=%s " % socket.inet_ntoa(tb[nfnlct.CTA_IP_V4_SRC].get_payload_v()), end='')
    if nfnlct.CTA_IP_V4_DST in tb:
        print("dst=%s " % socket.inet_ntoa(tb[nfnlct.CTA_IP_V4_DST].get_payload_v()), end='')


@mnl.attr_cb
def parse_proto_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_PROTO_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type in (nfnlct.CTA_PROTO_NUM,
                     nfnlct.CTA_PROTO_ICMP_TYPE,
                     nfnlct.CTA_PROTO_ICMP_CODE):
        try:
            attr.validate(mnl.MNL_TYPE_U8)
        except OSError as e:
            print("mnl_attr_validate: %s" % e)
            return mnl.MNL_CB_ERROR

    if attr_type in (nfnlct.CTA_PROTO_SRC_PORT,
                     nfnlct.CTA_PROTO_DST_PORT,
                     nfnlct.CTA_PROTO_ICMP_ID):
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
    if nfnlct.CTA_PROTO_NUM in tb:       print("proto=%u " % tb[nfnlct.CTA_PROTO_NUM].get_u8(), end='')
    if nfnlct.CTA_PROTO_SRC_PORT in tb:
        print("sport=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO_SRC_PORT].get_u16()), end='')
    if nfnlct.CTA_PROTO_DST_PORT in tb:
        print("dport=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO_DST_PORT].get_u16()), end='')
    if nfnlct.CTA_PROTO_ICMP_ID in tb:
        print("id=%u " % socket.ntohs(tb[nfnlct.CTA_PROTO_ICMP_ID].get_u16()), end='')
    if nfnlct.CTA_PROTO_ICMP_TYPE in tb: print("type=%u " % tb[nfnlct.CTA_PROTO_ICMP_TYPE].get_u8(), end='')
    if nfnlct.CTA_PROTO_ICMP_CODE in tb: print("code=%u " % tb[nfnlct.CTA_PROTO_ICMP_CODE].get_u8(), end='')


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
        except Exception as e:
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
    if nfnlct.CTA_TUPLE_IP in tb:    print_ip(tb[nfnlct.CTA_TUPLE_IP])
    if nfnlct.CTA_TUPLE_PROTO in tb: print_proto(tb[nfnlct.CTA_TUPLE_PROTO])


@mnl.attr_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == nfnlct.CTA_TUPLE_ORIG:
        try:
            attr.validate(mnl.MNL_TYPE_NESTED)
        except Exception as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
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
def data_cb(nlh, tb):
    tb = dict()
    nfg = nlh.get_payload_as(nfnl.Nfgenmsg)
    if nlh.nlmsg_type & 0xff == nfnlct.IPCTNL_MSG_CT_NEW:
        if nlh.nlmsg_flags & (netlink.NLM_F_CREATE|netlink.NLM_F_EXCL):
            print("%9s " % "[NEW] ", end='')
        else:
            print("%9s " % "[UPDATE] ", end='')
    elif nlh.nlmsg_type & 0xff == nfnlct.IPCTNL_MSG_CT_DELETE:
        print("%9s " % "[DESTROY] ", end='')

    nlh.parse(nfnl.Nfgenmsg.csize(), data_attr_cb, tb)
    if nfnlct.CTA_TUPLE_ORIG in tb: print_tuple(tb[nfnlct.CTA_TUPLE_ORIG])
    if nfnlct.CTA_MARK in tb:       print("mark=%u " % socket.ntohl(tb[nfnlct.CTA_MARK].get_u32()), end='')
    if nfnlct.CTA_SECMARK in tb:    print("secmark=%u " % socket.ntohl(tb[nfnlct.CTA_SECMARK].get_u32()), end='')
    print()

    return mnl.MNL_CB_OK


def main():
    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        nl.bind(nfnlcm.NF_NETLINK_CONNTRACK_NEW | \
                    nfnlcm.NF_NETLINK_CONNTRACK_UPDATE | \
                    nfnlcm.NF_NETLINK_CONNTRACK_DESTROY,
                mnl.MNL_SOCKET_AUTOPID)

        ret = mnl.MNL_CB_OK
        while ret >= mnl.MNL_CB_STOP:
            try:
                buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
                if len(buf) == 0: break
            except Exception as e:
                print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
                raise
            try:
                ret = mnl.cb_run(buf, 0, 0, data_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
