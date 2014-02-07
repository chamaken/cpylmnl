#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time, struct

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnl
import cpylmnl as mnl


log = logging.getLogger(__name__)


def data_attr_cb2(attr, tb):
    # skip unsupported attribute
    try:
        attr.type_valid(rtnl.RTAX_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    try:
        attr.validate(mnl.MNL_TYPE_U32)
    except OSError as e:
        print("mnl_attr_validate: %s" % e, file=sys.stderr)
        return mnl.MNL_CB_ERROR

    tb[attr.get_type()] = attr
    return mnl.MNL_CB_OK


# same as in rtnl-route-dump
def attributes_show_ipv4(tb):
    def _print_u32(fmt, attr):
        print(fmt % attr.get_u32(), end='')

    def _print_addr(fmt, attr):
        addr = attr.get_payload_v()
        print(fmt % socket.inet_ntoa(addr), end='')

    rtnl.RTA_TABLE in tb    and _print_u32("table=%u ", tb[rtnl.RTA_TABLE])
    rtnl.RTA_DST in tb	    and _print_addr("dst=%s ", tb[rtnl.RTA_DST])
    rtnl.RTA_SRC in tb	    and _print_u32_addr("src=%s ", tb[rtnl.RTA_SRC])
    rtnl.RTA_OIF in tb	    and _print_u32("oif=%u ", tb[rtnl.RTA_OIF])
    rtnl.RTA_FLOW in tb	    and _print_u32("flow=%u ",  tb[rtnl.RTA_FLOW])
    rtnl.RTA_PREFSRC in tb  and _print_addr("prefsrc=%s ", tb[rtnl.RTA_PREFSRC])
    rtnl.RTA_GATEWAY in tb  and _print_addr("gw=%s ", tb[rtnl.RTA_GATEWAY])
    rtnl.RTA_PRIORITY in tb and _print_u32("prio=%u ", tb[rtnl.RTA_PRIORITY])
    if rtnl.RTA_METRICS in tb:
        tbx = dict()
        tb[rtnl.RTA_METRICS].parse_nested(data_attr_cb2, tbx)
        for i in range(rtnl.RTAX_MAX):
            i in tbx	 and print("metrics[%d]=%u " % (i, tbx[i].get_u32()), end='')


def inet6_ntoa(addr):
    return socket.inet_ntop(socket.AF_INET6, addr)


def attributes_show_ipv6(tb):
    def _print_u32(fmt, attr):
        print(fmt % attr.get_u32(), end='')

    def _print_addr6(fmt, attr):
        addr = attr.get_payload_v()
        print(fmt % inet6_ntoa(addr), end='')

    rtnl.RTA_TABLE in tb    and _print_u32("table=%u ", tb[rtnl.RTA_TABLE])
    rtnl.RTA_DST in tb      and _print_addr6("dst=%s ", tb[rtnl.RTA_DST])
    rtnl.RTA_SRC in tb      and _print_addr6("src=%s ", tb[rtnl.RTA_SRC])
    rtnl.RTA_OIF in tb      and _print_u32("oif=%u ", tb[rtnl.RTA_OIF])
    rtnl.RTA_FLOW in tb     and _print_u32("flow=%u ", tb[rtnl.RTA_FLOW])
    rtnl.RTA_PREFSRC in tb  and _print_addr6("prefsrc=%s ", tb[rtnl.RTA_PREFSRC])
    rtnl.RTA_GATEWAY in tb  and _print_addr6("gw=%s ", tb[rtnl.RTA_GATEWAY])
    rtnl.RTA_PRIORITY in tb and _print_u32("prio=%u ", tb[rtnl.RTA_PRIORITY])
    if rtnl.RTA_METRICS in tb:
        tbx = dict()
        tb[rtnl.RTA_METRICS].parse_nested(data_attr_cb2, tbx)

        for i in range(rtnl.RTAX_MAX):
            if i in tbx:
                print("metrics[%d]=%u " % (i, tbx[i].get_u32()), end='')


@mnl.attribute_cb
def data_ipv4_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(rtnl.RTA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    ftbl = {rtnl.RTA_TABLE   : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_DST     : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_SRC     : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_OIF     : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_FLOW    : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_PREFSRC : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_GATEWAY : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_PRIORITY: lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_METRICS : lambda x: x.validate(mnl.MNL_TYPE_NESTED),
            }

    try:
        ftbl.get(attr_type, lambda a: (0, None))(attr)
    except OSError as e:
        print("mnl_attr_validate: %s" % e, file=sys.stderr)
        return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.attribute_cb
def data_ipv6_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(rtnl.RTA_MAX)
    except Exception as e:
        return mnl.MNL_CB_OK

    ftbl = {rtnl.RTA_TABLE   : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_OIF     : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_FLOW    : lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_DST     : lambda x: x.validate2(mnl.MNL_TYPE_BINARY, 16),
            rtnl.RTA_SRC     : lambda x: x.validate2(mnl.MNL_TYPE_BINARY, 16),
            rtnl.RTA_PREFSRC : lambda x: x.validate2(mnl.MNL_TYPE_BINARY, 16),
            rtnl.RTA_GATEWAY : lambda x: x.validate2(mnl.MNL_TYPE_BINARY, 16),
            rtnl.RTA_PRIORITY: lambda x: x.validate(mnl.MNL_TYPE_U32),
            rtnl.RTA_METRICS : lambda x: x.validate(mnl.MNL_TYPE_NESTED),
            }

    try:
        ftbl.get(attr_type, lambda a: (0, None))(attr)
    except OSError as e:
        print("mnl_attr_validate: %s" % e, file=sys.stderr)
        return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def data_cb(nlh, tb):
    tb = dict()
    rm = nlh.get_payload_as(rtnl.Rtmsg)

    if nlh.type == rtnl.RTM_NEWROUTE:
        print("[NEW] ", end='')
    elif nlh.type == rtnl.RTM_DELROUTE:
        print("[DEL] ", end='')

    # protocol family = AF_INET | AF_INET6
    print("family=%u " % rm.family,	end='')

    # destination CIDR, e.g. 24 or 32 for IPv4
    print("dst_len=%u " % rm.dst_len,	end='')

    # source CIDR
    print("src_len=%u " % rm.src_len,	end='')

    # type of service (TOS), e.g. 0
    print("tos=%u " % rm.tos,		end='')

    # table
    print("table=%u " % rm.table,	end='')

    # type
    print("type=%u " % rm.type,		end='')

    # scope
    print("scope=%u " % rm.scope,	end='')

    # proto
    print("proto=%u " % rm.protocol,	end='')

    # flags
    print("flags=%x " % rm.flags,	end='')

    if rm.family == socket.AF_INET:
        nlh.parse(rtnl.Rtmsg.sizeof(), data_ipv4_attr_cb, tb)
        attributes_show_ipv4(tb)
    elif rm.family == socket.AF_INET6:
        nlh.parse(rtnl.Rtmsg.sizeof(), data_ipv6_attr_cb, tb)
        attributes_show_ipv6(tb)

    print()
    return mnl.MNL_CB_OK


def main():
    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.bind(rtnl.RTMGRP_IPV4_ROUTE | rtnl.RTMGRP_IPV6_ROUTE, mnl.MNL_SOCKET_AUTOPID)

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            try:
                buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            except Exception as e:
                print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
                raise
            if len(buf) == 0: break
            try:
                ret = mnl.cb_run(buf, 0, 0, data_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
