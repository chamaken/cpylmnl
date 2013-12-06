#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl.nlstructs.rtnetlink as rtnl
from cpylmnl.nlstructs import if_addr
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attribute_cb
def data_attr_cb2(attr, tb):
    # skip unsupported attribute in user-space
    try:
        attr.type_valid(rtnl.RTAX.MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr.validate(mnl.MNL_TYPE_U32) < 0:
        return mnl.MNL_CB_ERROR, err

    tb[attr.get_type()] = attr
    return mnl.MNL_CB_OK


def attributes_show_ipv4(tb):
    def _print_u32(fmt, attr):
        print(fmt % attr.get_u32(), end='')

    def _print_addr(fmt, attr):
        addr = attr.get_payload_v()
        print(fmt % socket.inet_ntoa(addr), end='')

    h.RTA_TABLE in tb 	 and _print_u32("table=%u ", tb[h.RTA_TABLE])
    h.RTA_DST in tb	 and _print_addr("dst=%s ", tb[h.RTA_DST])
    h.RTA_SRC in tb	 and _print_u32_addr("src=%s ", tb[h.RTA_SRC])
    h.RTA_OIF in tb	 and _print_u32("oif=%u ", tb[h.RTA_OIF])
    h.RTA_FLOW in tb	 and _print_u32("flow=%u ",  tb[h.RTA_FLOW])
    h.RTA_PREFSRC in tb  and _print_addr("prefsrc=%s ", tb[h.RTA_PREFSRC])
    h.RTA_GATEWAY in tb  and _print_addr("gw=%s ", tb[h.RTA_GATEWAY])
    h.RTA_PRIORITY in tb and _print_u32("prio=%u ", tb[h.RTA_PRIORITY])

    if h.RTA_METRICS in tb:
        tbx = dict()
        tb[h.RTA_METRICS].parse_nested(data_attr_cb2, tbx)
        for i in range(h.RTAX_MAX):
            i in tbx	 and print("metrics[%d]=%u " % (i, tbx[i].get_u32()), end='')

    print()


def inet6_ntoa(addr):
    return socket.inet_ntop(socket.AF_INET6, addr)


def attributes_show_ipv6(tb):
    def _print_u32(fmt, attr):
        print(fmt % attr.get_u32(), end='')

    def _print_addr6(fmt, attr):
        addr = attr.get_payload_v()
        print(fmt % inet6_ntoa(addr), end='')

    h.RTA_TABLE in tb   and _print_u32("table=%u ", tb[h.RTA_TABLE])
    h.RTA_DST in tb     and _print_addr6("dst=%s ", tb[h.RTA_DST])
    h.RTA_SRC in tb     and _print_addr6("src=%s ", tb[h.RTA_SRC])
    h.RTA_OIF in tb     and _print_u32("oif=%u ", tb[h.RTA_OIF])
    h.RTA_FLOW in tb    and _print_u32("flow=%u ", tb[h.RTA_FLOW])
    h.RTA_PREFSRC in tb and _print_addr6("prefsrc=%s ", tb[h.RTA_PREFSRC])
    h.RTA_GATEWAY in tb and _print_addr6("gw=%s ", tb[h.RTA_GATEWAY])
    if h.RTA_METRICS in tb:
        tbx = dict()
        tb[h.RTA_METRICS].parse_nested(data_attr_cb2, tbx)

        for i in range(h.RTAX_MAX):
            if i in tbx:
                print("metrics[%d]=%u " % (i, tbx[i].get_u32()), end='')

    print()


def _validate_u32(attr):
    if attr.validate(mnl.MNL_TYPE_U32) < 0:
        return mnl.MNL_CB_ERROR
    return mnl.MNL_CB_OK

def _validate_nested(attr):
    if attr.validate(mnl.MNL_TYPE_NESTED) < 0:
        return mnl.MNL_CB_ERROR
    return mnl.MNL_CB_OK

def _validate_in6_addr(attr):
    if attr.validate2(mnl.MNL_TYPE_BINARY, 16) < 0: # XXX: sizeof(struct in6_addr)
        return mnl.MNL_CB_ERROR
    return mnl.MNL_CB_OK


@mnl.attribute_cb
def data_ipv4_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(h.RTA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    ftbl = {h.RTA_TABLE:   _validate_u32,
            h.RTA_DST:	   _validate_u32,
            h.RTA_SRC:	   _validate_u32,
            h.RTA_OIF:	   _validate_u32,
            h.RTA_FLOW:	   _validate_u32,
            h.RTA_PREFSRC: _validate_u32,
            h.RTA_GATEWAY: _validate_u32,
            h.RTA_METRICS: _validate_nested,
            }

    if ftbl.get(attr_type, lambda a: (0, None))(attr) < 0:
        return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.attribute_cb
def data_ipv6_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(h.RTA_MAX)
    except Exception as e:
        return mnl.MNL_CB_OK

    ftbl = {h.RTA_TABLE	  : _validate_u32,
            h.RTA_OIF	  : _validate_u32,
            h.RTA_FLOW	  : _validate_u32,
            h.RTA_DST	  : _validate_in6_addr,
            h.RTA_SRC	  : _validate_in6_addr,
            h.RTA_PREFSRC : _validate_in6_addr,
            h.RTA_GATEWAY : _validate_in6_addr,
            h.RTA_METRICS : _validate_nested,
            }
    if ftbl.get(attr_type, lambda a: (0, None))(attr) < 0:
        return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def data_cb(nlh, tb):
    tb = dict()
    rm = nlh.get_payload_as(rtnl.Rtmsg)

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
    # print("table=%s " % rtnl.RT_TABLE.code[rm.table],	end='')

    # type
    print("type=%u " % rm.type,		end='')
    # print("type=%s " % rtnl.RTN.code[rm.type],	end='')

    # scope
    print("scope=%u " % rm.scope,		end='')
    # print("scope=%s " % rtnl.RT_SCOPE.code[rm.scope],	end='')

    # proto
    print("proto=%u " % rm.protocol,		end='')
    # print("proto=%s " % rtnl.RTPROT.code[rm.protocol], 	end='')

    # flags
    print("flags=%x\n\t" % rm.flags,		end='')
    # flags = [v for k, v in rtnl.RTM_F.code.items() if k & rm.flags == k]
    # len(flags) != 0 and print("flags=%s\n\t" % "|".join(flags))

    if rm.family == socket.AF_INET:
        nlh.parse(rtnl.Rtmsg.sizeof(), data_ipv4_attr_cb, tb)
        attributes_show_ipv4(tb)
    elif rm.family == socket.AF_INET6:
        nlh.parse(rtnl.Rtmsg.sizeof(), data_ipv6_attr_cb, tb)
        attributes_show_ipv6(tb)

    return mnl.MNL_CB_OK


def main():
    if len(sys.argv) != 2:
        print("Usage: %s <inet|inet6>" % sys.argv[0])
        sys.exit(-1)

    nlh = mnl.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = h.RTM_GETROUTE
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.seq = seq
    rtm = nlh.put_extra_header_as(rtnl.Rtmsg.sizeof(), rtnl.Rtmsg)

    if sys.argv[1] == "inet":
        rtm.family = socket.AF_INET
    elif sys.argv[1] == "inet6":
        rtm.family = socket.AF_INET6

    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()
        nl.send_nlmsg(nlh)

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            buf = nl.recvfrom(mnl.MNL_SOCKET_BUFFER_SIZE)
            if len(buf) == 0: break
            ret = mnl.cb_run(buf, seq, portid, data_cb, None)

    if ret < 0:
        print(err, file=sys.stderr)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
