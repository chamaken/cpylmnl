#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.rtnetlinkh as rtnl
import cpylmnl.linux.if_addrh as if_addr
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attribute_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(if_addr.IFA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == if_addr.IFA_ADDRESS:
        try:
            attr.validate(mnl.MNL_TYPE_BINARY)
        except OSError as e:
            print("mnl_attr_validate: %s", file=sys.stderr)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def data_cb(nlh, data):
    ifa = nlh.get_payload_as(if_addr.Ifaddrmsg)
    print("index=%d family=%d " % (ifa.index, ifa.family), end='')

    tb = dict()
    nlh.parse(if_addr.Ifaddrmsg.sizeof(), data_attr_cb, tb)

    print("addr=", end='')
    if if_addr.IFA_ADDRESS in tb:
        attr = tb[if_addr.IFA_ADDRESS]
        addr = attr.get_payload_v()
        out = socket.inet_ntop(ifa.family, addr)
        print("%s " % out, end='')

    print("scope=", end='')
    {   0: lambda: print("global ",	end=''),
      200: lambda: print("site ",	end=''),
      253: lambda: print("link ",	end=''),
      254: lambda: print("host ",	end=''),
      255: lambda: print("nowhere ",	end='')
        }.get(ifa.scope, lambda: print("%d " % ifa.scope, end=''))()

    print()
    return mnl.MNL_CB_OK


def main():
    if len(sys.argv) != 2:
        print("Usage: %s <inet|inet6>" % sys.argv[0], file=sys.stderr)
        sys.exit(-1)

    nlh = mnl.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = rtnl.RTM_GETADDR
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_DUMP
    seq = int(time.time())
    nlh.seq = seq
    rt = nlh.put_extra_header_as(rtnl.Rtgenmsg)
    if sys.argv[1] == "inet":    rt.family = socket.AF_INET
    elif sys.argv[1] == "inet6": rt.family = socket.AF_INET6

    with mnl.Socket(netlink.NETLINK_ROUTE) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()
        nl.send_nlmsg(nlh)

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            try:
                buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            except Exception as e:
                print("mnl_socket_recvfrom: %s" % e, file=sys.stderr)
                raise
            if len(buf) == 0: break
            try:
                ret = mnl.cb_run(buf, nlh.seq, portid, data_cb, None)
            except Exception as e:
                print("mnl_cb_run: %s" % e, file=sys.stderr)
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
