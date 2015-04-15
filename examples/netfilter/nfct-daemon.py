#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, os, logging, socket, time, struct
import errno, select, signal
import ipaddr

import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_conntrackh as nfnlct
import cpylmnl.linux.netfilter.nfnetlink_compath as nfnlcm
import cpylmnl as mnl


log = logging.getLogger(__name__)
nstats = dict() # {ipaddr: Nstat}
# for sig handler
nl_socket = None
sending_nlh = None


class Nstat(object):
    __slots__ = ["addr", "pkts", "bytes"]
    def __init__(self):
        self.addr = None
        self.pkts = 0
        self.bytes = 0


@mnl.attribute_cb
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
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def be64toh(q):
    return struct.unpack(">Q", struct.pack("Q", q))[0]


def parse_counters(nest, ns):
    tb = dict()

    nest.parse_nested(parse_counters_cb, tb)
    if nfnlct.CTA_COUNTERS_PACKETS in tb:
        ns.pkts += be64toh(tb[nfnlct.CTA_COUNTERS_PACKETS].get_u64())
    if nfnlct.CTA_COUNTERS_BYTES in tb:
        ns.bytes += be64toh(tb[nfnlct.CTA_COUNTERS_BYTES].get_u64())


@mnl.attribute_cb
def parse_ip_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_IP_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == nfnlct.CTA_IP_V4_SRC \
            or attr_type == nfnlct.CTA_IP_V4_DST:
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    if attr_type == nfnlct.CTA_IP_V6_SRC \
            or attr_type == nfnlct.CTA_IP_V6_DST:
        try:
            attr.validate2(mnl.MNL_TYPE_BINARY, 16) # XXX: sizeof(struct in6_addr)
        except OSError as e:
            print("mnl_attr_validate2: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def parse_ip(nest, ns):
    tb = dict()

    nest.parse_nested(parse_ip_cb, tb)
    if nfnlct.CTA_IP_V4_SRC in tb:
        # ns.addr = ipaddr.IPv4Address(struct.unpack(">I", bytes(bytearray(tb[nfnlct.CTA_IP_V4_SRC].get_payload_v()))))
        ns.addr = ipaddr.IPv4Address(".".join("%d" % i for i in tb[nfnlct.CTA_IP_V4_SRC].get_payload_v()))
    if nfnlct.CTA_IP_V6_SRC in tb:
        v6addr = tb[nfnlct.CTA_IP_V6_SRC].get_payload_v()
        ns.addr = ipaddr.IPv6Address(":".join(["%x%x" % (a[i], a[i + 1]) for i in range(0, len(v6addr), 2)]))


@mnl.attribute_cb
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

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def parse_tuple(nest, ns):
    tb = dict()

    nest.parse_nested(parse_tuple_cb, tb)
    if nfnlct.CTA_TUPLE_IP in tb:
        parse_ip(tb[nfnlct.CTA_TUPLE_IP], ns)


@mnl.attribute_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(nfnlct.CTA_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type in (nfnlct.CTA_TUPLE_ORIG, nfnlct.CTA_COUNTERS_ORIG, nfnlct.CTA_COUNTERS_REPLY):
        try:
            attr.validate(mnl.MNL_TYPE_NESTED)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def data_cb(nlh, data):
    tb = dict()
    nfg = nlh.get_payload_as(nfnl.Nfgenmsg)
    ns = Nstat()

    nlh.parse(nfnl.Nfgenmsg.csize(), data_attr_cb, tb)
    if nfnlct.CTA_TUPLE_ORIG in tb:
        parse_tuple(tb[nfnlct.CTA_TUPLE_ORIG], ns)

    if nfnlct.CTA_COUNTERS_ORIG in tb:
        parse_counters(tb[nfnlct.CTA_COUNTERS_ORIG], ns)

    if nfnlct.CTA_COUNTERS_REPLY in tb:
        parse_counters(tb[nfnlct.CTA_COUNTERS_REPLY], ns)

    cur = nstats.setdefault(ns.addr, ns)
    cur.pkts += ns.pkts
    cur.bytes += ns.bytes

    return mnl.MNL_CB_OK


def handle(nl):
    try:
        buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
    except OSError as e:
        if e.errno == ENOBUFS:
            print("The daemon has hit ENOBUFS, you can " \
                      + "increase the size of your receiver " \
                      + "buffer to mitigate this or enable " \
                      + "reliable delivery.",
                  file=sys.stderr)
        else:
            print("mnl_socket_recvfrom: %s" % e)
        return -1

    try:
        ret = mnl.cb_run(buf, 0, 0, data_cb, None)
    except OSError as e:
        print("mnl_cb_run: %s" % e, file=sys.stderr)
        return -1

    return ret


def alarm_handler(signum, frame):
    global nl_socket
    global sending_nlh

    nl_socket.send_nlmsg(sending_nlh) # XXX: will cause EBUSY if send while dumping
    for cur in nstats.itervalues():
        print("src={cur.addr} counters {cur.pkts} {cur.bytes}".format(cur=cur))



def main():
    global nl_socket
    global sending_nlh

    if len(sys.argv) != 2:
        print("Usage: %s <poll-secs>" % sys.argv[0])
        sys.exit(-1)

    secs = int(sys.argv[1])
    print("Polling every %s seconds from kernel..." % secs)

    # Set high priority for this process, less chances to overrun
    # the netlink receiver buffer since the scheduler gives this process
    # more chances to run
    os.nice(-20)

    # Open netlink socket to operate with netfilter
    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl_socket:
        # Subscribe to destroy events to avoid leaking counters. The same
        # socket is used to periodically atomically dump and reset counters.
        nl_socket.bind(nfnlcm.NF_NETLINK_CONNTRACK_DESTROY, mnl.MNL_SOCKET_AUTOPID)

        # Set netlink receiver buffer to 16 MBytes, to avoid packet drops
        # XXX: has to use python's. socket.fromfd() is available only in Unix
        buffersize = 1 << 22
        sock = socket.fromfd(nl_socket.get_fd(), socket.AF_NETLINK, socket.SOCK_RAW)
        sock.setsockopt(socket.SOL_SOCKET, 33, buffersize) # SO_RCVBUFFORCE

        # The two tweaks below enable reliable event delivery, packets may
        # be dropped if the netlink receiver buffer overruns. This happens...
        #
        # a) if ther kernel spams this user-space process until the receiver
        #    is filled
        #
        # or:
        #
        # b) if the user-space process does not pull message from the
        #    receiver buffer so often.
        on = struct.pack("i", 1)
        nl_socket.setsockopt(netlink.NETLINK_BROADCAST_ERROR, on)
        nl_socket.setsockopt(netlink.NETLINK_NO_ENOBUFS, on)

        buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)
        sending_nlh = mnl.nlmsg_put_header(buf, mnl.Msghdr)

        # Counters are atomically zerod in each dump
        sending_nlh.nlmsg_type = (nfnl.NFNL_SUBSYS_CTNETLINK << 8) | nfnlct.IPCTNL_MSG_CT_GET_CTRZERO
        sending_nlh.nlmsg_flags = netlink.NLM_F_REQUEST|netlink.NLM_F_DUMP

        nfh = sending_nlh.put_extra_header_as(nfnl.Nfgenmsg)
        nfh.nfgen_family = socket.AF_INET
        nfh.version = nfnl.NFNETLINK_V0
        nfh.res_id = 0

        # Filter by mark: We only want to dump entries whose mark is zefo
        sending_nlh.put_u32(nfnlct.CTA_MARK, socket.htonl(0))
        sending_nlh.put_u32(nfnlct.CTA_MARK_MASK, socket.htonl(0xffffffff))

        # Every N seconds...
        # unfotunately python does not return remainded time
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.setitimer(signal.ITIMER_REAL, secs, secs)

        fd = nl_socket.get_fd()
        while True:
            try:
                rlist, wlist, xlist = select.select([fd], [], [])
            except select.error as e:
                if e[0] == errno.EINTR: continue
                raise

            # Handled event and periodic atomic-dump-and-reset messages
            if fd in rlist:
                if handle(nl_socket) < 0:
                    return -1


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
