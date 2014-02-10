#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, errno
import socket, time, struct, multiprocessing
import signal
import cPickle as pickle

import dpkt
import cpylmnl.linux.netlinkh as netlink
import cpylmnl.linux.netfilter.nfnetlinkh as nfnl
import cpylmnl.linux.netfilter.nfnetlink_logh as nfulnl
import cpylmnl as mnl

"""quote from ulogd2 document

  Just add rules using the NFLOG target to your firewalling chain. A
  very basic example:

       iptables -A FORWARD -j NFLOG --nflog-group 32 --nflog-prefix foo

  To increase logging performance, try to use the

       --nflog-qthreshold N

  option (where 1 < N <= 50). The number you specify is the amount of
  packets batched together in one multipart netlink message. If you set
  this to 20, the kernel schedules ulogd only once every 20 packets. All
  20 packets are then processed by ulogd. This reduces the number of
  context switches between kernel and userspace.

  Of course you can combine the NFLOG target with the different
  netfilter match modules. For a more detailed description, have a look
  at the netfilter HOWTO's, available on the netfilter homepage.

...
     --nflog-range N
        Copyrange. This works like the 'snaplen' parameter of tcpdump.
        You can specify a number of bytes up to which the packet is
        copied. If you say '40', you will receive the first fourty bytes
        of every packet. Leave it to 0 to dump the whole packet.

my adversaria:
    iptables -t raw -A PREROUTING -j NFLOG --nflog-group 1 --nflog-prefix myrouter \
                                           --nflog-qthreshold 16 --nflog-range 64

---

carbon path structure is:

    <src addr>.<dst addr>.<protocol>

IPv4 addresses are not dotted decimal, divide decimal by ``:''
because of my lack of knowledge. Value is

    (epoch from time.time(), <IP datagram length>)

Talking about iptables options above, --nflog-range would be enough 64
for those addresses, l4 proto. Sending to carbon every sigalarm raised
by seeing ``sendable'' global variable.
"""


log = logging.getLogger(__name__)
CARBON_SERVER = '127.0.0.1'
CARBON_PORT = 2004


@mnl.attribute_cb
def parse_attr_cb(attr, tb):
    """only interested in
    length from NFULA_PACKET_HDR
    payload from NFULA_PAYLOAD
    """
    attr_type = attr.get_type()

    if attr_type == nfulnl.NFULA_PACKET_HDR:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfulnl.NfulnlMsgPacketHdr.csize())
        except OSError as e:
            log.warn("invalid NFULA_PACKET_HDR: %s" % e)
        else:
            tb[attr_type] = attr
    elif attr_type == nfulnl.NFULA_PAYLOAD:
        tb[attr_type] = attr

    return mnl.MNL_CB_OK


def make_tuple(ethtype, pktbuf):
    """make 3 elements list.

    src and dst address, l4 protocol
    """
    if ethtype == 0x0800: # ETH_P_IP:
        dg = dpkt.ip.IP(pktbuf)
    elif ethtype == 0x86DD: # ETH_P_IPV6:
        dg = dpkt.ip6.IP6(pktbuf)
    elif ethtype == 0x0806: # ETH_P_ARP 
        # dg = dpkt.arp.ARP(pktbuf)
        log.info("ignore ARP")
        return None
    else:
        log.info("ignore unknown ether type (not in ETH_P_IP, ETH_P_IPV6, ETH_P_ARP)")
        return None

    return (dg.src, dg.dst, dg.p)


@mnl.header_cb
def log_cb(nlh, data):
    tb = dict()

    nlh.parse(nfnl.Nfgenmsg.csize(), parse_attr_cb, tb)
    if not nfulnl.NFULA_PACKET_HDR in tb:
        log.warn("no NFULA_PACKET_HDR")
        return mnl.MNL_CB_OK
    if not nfulnl.NFULA_PAYLOAD in tb:
        log.warn("no NFULA_PAYLOAD")
        return mnl.MNL_CB_OK

    ph = tb[nfulnl.NFULA_PACKET_HDR].get_payload_as(nfulnl.NfulnlMsgPacketHdr)
    # copying - dpkt require bytes, it uses struct.unpack
    pkt_buffer = bytes(bytearray(tb[nfulnl.NFULA_PAYLOAD].get_payload_v()))
    k = make_tuple(socket.ntohs(ph.hw_protocol), pkt_buffer)
    if k is not None:
        data[k] = data.get(k, 0) + len(pkt_buffer)

    return mnl.MNL_CB_OK


def nflog_build_cfg_pf_request(buf, command):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS_ULOG << 8) | nfulnl.NFULNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.family = socket.AF_INET
    nfg.version = nfnl.NFNETLINK_V0

    cmd = nfulnl.NfulnlMsgConfigCmd()
    cmd.command = command
    nlh.put(nfulnl.NFULA_CFG_CMD, cmd)

    return nlh


def nflog_build_cfg_request(buf, command, qnum):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS_ULOG << 8) | nfulnl.NFULNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.family = socket.AF_INET
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(qnum)

    cmd = nfulnl.NfulnlMsgConfigCmd()
    cmd.command = command
    nlh.put(nfulnl.NFULA_CFG_CMD, cmd)

    return nlh


def nflog_build_cfg_params(buf, mode, copy_range, qnum):
    nlh = mnl.Header(buf)
    nlh.put_header()
    nlh.type = (nfnl.NFNL_SUBSYS_ULOG << 8) | nfulnl.NFULNL_MSG_CONFIG
    nlh.flags = netlink.NLM_F_REQUEST

    nfg = nlh.put_extra_header_as(nfnl.Nfgenmsg)
    nfg.family = socket.AF_UNSPEC
    nfg.version = nfnl.NFNETLINK_V0
    nfg.res_id = socket.htons(qnum)

    params = nfulnl.NfulnlMsgConfigMode()
    params.copy_range = socket.htonl(copy_range)
    params.copy_mode = mode
    nlh.put(nfulnl.NFULA_CFG_MODE, params)

    return nlh


def make_carbon_path(t):
    # t: (saddr, dattr, proto)
    # XXX: addr len condition
    if len(t[0]) == 4: # IPv4
        "represents IPv4 address :decimal"
        return ".".join((":".join([str(ord(i)) for i in t[0]]),
                      ":".join([str(ord(i)) for i in t[1]]),
                      str(t[2])))
    else: # IPv6
        return ".".join((":".join(["%04x" % ((ord(t[0][i]) << 8) + ord(t[0][i + 1]))
                               for i in range(len(t[0])) if i %2 == 0]),
                      ":".join(["%04x" % ((ord(t[1][i]) << 8) + ord(t[1][i + 1]))
                               for i in range(len(t[1])) if i %2 == 0]),
                      str(t[2])))


def send_process(sock, q):
    while True:
        # got from q: {(saddr, dattr, proto): payload_len}
        d = q.get()
        if d is None:
            return

        now = int(time.time())
        listOfMetricTuples = []
        for k, v in d.iteritems():
            listOfMetricTuples.append((make_carbon_path(k), (now, v)))
        """
        print("\n\nsending entries: %d" % len(listOfMetricTuples))
        for e in listOfMetricTuples:
            print(e)
        """
        payload = pickle.dumps(listOfMetricTuples)
        header = struct.pack("!L", len(payload))
        message = header + payload
        # should catch EINTR?
        sock.sendall(message)


sendable = False

def alarm_handler(signum, frame):
    global sendable
    sendable = True


def main():
    if len(sys.argv) != 2:
        print("Usage: %s [queue_num]" % sys.argv[0])
        sys.exit(-1)

    # for netlink sending
    qnum = int(sys.argv[1])
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)

    # prepare for sending to carbon
    sock = socket.socket()
    try:
        sock.connect((CARBON_SERVER, CARBON_PORT))
    except Exception as e:
        log.fatal("could not connect to carbon server %d@%s" % (CARBON_PORT, CARBON_SERVER))
        sys.exit(-1)

    q = multiprocessing.Queue() # XXX: size?
    p = multiprocessing.Process(target=send_process, args=(sock, q))
    p.start()

    # netlink transaction
    with mnl.Socket(netlink.NETLINK_NETFILTER) as nl:
        # request that I want to acquire qnum queue packet log
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()

        nlh = nflog_build_cfg_pf_request(buf, nfulnl.NFULNL_CFG_CMD_PF_UNBIND)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_pf_request(buf, nfulnl.NFULNL_CFG_CMD_PF_BIND)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_request(buf, nfulnl.NFULNL_CFG_CMD_BIND, qnum)
        nl.send_nlmsg(nlh)

        nlh = nflog_build_cfg_params(buf, nfulnl.NFULNL_COPY_PACKET, 0xFFFF, qnum)
        nl.send_nlmsg(nlh)

        # prepare sigalrm
        global sendable
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.setitimer(signal.ITIMER_REAL, 2, 10)

        # {(saddr, dattr, proto): payload_len}
        data = dict()

        # receiving loop
        ret = mnl.MNL_CB_OK
        while ret >= mnl.MNL_CB_STOP:
            try:
                nrecv = nl.recv_into(buf)
            except OSError as oe:
                if oe.errno == errno.EINTR:
                    continue
            except Exception as e:
                log.error("mnl_socket_recvfrom: %s" % e)
                continue
            try:
                ret = mnl.cb_run(buf[:nrecv], 0, portid, log_cb, data)
            except Exception as e:
                log.error("mnl_cb_run: %s" %e)

            if sendable and len(data) > 0:
                sendable = False
                q.put(data)
                data = dict()
        q.put(None)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
