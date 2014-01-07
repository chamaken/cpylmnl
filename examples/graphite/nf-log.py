#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time, struct
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

---

carbon path structure is:

    <src addr>.<dst addr>.<protocol>.<src port>.<dst port>

in TCP, UDP, SCP

    <src addr>.<dst addr>.<protocol>.<icmp type>.<icmp code>

in ICMP. IPv4 addresses are not dotted decimal, divide decimal by ``:''
because of my lack of knowledge. Value is

    (<second from nflog>, <IP datagram length>)

Talking about iptables options above, --nflog-range would be enough 64
for those addresses, ports. Sending data to carbon for every kernel
notification so that --nflog-qthreshold may need too.
"""


log = logging.getLogger(__name__)
CARBON_SERVER = '127.0.0.1'
CARBON_PORT = 2004


@mnl.attribute_cb
def parse_attr_cb(attr, tb):
    """only interested in
    timestamp second from NFULA_TIMESTAMP
    length from NFULA_PACKET_HDR
    payload from NFULA_PAYLOAD
    """
    attr_type = attr.get_type()

    if attr_type == nfulnl.NFULA_TIMESTAMP:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfulnl.NfulnlMsgPacketTimestamp.sizeof())
        except OSError as e:
            log.warn("invalid NFULA_TIMESTAMP: %s" % e)
        else:
            tb[attr_type] = attr
    elif attr_type == nfulnl.NFULA_PACKET_HDR:
        try:
            attr.validate2(mnl.MNL_TYPE_UNSPEC, nfulnl.NfulnlMsgPacketHdr.sizeof())
        except OSError as e:
            log.warn("invalid NFULA_PACKET_HDR: %s" % e)
        else:
            tb[attr_type] = attr
    elif attr_type == nfulnl.NFULA_PAYLOAD:
        tb[attr_type] = attr

    return mnl.MNL_CB_OK


def append_l4_tuple(proto, pkt, prefix):
    # pkt has already been dpkt instance
    if proto == dpkt.ip.IP_PROTO_ICMP: # isinstance(pkt, dpkt.icmp.ICMP):
        return ".".join([prefix, str(pkt.type), str(pkt.code)])
    elif proto in (dpkt.ip.IP_PROTO_TCP,
                   dpkt.ip.IP_PROTO_UDP,
                   dpkt.ip.IP_PROTO_SCTP):
        return ".".join([prefix, str(pkt.sport), str(pkt.dport)])
    else:
        log.info("unknown IP_PROTO: %r" % pkt)
        return prefix


def make_prefix(dg):
    return ".".join((":".join([str(ord(i)) for i in dg.src]),
                     ":".join([str(ord(i)) for i in dg.dst]),
                     str(dg.p)))

def make_carbon_path(ethtype, pktbuf):
    """make carbon path from 5 elements.

    src and dst address, protocol and
    - TCP, UDP, SCTP, DCCP: src and dst port
    - ICMP: type and code
    """
    if ethtype == 0x0800: # ETH_P_IP:
        dg = dpkt.ip.IP(pktbuf)
        prefix = make_prefix(dg)
    elif ethtype == 0x86DD: # ETH_P_IPV6:
        dg = dpkt.ip6.IP6(pktbuf)
        prefix = make_prefix(dg)
    elif ethtype == 0x0806: # ETH_P_ARP 
        # dg = dpkt.arp.ARP(pktbuf)
        log.info("ignore ARP")
        return None
    else:
        log.info("ignore unknown ether type (not in ETH_P_IP, ETH_P_IPV6, ETH_P_ARP)")
        return None

    return append_l4_tuple(dg.p, dg.data, prefix)


def be64toh(q):
    return struct.unpack(">Q", struct.pack("Q", q))[0]
    

@mnl.header_cb
def log_cb(nlh, data_list):
    tb = dict()

    nlh.parse(nfnl.Nfgenmsg.sizeof(), parse_attr_cb, tb)
    if not nfulnl.NFULA_TIMESTAMP in tb:
        log.warn("no NFULA_TIMESTAMP")
        return mnl.MNL_CB_OK
    if not nfulnl.NFULA_PACKET_HDR in tb:
        log.warn("no NFULA_PACKET_HDR")
        return mnl.MNL_CB_OK
    if not nfulnl.NFULA_PAYLOAD in tb:
        log.warn("no NFULA_PAYLOAD")
        return mnl.MNL_CB_OK

    ph = tb[nfulnl.NFULA_PACKET_HDR].get_payload_as(nfulnl.NfulnlMsgPacketHdr)
    ts = tb[nfulnl.NFULA_TIMESTAMP].get_payload_as(nfulnl.NfulnlMsgPacketTimestamp)
    # copying - dpkt require bytes, it uses struct.unpack
    pkt_buffer = bytes(bytearray(tb[nfulnl.NFULA_PAYLOAD].get_payload_v()))

    carbon_values = (be64toh(ts.sec), len(pkt_buffer))
    carbon_path = make_carbon_path(socket.ntohs(ph.hw_protocol), pkt_buffer)
    print("(%s, %r)" % (carbon_path, carbon_values))
    # data_list.append((carbon_path, varbon_values))

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


def send_process(sock, q):
    while True:
        listOfMetricTuples = q.get()
        if listOfMetricTuples is None: # means finish
            return

        payload = pickle.dumps(listOfMetricTuples)
        header = struct.pack("!L", len(payload))
        message = header + payload
        sock.sendall(message)


def main():
    if len(sys.argv) != 2:
        print("Usage: %s [queue_num]" % sys.argv[0])
        sys.exit(-1)

    # for netlink sending
    qnum = int(sys.argv[1])
    buf = bytearray(mnl.MNL_SOCKET_BUFFER_SIZE)

    # prepare for sending to carbon
    sock = socket()
    try:
        sock.connect((CARBON_SERVER, CARBON_PORT))
    except Exception as e:
        log.fatal("could not connect to carbon server %d@%s" % (CARBON_PORT, CARBON_SERVER))
        sys.exit(-1)
    q = multiprocessing.Queue() # XXX: size?
    p = multiprocessing.Process(target=send_process, args=(sock, q))

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

        # receiving loop
        ret = mnl.MNL_CB_OK
        while ret >= mnl.MNL_CB_STOP:
            try:
                nrecv = nl.recv_into(buf)
                data_list = []
                ret = mnl.cb_run(buf[:nrecv], 0, portid, log_cb, data_list)
                q.put(data_list)
            except Exception as e:
                raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
