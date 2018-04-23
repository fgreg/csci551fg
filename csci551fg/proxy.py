# Copyright 2018, Frank Greguska, All rights reserved.

"""
Functions in this file:
    setup_log
    bind_router_socket
    handle_udp_socket
    _route_message
    _build_circuit
    _extend_circuit
    _relay_data
    _handle_echo
    _handle_minitor
    handle_tunnel
    proxy

This module is responsible for handling the proxy. It logs to the appropriate files
and read/write to both the UDP socket and the Tunnel pipes. Messages are stored
in memory while they are waiting to be written to one of the pipes.
"""
import functools
import ipaddress
import logging
import os
import random
import selectors
import socket
import struct
import time
from collections import namedtuple

import csci551fg.crypto
import csci551fg.ipfg
import csci551fg.tunnel
from csci551fg.driver import UDP_BUFFER_SIZE, TUNNEL_BUFFER_SIZE

Circuit = namedtuple('Circuit', ['circuit_id', 'source_ip', 'first_hop', 'hops', 'ext_acked', 'extending', 'diffie'])

the_circuit = None

proxy_logger = logging.getLogger('csci551fg.proxy')
proxy_selector = selectors.DefaultSelector()
routers = []

# Holding queue for messages waiting to go to the routers
_echo_messages = []
# Holding queue for messages waiting to go to the tunnel
_echo_replies = []


def setup_log(stage):
    proxy_handler = logging.FileHandler(os.path.join(os.curdir, "stage%d.proxy.out" % stage), mode='w')
    proxy_handler.setFormatter(logging.Formatter("%(message)s"))
    proxy_handler.setLevel(logging.INFO)

    proxy_logger.addHandler(proxy_handler)
    proxy_logger.setLevel(logging.DEBUG)


def bind_router_socket(stage=None, num_hops=None):
    my_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.bind((socket.gethostbyname(socket.gethostname()), 0))

    handler = functools.partial(handle_udp_socket, stage=stage, num_hops=num_hops)

    proxy_selector.register(my_socket, selectors.EVENT_READ | selectors.EVENT_WRITE, handler)

    proxy_logger.info("proxy port: %d" % my_socket.getsockname()[1])

    return my_socket.getsockname()


def handle_udp_socket(udp_socket, mask, stage=None, num_hops=None):
    global routers
    if mask & selectors.EVENT_READ:
        data, address = udp_socket.recvfrom(UDP_BUFFER_SIZE)
        proxy_logger.debug("Proxy received data from router @ %s" % str(address))

        # Don't try to handle any ICMP packets before we get a hello from every router
        if any(router["address"] is None for router in routers):
            received_pid, ipv4_address = struct.unpack("!2I", data)
            router = next(router for router in routers if router["pid"] == received_pid)
            router["address"] = address
            if stage >= 4:
                router["ipv4_address"] = ipaddress.IPv4Address(ipv4_address)

            if stage >= 5:
                proxy_logger.info("router: %d, pid: %d, port: %d, IP: %s"
                                  % (router['index'] + 1, received_pid, address[1], router["ipv4_address"]))
            else:
                proxy_logger.info("router: %d, pid: %d, port: %d"
                                  % (router['index'] + 1, received_pid, address[1]))

            proxy_logger.debug("updated routers %s" % routers)
        else:

            message = csci551fg.ipfg.IPv4Packet(data)
            (ip_proto,) = struct.unpack("!B", message.protocol)
            if ip_proto == socket.IPPROTO_ICMP:
                message_handler = _handle_echo
            elif ip_proto == csci551fg.ipfg.IPPROTO_MINITOR:
                proxy_logger.info("pkt from port: %s, length: %s, contents: 0x%s" % (
                    address[1], len(message.packet_data[20:]), message.packet_data[20:].hex()))
                message_handler = _handle_minitor
            else:
                raise Exception(
                    "Could not determine message type in router. IP Protocol: %s, Message: %s" % (ip_proto, message))

            message_handler(data, address)

    if mask & selectors.EVENT_WRITE:
        global the_circuit
        if all(router["address"] is not None for router in routers):
            if stage <= 4 and _echo_messages:
                message = _echo_messages.pop()
                router_address = _route_message(message)
            elif stage > 4:
                if not the_circuit:
                    # Need to establish new circuit
                    (message, router_address) = _build_circuit(stage, num_hops, encrypted=stage > 5)
                elif not all(the_circuit.ext_acked) and not the_circuit.extending:
                    # Need to extend circuit
                    (message, router_address) = _extend_circuit(stage, num_hops, encrypted=stage > 5)
                elif all(the_circuit.ext_acked) and _echo_messages:
                    # Need to relay data
                    (message, router_address) = _relay_data(stage, num_hops, encrypted=stage > 5)
                else:
                    # Nothing to do
                    return
            else:
                # Nothing to do
                return

            proxy_logger.debug("Proxy sending message {} to {}".format(message, router_address))
            udp_socket.sendto(message.packet_data, router_address)


def _route_message(message):
    global routers
    destination = message.destination_ipv4
    try:
        target_router = next((r for r in routers if r["ipv4_address"] == destination),
                             routers[int(destination) % len(routers)])
    except KeyError:
        target_router = routers[0]
        routers = routers[-1:] + routers[:-1]

    return target_router['address']


def _build_circuit(stage, num_hops, encrypted=False):
    global the_circuit
    # Establish circuit
    hops = random.sample(routers, num_hops)
    if stage > 5:
        # Create keys for each hop
        for router in hops:
            router['key'] = csci551fg.crypto.new_key(router['index'] + 1)
    the_circuit = Circuit(1, None, hops[0], hops, [False] * len(hops), False, False)
    proxy_logger.debug("new circuit %s" % (the_circuit,))

    return _extend_circuit(stage, num_hops, encrypted=encrypted)


def _extend_circuit(stage, num_hops, encrypted=False):
    global the_circuit
    hop_num = the_circuit.ext_acked.index(False) + 1
    router_num = the_circuit.hops[hop_num - 1]['index'] + 1
    try:
        next_hop = the_circuit.hops[the_circuit.ext_acked.index(False) + 1]
    except IndexError:
        next_hop = {'address': (None, csci551fg.ipfg.LAST_HOP)}

    # Circuit incomplete, Extend circuit
    if encrypted:
        # Building encrypted circuit check if diffie has been sent yet
        if not the_circuit.diffie:
            # Send diffie
            key = the_circuit.hops[hop_num - 1]['key']
            proxy_logger.info("hop: %d, router: %s" % (hop_num, router_num))
            proxy_logger.info("new-fake-diffie-hellman, router index: {}, circuit outgoing: {}, key: 0x{}".format(
                router_num, hex(the_circuit.circuit_id), key.hex()
            ))

            the_circuit = Circuit(the_circuit.circuit_id, the_circuit.source_ip, the_circuit.first_hop,
                                  the_circuit.hops,
                                  the_circuit.ext_acked,
                                  False, True)
            keys = [h['key'] for h in reversed(the_circuit.hops[:hop_num - 1])]
            proxy_logger.debug("keys {}".format(keys))
            message = csci551fg.ipfg.FakeDiffieHellman(bytes(39)) \
                .set_circuit_id(the_circuit.circuit_id) \
                .set_session_key(csci551fg.crypto.onion_encrypt(keys, key))
        else:
            # Send encrypted circuit extend
            the_circuit = Circuit(the_circuit.circuit_id, the_circuit.source_ip, the_circuit.first_hop,
                                  the_circuit.hops,
                                  the_circuit.ext_acked,
                                  True, False)
            keys = [h['key'] for h in reversed(the_circuit.hops[:hop_num])]
            proxy_logger.debug("keys {}".format(keys))
            message = csci551fg.ipfg.EncryptedCircuitExtend(bytes(25)) \
                .set_circuit_id(the_circuit.circuit_id) \
                .set_next_hop(csci551fg.crypto.onion_encrypt(keys, struct.pack("!H", next_hop['address'][1])),
                              packed=True)
    else:
        # Not building encrypted circuit, use regular circuit extend
        the_circuit = Circuit(the_circuit.circuit_id, the_circuit.source_ip, the_circuit.first_hop, the_circuit.hops,
                              the_circuit.ext_acked,
                              True, False)
        message = csci551fg.ipfg.CircuitExtend(bytes(25)) \
            .set_circuit_id(the_circuit.circuit_id) \
            .set_next_hop(next_hop['address'][1])

        if stage <= 5:
            proxy_logger.info("hop: %d, router: %s" % (hop_num, router_num))

    router_address = the_circuit.first_hop['address']

    return message, router_address


def _relay_data(stage, num_hops, encrypted=False):
    global the_circuit
    message = _echo_messages.pop()
    proxy_logger.debug("Popped message for sending to router {}".format(message))

    if not encrypted:
        mcm_rd = csci551fg.ipfg.RelayData(bytes(23))
        mcm_rd = mcm_rd.set_circuit_id(the_circuit.circuit_id)
        message = mcm_rd.set_contents(message.packet_data)
        router_address = the_circuit.first_hop['address']
        proxy_logger.debug("relaying packet {} to {}".format(message, router_address))
    else:
        source_ip = message.source_ipv4
        message = message.set_source(ipaddress.IPv4Address('0.0.0.0'))
        the_circuit = Circuit(the_circuit.circuit_id, source_ip, the_circuit.first_hop,
                              the_circuit.hops, the_circuit.ext_acked,
                              the_circuit.extending, the_circuit.diffie)
        keys = [h['key'] for h in reversed(the_circuit.hops)]
        mcm_red = csci551fg.ipfg.RelayEncryptedData(bytes(23)) \
            .set_circuit_id(the_circuit.circuit_id) \
            .set_source(ipaddress.IPv4Address('0.0.0.0')) \
            .encrypt_contents(keys, message.packet_data)
        router_address = the_circuit.first_hop['address']

        message = mcm_red
        proxy_logger.debug("relaying encrypted packet {} to {}".format(message, router_address))

    return message, router_address


def _handle_echo(data, address):
    echo_message = csci551fg.ipfg.ICMPEcho(data)
    proxy_logger.info("ICMP from port: %s, src: %s, dst: %s, type: %s",
                      address[1], echo_message.source_ipv4,
                      echo_message.destination_ipv4, echo_message.icmp_type[0])

    _echo_replies.append(echo_message)


def _handle_minitor(data, address):
    mcm_message = csci551fg.ipfg.MCMPacket(data)
    (mcm_type,) = struct.unpack("!B", mcm_message.message_type)
    if mcm_type == csci551fg.ipfg.MCM_CED or mcm_type == csci551fg.ipfg.MCM_ECED:
        mcm_ced = csci551fg.ipfg.CircuitExtendDone(data)
        (id_i,) = struct.unpack("!H", mcm_ced.circuit_id)
        global the_circuit
        ext_acks = the_circuit.ext_acked
        ext_acks[ext_acks.index(False)] = True
        the_circuit = Circuit(the_circuit.circuit_id, the_circuit.source_ip, the_circuit.first_hop, the_circuit.hops,
                              ext_acks, False, False)
        proxy_logger.debug("extend acked. %s" % (the_circuit,))
        proxy_logger.info("incoming extend-done circuit, incoming: %s from port: %d" % (hex(id_i), address[1]))
    elif mcm_type == csci551fg.ipfg.MCM_RRD:
        mcm_rrd = csci551fg.ipfg.RelayReturnData(data)
        (id_i,) = struct.unpack("!H", mcm_rrd.circuit_id)
        i_packet = csci551fg.ipfg.IPv4Packet(mcm_rrd.contents)
        proxy_logger.info("incoming packet, circuit incoming: {}, src: {}, dst: {}".format(
            hex(id_i), i_packet.source_ipv4, i_packet.destination_ipv4
        ))
        _echo_replies.append(i_packet)
    elif mcm_type == csci551fg.ipfg.MCM_RRED:
        mcm_rred = csci551fg.ipfg.RelayReturnEncryptedData(data)
        (id_i,) = struct.unpack("!H", mcm_rred.circuit_id)

        contents = mcm_rred.contents
        for key in [h['key'] for h in the_circuit.hops]:
            contents = csci551fg.crypto.onion_decrypt(key, contents)
        i_packet = csci551fg.ipfg.IPv4Packet(contents)

        ip_proto = i_packet.get_protocol()
        if ip_proto == socket.IPPROTO_ICMP:
            proxy_logger.info("incoming packet, circuit incoming: {}, src: {}, dst: {}".format(
                hex(id_i), i_packet.source_ipv4, i_packet.destination_ipv4
            ))
            i_packet = csci551fg.ipfg.ICMPEcho(i_packet.packet_data).set_destination(the_circuit.source_ip)
        elif ip_proto == socket.IPPROTO_TCP:
            tcp_packet = csci551fg.ipfg.TCPPacket(i_packet.packet_data).set_destination(the_circuit.source_ip)
            proxy_logger.info("incoming TCP packet, circuit incoming: {}, src IP/port: {}:{}, "
                              "dst IP/port: {}:{}, seqno: {}, ackno: {}".format(
                hex(id_i), tcp_packet.source_ipv4, tcp_packet.get_source_port(),
                tcp_packet.destination_ipv4, tcp_packet.get_destination_port(), tcp_packet.get_sequence_no(),
                tcp_packet.get_ack_no()
            ))
            proxy_logger.debug("incoming TCP packet {}".format(tcp_packet))
            i_packet = csci551fg.ipfg.TCPPacket(i_packet.packet_data).set_destination(the_circuit.source_ip)
        else:
            proxy_logger.debug("Unknown protocol for data returned {}. data {} ".format(ip_proto, i_packet))
            return
        _echo_replies.append(i_packet)
    else:
        raise Exception("Unkown MCM message. Type %s, Message %s" % (hex(mcm_type), mcm_message))


def handle_tunnel(tunnel, mask):
    if mask & selectors.EVENT_READ:
        data = tunnel.read(TUNNEL_BUFFER_SIZE)

        message = csci551fg.ipfg.IPv4Packet(data)
        (ip_proto,) = struct.unpack("!B", message.protocol)

        if message.source_ipv4 == ipaddress.IPv4Address('0.0.0.0'):
            proxy_logger.debug("Dropped 0.0.0.0")
            return

        if ip_proto == socket.IPPROTO_ICMP:
            message = csci551fg.ipfg.ICMPEcho(data)
            proxy_logger.info("ICMP from tunnel, src: %s, dst: %s, type: %s", message.source_ipv4,
                              message.destination_ipv4, struct.unpack("!B", message.icmp_type)[0])
        elif ip_proto == socket.IPPROTO_TCP:
            message = csci551fg.ipfg.TCPPacket(data)
            proxy_logger.info("TCP from tunnel, src IP/port: {}:{}, dst IP/port: {}:{}, seqno: {}, ackno {}".format(
                message.source_ipv4, message.get_source_port(), message.destination_ipv4,
                message.get_destination_port(), message.get_sequence_no(), message.get_ack_no()))
        else:
            raise Exception(
                "Could not determine message type in proxy. IP Protocol: %s, Message: %s" % (ip_proto, message))

        proxy_logger.debug("Proxy received data from tunnel {}".format(message))

        _echo_messages.append(message)

    if mask & selectors.EVENT_WRITE:
        if _echo_replies:
            reply = _echo_replies.pop()
            num_bytes = tunnel.write(reply.packet_data)
            proxy_logger.debug("wrote %d bytes to tunnel" % num_bytes)


def proxy(**kwargs):
    proxy_logger.debug("starting proxy %s" % kwargs)

    if kwargs['stage'] >= 2:
        my_tunnel = csci551fg.tunnel.tun_alloc("tun1", [csci551fg.tunnel.IFF_TUN, csci551fg.tunnel.IFF_NO_PI])
        proxy_selector.register(my_tunnel, selectors.EVENT_READ | selectors.EVENT_WRITE, handle_tunnel)

    global routers
    routers = [{"index": i, "pid": r, "address": None} for i, r in enumerate(kwargs['routers'])]
    proxy_logger.debug("assigning routers %s" % routers)

    while True:
        events = proxy_selector.select()
        for key, mask in events:
            func = key.data
            func(key.fileobj, mask)
